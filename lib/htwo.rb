# frozen_string_literal: true

require "htwo/hpack"
require "htwo/errors"

module HTWO
  module Frames
    NAMES = [
      :DATA,
      :HEADERS,
      :PRIORITY,
      :RST_STREAM,
      :SETTINGS,
      :PUSH_PROMISE,
      :PING,
      :GOAWAY,
      :WINDOW_UPDATE,
      :CONTINUATION,
    ]

    NAMES.each_with_index { next unless _1; const_set(_1, _2) }

    class Settings
      NAMES = [
        nil,
        :HEADER_TABLE_SIZE,
        :ENABLE_PUSH,
        :MAX_CONCURRENT_STREAMS,
        :INITIAL_WINDOW_SIZE,
        :MAX_FRAME_SIZE,
        :MAX_HEADER_LIST_SIZE,
      ].freeze

      NAMES.each_with_index { next unless _1; const_set(_1, _2) }

      DEFAULT = [
        nil,
        nil, # default is 4096
        nil, # don't specify push promise
        100, # max concurrent streams
      ].freeze

      def self.encode stream_id, settings
        settings = settings.each_with_index.select { |v, _| v }
        bytesize = settings.length * 6
        type = 0x4

        [
          (bytesize << 8) | type,
          0,
          stream_id
        ].pack("NCN") + settings.map { |val, i|
          [i, val].pack("nN")
        }.join
      end

      DEFAULT_ENCODED = encode(0, DEFAULT).freeze
    end
  end

  class Handler
    def on_headers stream; end
    def on_data stream, chunk; end
    def on_request stream; end
    def on_ping rtt; end
    def on_close; end
  end

  Stream = Struct.new(:id, :headers, :data, :session, :state, :window_size, :rst_received, :content_length, :received_end_stream, :pending_body) do
    def respond headers, body: nil
      session.send_response self, headers, body
    end

    # State predicates
    def idle?
      state == :idle
    end

    def open?
      state == :open
    end

    def closed?
      state == :closed
    end

    def half_closed_remote?
      state == :half_closed_remote
    end

    def half_closed_local?
      state == :half_closed_local
    end

    # State transitions
    def open!
      self.state = :open
    end

    def half_close_remote!
      if open?
        self.state = :half_closed_remote
      elsif half_closed_local?
        self.state = :closed
      end
    end

    def half_close_local!
      if open?
        self.state = :half_closed_local
      elsif half_closed_remote?
        self.state = :closed
      end
    end

    def close!
      self.state = :closed
    end
  end

  class Session
    HEADER_BUFF = ("\0".b * 9).freeze
    private_constant :HEADER_BUFF

    CONNECTION_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".b.freeze

    attr_reader :io

    def initialize io, handler:
      @io = io
      @handler = handler

      # Table used to encode values sent to the peer
      @encoding_table = HPACK.new

      # Table used to decode values sent by the peer
      @decoding_table = HPACK.new

      @peer_settings = [
        0,
        4096, # default header table size,
        1,    # default enable_push
        -1,   # default value max concurrent streams (-1 for unlimited)
        65535, # initial window size
        16384, # initial max frame size
        -1,    # max header list size (-1 for not set)
      ]

      @window_size = 65535
      @next_stream_id = 1
      @streams = {}
      @highest_stream_id = 0 # Track highest stream ID seen from peer
      @open_stream_count = 0 # Track concurrent open streams
      @local_max_concurrent_streams = 100

      # CONTINUATION frame state
      @expecting_continuation = false
      @continuation_stream_id = nil
      @header_buffer = nil
      @continuation_flags = nil

      # Server vs client mode (nil until connect/receive is called)
      @server_mode = nil
    end

    def get path
      stream_id = @next_stream_id
      @next_stream_id += 2
      @streams[stream_id] = Stream.new(stream_id, nil, nil, self, :idle, @peer_settings[4], false, nil, false)

      headers = [
        [":method", "GET"],
        [":path", "/"],
        [":scheme", "http"],
        [":authority", "localhost:8443"],
        ["priority", "u=3"],
        ["accept", "*/*"],
        ["accept-encoding", "gzip, deflate"],
        ["user-agent", "htwo"],
      ]

      hpack = @encoding_table.encode headers

      send_headers io, stream_id, hpack
      stream_id
    end

    def finish
      send_goaway io, 0x0 # NO_ERROR
      io.flush
      io.close
      @reader.join
    end

    def connect
      @server_mode = false
      start_read_thread
      io.write CONNECTION_PREFACE
      send_settings io, nil
    end

    def receive
      @server_mode = true
      preface = io.read CONNECTION_PREFACE.bytesize
      if preface != CONNECTION_PREFACE
        send_goaway io, 0x1 # PROTOCOL_ERROR
        io.close
        return
      end
      send_settings io, nil
      io.flush
      start_read_thread
    end

    def ping
      ts = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)
      send_ping io, [ts].pack("Q>")
    end

    private

    def validate_headers headers, stream_id, is_trailer
      # Track pseudo-headers and regular headers
      pseudo_headers = {}
      seen_regular_header = false

      # Connection-specific headers that are not allowed
      forbidden_headers = %w[connection keep-alive proxy-connection transfer-encoding upgrade]

      headers.each do |name, value|
        # Check for uppercase letters
        if name =~ /[A-Z]/
          send_rst_stream @io, stream_id, 0x1 # PROTOCOL_ERROR
          return false
        end

        if name.start_with?(":")
          # Pseudo-header
          if is_trailer
            # Pseudo-headers not allowed in trailers
            send_rst_stream @io, stream_id, 0x1 # PROTOCOL_ERROR
            return false
          end

          if seen_regular_header
            # Pseudo-headers must come before regular headers
            send_rst_stream @io, stream_id, 0x1 # PROTOCOL_ERROR
            return false
          end

          # Check for duplicate pseudo-headers
          if pseudo_headers.key?(name)
            send_rst_stream @io, stream_id, 0x1 # PROTOCOL_ERROR
            return false
          end
          pseudo_headers[name] = value

          # Validate known pseudo-headers
          unless %w[:method :scheme :path :authority :status].include?(name)
            send_rst_stream @io, stream_id, 0x1 # PROTOCOL_ERROR
            return false
          end

          # :status is for responses only
          if @server_mode && name == ":status"
            send_rst_stream @io, stream_id, 0x1 # PROTOCOL_ERROR
            return false
          end

          # :path must not be empty
          if name == ":path" && value.empty?
            send_rst_stream @io, stream_id, 0x1 # PROTOCOL_ERROR
            return false
          end
        else
          # Regular header
          seen_regular_header = true

          # Check for forbidden connection-specific headers
          if forbidden_headers.include?(name.downcase)
            send_rst_stream @io, stream_id, 0x1 # PROTOCOL_ERROR
            return false
          end

          # TE header only allowed with value "trailers"
          if name.downcase == "te" && value != "trailers"
            send_rst_stream @io, stream_id, 0x1 # PROTOCOL_ERROR
            return false
          end
        end
      end

      # Check required pseudo-headers for requests (server mode)
      if @server_mode && !is_trailer
        unless pseudo_headers.key?(":method") && pseudo_headers.key?(":scheme") && pseudo_headers.key?(":path")
          send_rst_stream @io, stream_id, 0x1 # PROTOCOL_ERROR
          return false
        end
      end

      true
    end

    def start_read_thread
      @reader = Thread.new do
        read_loop
      rescue => e
        $stderr.puts "#{e.class}: #{e.message}"
        $stderr.puts e.backtrace.first(5).join("\n")
      end
    end

    def read_loop
      header_buff = HEADER_BUFF.dup

      while true
        begin
          str = io.readpartial(9, header_buff)
        rescue IOError, EOFError, Errno::ECONNRESET
          break
        end
        len_type, flags, stream_ident = str.unpack("NCN")
        len = len_type >> 8
        type = len_type & 0xFF
        stream_ident &= 0x7FFF_FFFF # clear reserved bit

        begin
          if len > 16384 && type != 0x4 # SETTINGS_MAX_FRAME_SIZE default
            raise Errors::FrameSizeError.new("Frame too large", 0)
          end

          # If we're expecting CONTINUATION, only CONTINUATION is allowed
          if @expecting_continuation && type != 0x9
            raise Errors::ProtocolError.new("Expected CONTINUATION", 0)
          end

          case type
          when 0x0 then handle_data io, len, flags, stream_ident
          when 0x1 then handle_headers io, len, flags, stream_ident
          when 0x2 then handle_priority io, len, flags, stream_ident
          when 0x3 then handle_rst_stream io, len, flags, stream_ident
          when 0x4 then handle_settings io, len, flags, stream_ident
          when 0x5 then handle_push_promise io, len, flags, stream_ident
          when 0x6 then handle_ping io, len, flags, stream_ident
          when 0x7
            handle_goaway io, len, flags, stream_ident
            io.close
            break
          when 0x8 then handle_window_update io, len, flags, stream_ident
          when 0x9 then handle_continuation io, len, flags, stream_ident
          else
            io.read(len) if len > 0 # skip unknown frame types (RFC 7540 4.1)
          end
        rescue Errors::ConnectionError => e
          io.read(e.remaining) if e.remaining > 0
          send_goaway io, e.error_code
          io.close
          break
        end
      end

      @handler.on_close
    end

    def send_ping io, data
      io.write "\x00\x00\x08\x06\x00\x00\x00\x00\x00"
      io.write data
    end

    def send_headers io, ident, hpack
      len = hpack.bytesize
      len_type = (len << 8) | 0x1

      flags = 0x04 | # END_HEADERS
        0x01 # END_STREAM

      io.write [len_type, flags, ident].pack("NCN")
      io.write hpack
    end

    def send_settings io, settings
      if settings
        raise NotImplementedError
      else
        io.write Frames::Settings::DEFAULT_ENCODED
      end
    end

    public

    def send_response stream, headers, body
      hpack = @encoding_table.encode headers
      len = hpack.bytesize
      len_type = (len << 8) | 0x1

      flags = 0x04 # END_HEADERS
      flags |= 0x01 unless body # END_STREAM if no body

      io.write [len_type, flags, stream.id].pack("NCN")
      io.write hpack
      io.flush

      if body
        body = body.b if body.encoding != Encoding::BINARY
        send_data_with_flow_control stream, body
      else
        stream.half_close_local!
      end
    end

    def send_data_with_flow_control stream, body
      offset = 0
      remaining = body.bytesize

      while remaining > 0
        max_frame = @peer_settings[5] # MAX_FRAME_SIZE
        send_size = [remaining, max_frame, stream.window_size, @window_size].min

        # If window is exhausted, buffer remaining data
        if send_size <= 0
          stream.pending_body = body.byteslice(offset, remaining)
          return
        end

        chunk = body.byteslice(offset, send_size)
        is_last = (offset + send_size) >= body.bytesize

        len = chunk.bytesize
        len_type = (len << 8) | 0x0
        flags = is_last ? 0x01 : 0x00 # END_STREAM on last chunk

        io.write [len_type, flags, stream.id].pack("NCN")
        io.write chunk
        io.flush

        stream.window_size -= len
        @window_size -= len
        offset += send_size
        remaining -= send_size
      end

      stream.half_close_local!
    end

    private

    def send_goaway io, error
      len = 8
      len_type = (len << 8) | 0x7
      flags = 0
      ident = 0
      last_stream_id = @highest_stream_id
      io.write [len_type, flags, ident, last_stream_id, error].pack("NCNNN")
      io.flush
    end

    def send_settings_ack io
      io.write "\x00\x00\x00\x04\x01\x00\x00\x00\x00"
      io.flush
    end

    def send_rst_stream io, stream_id, error_code
      len = 4
      len_type = (len << 8) | 0x3 # RST_STREAM
      flags = 0
      io.write [len_type, flags, stream_id, error_code].pack("NCNN")
      io.flush
    end

    def handle_data io, len, flags, stream_id
      # DATA frames cannot have stream_id = 0
      if stream_id.zero?
        raise Errors::ProtocolError.new("Got DATA on stream 0", len)
      end

      # Check for PADDED flag (bit 3)
      if flags[3].zero?
        # No padding, read all data
        chunk = io.read(len) if len > 0
      else
        # Read pad length
        return unless len > 0
        pad_length = io.readbyte

        # Validate pad length
        if pad_length >= len
          # Pad length is invalid (too large)
          raise Errors::ProtocolError.new("Invalid pad length", len - 1)
        end

        # Read data (excluding pad length byte and padding)
        data_len = len - pad_length - 1
        chunk = io.read(data_len) if data_len > 0

        # Read and discard padding
        io.read(pad_length) if pad_length > 0
      end

      stream = @streams[stream_id]

      # If stream doesn't exist or is in idle state, send error
      if !stream || stream.idle?
        raise Errors::ProtocolError.new("Invalid stream", 0)
      end

      # Check stream state - DATA not allowed on closed or half_closed_remote
      if stream.closed?
        raise Errors::StreamClosedError.new("DATA on closed stream", 0)
      elsif stream.half_closed_remote?
        send_rst_stream io, stream_id, 0x5 # STREAM_CLOSED
        return
      end

      if chunk && chunk.bytesize > 0
        stream.data ||= "".b
        stream.data << chunk
        @handler.on_data stream, chunk
      end

      # If END_STREAM flag is set, half-close remote
      unless flags[0].zero?
        # Validate content-length if specified
        if stream.content_length && stream.data
          if stream.data.bytesize != stream.content_length
            send_rst_stream io, stream_id, 0x1 # PROTOCOL_ERROR
            return
          end
        end

        stream.half_close_remote!
        @handler.on_request stream
      end
    end

    def handle_headers io, len, flags, stream_id
      # If already expecting CONTINUATION, receiving HEADERS is an error
      if @expecting_continuation
        raise Errors::ProtocolError.new("Already expecting continuation", 0)
      end

      # Validate stream ID is non-zero
      if stream_id.zero?
        raise Errors::ProtocolError.new("Got HEADERS on stream 0", len)
      end

      # Validate stream ID parity (clients use odd, servers use even)
      if @server_mode && stream_id.even?
        raise Errors::ProtocolError.new("Even stream ID from client", len)
      elsif !@server_mode && stream_id.odd?
        raise Errors::ProtocolError.new("Odd stream ID from server", len)
      end

      # Validate stream ID is increasing (unless stream already exists)
      if !@streams.key?(stream_id) && stream_id <= @highest_stream_id
        raise Errors::ProtocolError.new("Stream ID not increasing", len)
      end

      # Check MAX_CONCURRENT_STREAMS limit for new streams
      if !@streams.key?(stream_id) && @open_stream_count >= @local_max_concurrent_streams
        io.read(len) if len > 0
        send_rst_stream io, stream_id, 0x7 # REFUSED_STREAM
        @highest_stream_id = stream_id if stream_id > @highest_stream_id
        return
      end

      # Check stream state
      stream = @streams[stream_id]
      if stream
        # Check if receiving second HEADERS without END_STREAM (trailers must have END_STREAM)
        if stream.headers && !flags[0].positive?
          # Receiving second HEADERS without END_STREAM is error
          io.read(len) if len > 0
          send_rst_stream io, stream_id, 0x1 # PROTOCOL_ERROR
          return
        end

        # Stream exists - validate state allows HEADERS
        if stream.closed?
          # Receiving HEADERS on closed stream
          io.read(len) if len > 0

          # If stream was closed with RST_STREAM, send RST_STREAM (stream error)
          # If closed with END_STREAM, send GOAWAY (connection error)
          if stream.rst_received
            send_rst_stream io, stream_id, 0x5 # STREAM_CLOSED
            return
          else
            raise Errors::StreamClosedError.new("HEADERS on closed stream", 0)
          end
        elsif stream.half_closed_remote?
          # Already received END_STREAM, can't receive more HEADERS
          io.read(len) if len > 0
          send_rst_stream io, stream_id, 0x5 # STREAM_CLOSED
          return
        end
      end

      # Check for PRIORITY flag (bit 5) - HEADERS can include priority data
      has_priority = flags[5].positive?
      priority_bytes = has_priority ? 5 : 0

      payload = "".b
      payload_start = 0
      payload_len = 0

      # Check for PADDED flag (bit 3)
      if flags[3].zero?
        # No padding
        if len > 0
          payload = io.read(len)
          payload_len = len
        end

        # If PRIORITY flag set, validate and extract priority data
        if has_priority
          if payload.bytesize < 5
            raise Errors::FrameSizeError.new("HEADERS priority too short", 0)
          end
          stream_dependency = payload.unpack1("N") & 0x7FFF_FFFF
          # Check for self-dependency
          if stream_dependency == stream_id
            send_rst_stream io, stream_id, 0x1 # PROTOCOL_ERROR
            return
          end

          # Remove priority data from payload
          payload_start = 5
          payload_len -= 5
        end
      else
        # Has padding
        return if len.zero?
        pad_length = io.readbyte

        # Validate pad length (must account for priority data if present)
        min_len = 1 + priority_bytes # pad_length byte + priority bytes
        if pad_length >= len || (len - pad_length - 1) < priority_bytes
          raise Errors::ProtocolError.new("Invalid HEADERS pad length", len - 1)
        end

        # Read header block (excluding pad length byte, priority, and padding)
        data_len = len - pad_length - 1
        if data_len > 0
          payload = io.read(data_len)
          payload_len = data_len
        end

        # If PRIORITY flag set, validate and extract priority data
        if has_priority && payload.bytesize >= 5
          stream_dependency = payload.unpack1("N") & 0x7FFF_FFFF
          # Check for self-dependency
          if stream_dependency == stream_id
            # Read and discard remaining data
            io.read(pad_length) if pad_length > 0
            send_rst_stream io, stream_id, 0x1 # PROTOCOL_ERROR
            return
          end
          # Remove priority data from payload
          payload_start = 5
          payload_len -= 5
        end

        # Read and discard padding
        io.read(pad_length) if pad_length > 0
      end

      # Check if END_HEADERS flag is set (bit 2)
      end_headers = flags[2].positive?

      if end_headers
        # Complete header block in this frame
        headers = @decoding_table.decode payload, payload_start, payload_len

        # Update highest stream ID seen
        if stream_id > @highest_stream_id
          @highest_stream_id = stream_id
        end

        stream = @streams[stream_id] ||= Stream.new(stream_id, nil, nil, self, :idle, @peer_settings[4], false, nil, false)

        # Validate headers
        is_trailer = stream.headers ? true : false
        return unless validate_headers(headers, stream_id, is_trailer)

        # Transition state: idle -> open
        if stream.idle?
          stream.open!
          @open_stream_count += 1
        end

        stream.headers = headers

        # Extract content-length if present
        content_length_header = headers.find { |k, v| k == "content-length" }
        if content_length_header
          stream.content_length = content_length_header[1].to_i
        end

        @handler.on_headers stream

        # If END_STREAM flag is set, half-close remote
        if flags[0].positive?
          # Validate content-length before closing
          if stream.content_length && stream.data
            if stream.data.bytesize != stream.content_length
              send_rst_stream @io, stream_id, 0x1 # PROTOCOL_ERROR
              return
            end
          end

          stream.half_close_remote!
          @handler.on_request stream
        end
      else
        # Partial header block, expect CONTINUATION
        @expecting_continuation = true
        @continuation_stream_id = stream_id
        @header_buffer = payload.dup
        @continuation_flags = flags # Save flags from HEADERS frame

        # Update highest stream ID seen
        if stream_id > @highest_stream_id
          @highest_stream_id = stream_id
        end
      end
    end

    def handle_ping io, len, flags, stream_ident
      raise Errors::ProtocolError.new("PING on non-zero stream", len) unless stream_ident.zero?
      raise Errors::FrameSizeError.new("PING length != 8", len) unless len == 8

      payload = io.read(8)
      if flags[0].zero?
        # Peer PING: echo back with ACK flag (bit 0)
        io.write "\x00\x00\x08\x06\x01\x00\x00\x00\x00"
        io.write payload
      else
        # ACK of our PING: compute RTT
        sent_at = payload.unpack1("Q>")
        rtt_ns = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond) - sent_at
        @handler.on_ping rtt_ns
      end
    end

    def handle_settings io, len, flags, stream_ident
      raise Errors::ProtocolError.new("SETTINGS on non-zero stream", len) unless stream_ident.zero?

      # SETTINGS with ACK flag must have zero length (bit 0)
      if flags[0].positive?
        raise Errors::FrameSizeError.new("SETTINGS ACK with payload", len) if len.positive?
        return
      end

      raise Errors::FrameSizeError.new("SETTINGS length not multiple of 6", len) if (len % 6) != 0

      read = 0
      s = "\0".b * 6
      old_initial_window_size = @peer_settings[4]

      while read < len
        ident, value = io.readpartial(6, s).unpack("nN")

        # Validate parameter values
        case ident
        when 0x2 # SETTINGS_ENABLE_PUSH
          unless value == 0 || value == 1
            raise Errors::ProtocolError.new("ENABLE_PUSH must be 0 or 1", len - read - 6)
          end
        when 0x4 # SETTINGS_INITIAL_WINDOW_SIZE
          if value > 0x7FFF_FFFF
            raise Errors::FlowControlError.new("INITIAL_WINDOW_SIZE too large", len - read - 6)
          end
        when 0x5 # SETTINGS_MAX_FRAME_SIZE
          if value < 16384 || value > 16777215
            raise Errors::ProtocolError.new("MAX_FRAME_SIZE out of range", len - read - 6)
          end
        end

        @peer_settings[ident] = value if ident < @peer_settings.length
        read += 6
      end

      # Apply window size updates to existing streams
      new_initial_window_size = @peer_settings[4]
      if new_initial_window_size != old_initial_window_size
        delta = new_initial_window_size - old_initial_window_size

        @streams.each_value do |stream|
          next if stream.idle? || stream.closed?

          stream.window_size ||= old_initial_window_size
          new_window = stream.window_size + delta

          # Only overflow (> 2^31-1) is an error
          # Negative windows are valid - sender just can't send until WINDOW_UPDATE
          if new_window > 0x7FFF_FFFF
            raise Errors::FlowControlError.new("Window size overflow", 0)
          end

          stream.window_size = new_window

          # Flush pending data if window opened up
          if stream.pending_body && stream.window_size > 0
            send_data_with_flow_control stream, stream.pending_body
            stream.pending_body = nil
          end
        end
      end

      send_settings_ack io
    end

    def handle_goaway io, len, flags, stream_ident
      raise Errors::ProtocolError.new("GOAWAY on non-zero stream", len) unless stream_ident.zero?
      raise Errors::FrameSizeError.new("GOAWAY too short", len) if len < 8

      buff = "\0".b * 4
      last_stream_id = io.readpartial(4, buff).unpack1("N") & 0x7FFF_FFF
      error_code = io.readpartial(4, buff).unpack1("N")

      # Read optional debug data
      if len > 8
        io.read(len - 8)
      end
    end

    def handle_window_update io, len, flags, stream_ident
      raise Errors::FrameSizeError.new("WINDOW_UPDATE length != 4", len) unless len == 4

      increment = io.readpartial(4).unpack1("N") & 0x7FFF_FFFF

      # Increment must be non-zero
      if increment.zero?
        if stream_ident.zero?
          raise Errors::ProtocolError.new("WINDOW_UPDATE increment 0 on connection", 0)
        else
          send_rst_stream io, stream_ident, 0x1 # PROTOCOL_ERROR
          return
        end
      end

      if stream_ident.zero?
        @window_size += increment
        raise Errors::FlowControlError.new("Connection window overflow", 0) if @window_size > 0x7FFF_FFFF
      else
        stream = @streams[stream_ident]
        raise Errors::ProtocolError.new("WINDOW_UPDATE on idle stream", 0) if !stream || stream.idle?

        stream.window_size ||= 65535
        stream.window_size += increment

        # Check for overflow
        if stream.window_size > 0x7FFF_FFFF
          send_rst_stream io, stream_ident, 0x3 # FLOW_CONTROL_ERROR
          return
        end

        # Flush pending data if window opened up
        if stream.pending_body && stream.window_size > 0
          send_data_with_flow_control stream, stream.pending_body
          stream.pending_body = nil
        end
      end
    end

    def handle_rst_stream io, len, flags, stream_id
      raise Errors::ProtocolError.new("RST_STREAM on stream 0", len) if stream_id.zero?
      raise Errors::FrameSizeError.new("RST_STREAM length != 4", len) if len != 4

      error_code = io.readpartial(4).unpack1("N")

      # Validate stream state - RST_STREAM on idle stream is PROTOCOL_ERROR
      stream = @streams[stream_id]
      raise Errors::ProtocolError.new("RST_STREAM on idle stream", 0) if !stream || stream.idle?

      # Close the stream and mark that RST_STREAM was received
      stream.rst_received = true
      stream.close!
    end

    def handle_priority io, len, flags, stream_id
      raise Errors::ProtocolError.new("PRIORITY on stream 0", len) if stream_id.zero?
      raise Errors::FrameSizeError.new("PRIORITY length != 5", len) if len != 5

      # Read priority data
      data = io.readpartial(5)
      stream_dependency = data.unpack1("N") & 0x7FFF_FFFF
      # exclusive = (data.unpack1("N") & 0x8000_0000) != 0
      # weight = data[4].unpack1("C")

      # Check for self-dependency
      if stream_dependency == stream_id
        # Send RST_STREAM for this stream
        send_rst_stream io, stream_id, 0x1 # PROTOCOL_ERROR
        return
      end

      # Otherwise, we just ignore priority info for now
    end

    def handle_push_promise io, len, flags, stream_id
      raise Errors::ProtocolError.new("PUSH_PROMISE not allowed", len)
    end

    def handle_continuation io, len, flags, stream_id
      raise Errors::ProtocolError.new("Unexpected CONTINUATION", len) unless @expecting_continuation
      raise Errors::ProtocolError.new("CONTINUATION stream mismatch", len) if stream_id != @continuation_stream_id
      raise Errors::ProtocolError.new("CONTINUATION on stream 0", len) if stream_id.zero?

      payload = io.read(len)
      return unless payload

      # Append to header buffer
      @header_buffer << payload

      # Check if END_HEADERS flag is set (bit 2)
      end_headers = flags[2].positive?

      if end_headers
        # Complete header block
        @expecting_continuation = false
        complete_payload = @header_buffer
        saved_flags = @continuation_flags # Use flags from original HEADERS frame
        @header_buffer = nil
        @continuation_stream_id = nil
        @continuation_flags = nil

        headers = @decoding_table.decode complete_payload, 0, complete_payload.bytesize

        stream = @streams[stream_id] ||= Stream.new(stream_id, nil, nil, self, :idle, @peer_settings[4], false, nil, false)

        # Validate headers
        is_trailer = stream.headers ? true : false
        return unless validate_headers(headers, stream_id, is_trailer)

        # Transition state: idle -> open
        if stream.idle?
          stream.open!
          @open_stream_count += 1
        end

        stream.headers = headers
        @handler.on_headers stream

        # If END_STREAM flag was set on original HEADERS frame, half-close remote
        if saved_flags[0].positive?
          stream.half_close_remote!
          @handler.on_request stream
        end
      end
      # Otherwise, keep expecting more CONTINUATION frames
    end
  end

  class ClientHandler < Handler
    def initialize
      @ports = {}
      @ping_port = nil
    end

    attr_writer :ping_port

    def register stream_id, port
      @ports[stream_id] = port
    end

    def on_headers stream
      @ports[stream.id] << stream.headers
    end

    def on_data stream, chunk
      @ports[stream.id] << chunk.freeze
    end

    def on_request stream
      @ports[stream.id] << nil
      @ports.delete stream.id
    end

    def on_ping rtt
      @ping_port << rtt
    end

    def on_close
      @ports.each_value { |port| port << nil }
      @ports.clear
    end
  end

  class Connection
    def initialize io
      @s = Ractor.new(io) { |io|
        handler = ClientHandler.new
        session = Session.new(io, handler: handler)
        while true
          cmd, port, data = Ractor.receive

          case cmd
          when :connect then session.connect
          when :receive then session.receive
          when :ping
            handler.ping_port = port
            session.ping
          when :get
            stream_id = session.get(data)
            handler.register(stream_id, port)
          when :finish then session.finish; break
          else
          end
        end
      }
    end

    def connect
      @s << [:connect, Ractor.current.default_port]
    end

    def receive
      @s << [:receive, Ractor.current.default_port]
    end

    def finish
      @s << [:finish, Ractor.current.default_port]
      @s.value
    end

    def ping
      @s << [:ping, Ractor.current.default_port]
      Ractor.receive
    end

    def get path
      @s << [:get, Ractor.current.default_port, path]
      headers = Ractor.receive
      body = "".b
      while part = Ractor.receive
        body << part
      end
      [headers, body]
    end
  end
end

if $0 == __FILE__
  require "socket"
  require "openssl"
  require "uri"

  uri = URI.parse "https://localhost:8443"

  tcp = TCPSocket.new uri.host, uri.port
  tcp.sync = true

  client = HTWO::Connection.new tcp
  client.connect
  p PING: client.ping
  p client.get "/"
  client.finish
end
