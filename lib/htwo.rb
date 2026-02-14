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

    def receiving_headers! end_stream, remaining
      # Second HEADERS without END_STREAM is invalid (trailers must end the stream)
      if headers && !end_stream
        raise Errors::StreamError.new("Second HEADERS without END_STREAM", id, remaining)
      end

      if closed?
        # If stream was closed with RST_STREAM, send RST_STREAM (stream error)
        # If closed with END_STREAM, send GOAWAY (connection error)
        if rst_received
          raise Errors::StreamClosed.new("HEADERS on RST closed stream", id, remaining)
        else
          raise Errors::StreamClosedError.new("HEADERS on closed stream", remaining)
        end
      elsif half_closed_remote?
        raise Errors::StreamClosed.new("HEADERS on half-closed-remote stream", id, remaining)
      end
    end
  end

  class Session
    HEADER_BUFF = ("\0".b * 9).freeze
    private_constant :HEADER_BUFF

    MAX_HEADER_LIST_SIZE = 65536
    MAX_PENDING_BODY_SIZE = 1_048_576

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
      @pending_body_size = 0
      @local_max_concurrent_streams = 100

      # CONTINUATION frame state
      @expecting_continuation = false
      @continuation_stream_id = nil
      @header_buffer = nil
      @continuation_flags = nil

      # Server vs client mode (nil until connect/receive is called)
      @server_mode = nil
    end

    def new_stream
      stream_id = @next_stream_id
      @next_stream_id += 2
      stream = Stream.new(stream_id, nil, nil, self, :idle, @peer_settings[4], false, nil, false)
      @streams[stream_id] = stream
      stream_id
    end

    def send_headers stream_id, headers, has_body: false
      stream = @streams.fetch(stream_id)

      hpack = @encoding_table.encode headers
      len = hpack.bytesize
      len_type = (len << 8) | 0x1

      flags = 0x04 # END_HEADERS
      flags |= 0x01 unless has_body # END_STREAM if no body

      io.write [len_type, flags, stream_id].pack("NCN")
      io.write hpack
      io.flush

      if stream.idle?
        stream.open!
        @open_stream_count += 1
      end

      unless has_body
        stream.half_close_local!
        if stream.closed?
          @streams.delete(stream_id)
          @open_stream_count -= 1
        end
      end
    end

    def send_body stream_id, body
      stream = @streams.fetch stream_id
      body = body.b if body.encoding != Encoding::BINARY
      send_data_with_flow_control stream, body
    end

    def request headers, body: nil
      stream_id = self.new_stream

      send_headers stream_id, headers, has_body: body

      send_headers stream_id, body if body

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
      content_length = nil

      # Connection-specific headers that are not allowed
      forbidden_headers = %w[connection keep-alive proxy-connection transfer-encoding upgrade]

      headers.each do |name, value|
        raise Errors::StreamError.new("Uppercase header name", stream_id) if name =~ /[A-Z]/

        if name.start_with?(":")
          raise Errors::StreamError.new("Pseudo-header in trailers", stream_id) if is_trailer
          raise Errors::StreamError.new("Pseudo-header after regular header", stream_id) if seen_regular_header
          raise Errors::StreamError.new("Duplicate pseudo-header", stream_id) if pseudo_headers.key?(name)
          pseudo_headers[name] = value

          unless %w[:method :scheme :path :authority :status].include?(name)
            raise Errors::StreamError.new("Unknown pseudo-header", stream_id)
          end

          raise Errors::StreamError.new("Response pseudo-header in request", stream_id) if @server_mode && name == ":status"
          raise Errors::StreamError.new("Empty :path", stream_id) if name == ":path" && value.empty?
        else
          seen_regular_header = true
          raise Errors::StreamError.new("Forbidden connection header", stream_id) if forbidden_headers.include?(name.downcase)
          raise Errors::StreamError.new("Invalid TE value", stream_id) if name.downcase == "te" && value != "trailers"
          content_length = value.to_i if name == "content-length"
        end
      end

      # Check required pseudo-headers for requests (server mode)
      if @server_mode && !is_trailer
        unless pseudo_headers.key?(":method") && pseudo_headers.key?(":scheme") && pseudo_headers.key?(":path")
          raise Errors::StreamError.new("Missing required pseudo-header", stream_id)
        end
      end

      content_length
    end

    def start_read_thread
      @reader = Thread.new { read_loop }
    end

    def read_loop
      header_buff = HEADER_BUFF.dup

      while true
        begin
          str = io.read(9, header_buff)
        rescue IOError, Errno::ECONNRESET
          break
        end
        break unless str
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
        rescue Errors::StreamError => e
          io.read(e.remaining) if e.remaining > 0
          send_rst_stream io, e.stream_id, e.error_code
          @highest_stream_id = e.stream_id if e.stream_id > @highest_stream_id
        rescue Errors::ConnectionError => e
          io.read(e.remaining) if e.remaining > 0
          send_goaway io, e.error_code
          io.close
          break
        rescue IOError, Errno::ECONNRESET
          break
        end
      end

      @handler.on_close
    end

    def send_ping io, data
      io.write "\x00\x00\x08\x06\x00\x00\x00\x00\x00"
      io.write data
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
        if stream.closed?
          @streams.delete(stream.id)
          @open_stream_count -= 1
        end
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
          pending = body.byteslice(offset, remaining)
          if @pending_body_size + pending.bytesize > MAX_PENDING_BODY_SIZE
            send_rst_stream io, stream.id, 0x7 # REFUSED_STREAM
            stream.close!
            @streams.delete(stream.id)
            @open_stream_count -= 1
            return
          end
          @pending_body_size += pending.bytesize
          stream.pending_body = pending
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
      if stream.closed?
        @streams.delete(stream.id)
        @open_stream_count -= 1
      end
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
      if !stream
        if stream_id <= @highest_stream_id
          raise Errors::StreamClosedError.new("DATA on closed stream", 0)
        else
          raise Errors::ProtocolError.new("Invalid stream", 0)
        end
      elsif stream.idle?
        raise Errors::ProtocolError.new("Invalid stream", 0)
      end

      # Check stream state - DATA not allowed on closed or half_closed_remote
      if stream.closed?
        raise Errors::StreamClosedError.new("DATA on closed stream", 0)
      elsif stream.half_closed_remote?
        raise Errors::StreamClosed.new("DATA on half-closed-remote stream", stream_id)
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
            raise Errors::StreamError.new("Content-length mismatch", stream_id)
          end
        end

        stream.half_close_remote!
        @handler.on_request stream
        if stream.closed?
          @streams.delete(stream_id)
          @open_stream_count -= 1
        end
      end
    end

    def handle_headers io, len, flags, stream_id
      # If already expecting CONTINUATION, receiving HEADERS is an error
      raise Errors::ProtocolError.new("Already expecting continuation", 0) if @expecting_continuation

      # Validate stream ID is non-zero
      raise Errors::ProtocolError.new("Got HEADERS on stream 0", len) if stream_id.zero?

      # Validate stream ID parity for new streams (peer-initiated)
      if !@streams.key?(stream_id)
        if @server_mode && stream_id.even?
          raise Errors::ProtocolError.new("Even stream ID from client", len)
        elsif !@server_mode && stream_id.odd?
          raise Errors::ProtocolError.new("Odd stream ID from server", len)
        end
      end

      # Validate stream ID is increasing (unless stream already exists)
      if !@streams.key?(stream_id) && stream_id <= @highest_stream_id
        raise Errors::ProtocolError.new("Stream ID not increasing", len)
      end

      # Check MAX_CONCURRENT_STREAMS limit for new streams
      if !@streams.key?(stream_id) && @open_stream_count >= @local_max_concurrent_streams
        raise Errors::RefusedStream.new("Max concurrent streams exceeded", stream_id, len)
      end

      # Check stream state
      @streams[stream_id]&.receiving_headers!(flags[0].positive?, len)

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
            raise Errors::StreamError.new("HEADERS self-dependency", stream_id)
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
            io.read(pad_length) if pad_length > 0
            raise Errors::StreamError.new("HEADERS self-dependency", stream_id)
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
        headers = @decoding_table.decode payload, payload_start, payload_len, max_list_size: MAX_HEADER_LIST_SIZE

        # Update highest stream ID seen
        if stream_id > @highest_stream_id
          @highest_stream_id = stream_id
        end

        stream = @streams[stream_id] ||= Stream.new(stream_id, nil, nil, self, :idle, @peer_settings[4], false, nil, false)

        # Validate headers
        stream.content_length = validate_headers headers, stream_id, !!stream.headers

        # Transition state: idle -> open
        if stream.idle?
          stream.open!
          @open_stream_count += 1
        end

        stream.headers = headers

        @handler.on_headers stream

        # If END_STREAM flag is set, half-close remote
        if flags[0].positive?
          # Validate content-length before closing
          if stream.content_length && stream.data
            if stream.data.bytesize != stream.content_length
              raise Errors::StreamError.new("Content-length mismatch", stream_id)
            end
          end

          stream.half_close_remote!
          @handler.on_request stream
          if stream.closed?
            @streams.delete(stream_id)
            @open_stream_count -= 1
          end
        end
      else
        # Partial header block, expect CONTINUATION
        @expecting_continuation = true
        @continuation_stream_id = stream_id
        if payload_start > 0
          @header_buffer = payload.byteslice(payload_start, payload_len)
        else
          @header_buffer = payload
        end
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
        ident, value = io.read(6, s).unpack("nN")

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
            @pending_body_size -= stream.pending_body.bytesize
            pending = stream.pending_body
            stream.pending_body = nil
            send_data_with_flow_control stream, pending
          end
        end
      end

      send_settings_ack io
    end

    def handle_goaway io, len, flags, stream_ident
      raise Errors::ProtocolError.new("GOAWAY on non-zero stream", len) unless stream_ident.zero?
      raise Errors::FrameSizeError.new("GOAWAY too short", len) if len < 8

      # Consume last_stream_id and error_code fields to advance the IO position
      io.read(8)

      # Read optional debug data
      if len > 8
        io.read(len - 8)
      end
    end

    def handle_window_update io, len, flags, stream_ident
      raise Errors::FrameSizeError.new("WINDOW_UPDATE length != 4", len) unless len == 4

      increment = io.read(4).unpack1("N") & 0x7FFF_FFFF

      # Increment must be non-zero
      if increment.zero?
        if stream_ident.zero?
          raise Errors::ProtocolError.new("WINDOW_UPDATE increment 0 on connection", 0)
        else
          raise Errors::StreamError.new("WINDOW_UPDATE increment 0 on stream", stream_ident)
        end
      end

      if stream_ident.zero?
        @window_size += increment
        raise Errors::FlowControlError.new("Connection window overflow", 0) if @window_size > 0x7FFF_FFFF
      else
        stream = @streams[stream_ident]
        if !stream
          if stream_ident <= @highest_stream_id
            return # Stream already closed, ignore
          else
            raise Errors::ProtocolError.new("WINDOW_UPDATE on idle stream", 0)
          end
        elsif stream.idle?
          raise Errors::ProtocolError.new("WINDOW_UPDATE on idle stream", 0)
        end

        stream.window_size ||= 65535
        stream.window_size += increment

        # Check for overflow
        if stream.window_size > 0x7FFF_FFFF
          raise Errors::StreamError.new("Stream window overflow", stream_ident, 0, 0x3)
        end

        # Flush pending data if window opened up
        if stream.pending_body && stream.window_size > 0
          @pending_body_size -= stream.pending_body.bytesize
          pending = stream.pending_body
          stream.pending_body = nil
          send_data_with_flow_control stream, pending
        end
      end
    end

    def handle_rst_stream io, len, flags, stream_id
      raise Errors::ProtocolError.new("RST_STREAM on stream 0", len) if stream_id.zero?
      raise Errors::FrameSizeError.new("RST_STREAM length != 4", len) if len != 4

      # Consume error_code to advance the IO position
      io.read(4)

      # Validate stream state - RST_STREAM on idle stream is PROTOCOL_ERROR
      stream = @streams[stream_id]
      if !stream
        if stream_id <= @highest_stream_id
          return # Stream already closed, ignore per RFC
        else
          raise Errors::ProtocolError.new("RST_STREAM on idle stream", 0)
        end
      elsif stream.idle?
        raise Errors::ProtocolError.new("RST_STREAM on idle stream", 0)
      end

      # Close the stream and mark that RST_STREAM was received
      if stream.pending_body
        @pending_body_size -= stream.pending_body.bytesize
        stream.pending_body = nil
      end
      stream.rst_received = true
      stream.close!
      @streams.delete(stream_id)
      @open_stream_count -= 1
    end

    def handle_priority io, len, flags, stream_id
      raise Errors::ProtocolError.new("PRIORITY on stream 0", len) if stream_id.zero?
      raise Errors::FrameSizeError.new("PRIORITY length != 5", len) if len != 5

      # Read priority data
      data = io.read(5)
      stream_dependency = data.unpack1("N") & 0x7FFF_FFFF
      # exclusive = (data.unpack1("N") & 0x8000_0000) != 0
      # weight = data[4].unpack1("C")

      # Check for self-dependency
      if stream_dependency == stream_id
        raise Errors::StreamError.new("PRIORITY self-dependency", stream_id)
      end
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

      if @header_buffer.bytesize > MAX_HEADER_LIST_SIZE
        @expecting_continuation = false
        @header_buffer = nil
        @continuation_stream_id = nil
        @continuation_flags = nil
        raise Errors::ConnectionError.new("Header block too large", 0, 0x0B) # ENHANCE_YOUR_CALM
      end

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

        headers = @decoding_table.decode complete_payload, 0, complete_payload.bytesize, max_list_size: MAX_HEADER_LIST_SIZE

        stream = @streams[stream_id] ||= Stream.new(stream_id, nil, nil, self, :idle, @peer_settings[4], false, nil, false)

        # Validate headers
        stream.content_length = validate_headers headers, stream_id, !!stream.headers

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
          if stream.closed?
            @streams.delete(stream_id)
            @open_stream_count -= 1
          end
        end
      end
      # Otherwise, keep expecting more CONTINUATION frames
    end
  end
end
