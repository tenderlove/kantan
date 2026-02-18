# frozen_string_literal: true

require "htwo/hpack"
require "htwo/errors"
require "htwo/stream"
require "securerandom"

module HTWO
  module Body
    class Buffer
      def initialize(string)
        @string = string
        @offset = 0
      end

      def read(n)
        chunk = @string.byteslice(@offset, n)
        @offset += n
        chunk
      end

      def bytesize
        @string.bytesize - @offset
      end

      def empty?
        @offset >= @string.bytesize
      end

      def close
      end
    end

    class File
      def initialize(path)
        @io = ::File.open(path, "rb")
        @remaining = @io.size
      end

      def read(n)
        chunk = @io.read(n)
        @remaining -= chunk.bytesize
        chunk
      end

      def bytesize
        @remaining
      end

      def empty?
        @remaining == 0
      end

      def close
        @io.close
      end
    end
  end

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

    class Settings < Struct.new(:nil, :header_table_size, :enable_push, :max_concurrent_streams,
      :initial_window_size, :max_frame_size, :max_header_list_size)
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

      DEFAULT = self.new(
        nil,
        nil, # default is 4096
        nil, # don't specify push promise
        100, # max concurrent streams
      ).freeze

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

      def encode stream_id
        self.class.encode stream_id, self
      end

      DEFAULT_ENCODED = DEFAULT.encode(0).freeze
    end
  end

  class Handler
    def on_headers stream; end
    def on_data stream, chunk; end
    def on_request stream; end
    def on_ping rtt; end
    def on_close; end
  end

  class Session
    MAX_HEADER_LIST_SIZE = 65536
    MAX_PENDING_BODY_SIZE = 1_048_576
    WRITE_BUFFER_SIZE = 65536

    CONNECTION_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".b.freeze

    def initialize io, handler:
      @name = SecureRandom.uuid
      @io = io
      @handler = handler

      # Table used to encode values sent to the peer (owned by write thread)
      @encoding_table = HPACK.new

      # Table used to decode values sent by the peer (owned by read thread)
      @decoding_table = HPACK.new

      @peer_settings = Frames::Settings.new(
        0,
        4096, # default header table size,
        1,    # default enable_push
        -1,   # default value max concurrent streams (-1 for unlimited)
        65535, # initial window size
        16384, # initial max frame size
        -1,    # max header list size (-1 for not set)
      )

      @connection_window = 65535
      @write_queue = Thread::Queue.new
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
      stream = Stream.new(stream_id, nil, 0, self, :idle, @peer_settings.initial_window_size, false, nil, false)
      @streams[stream_id] = stream
      stream_id
    end

    def send_headers stream_id, headers, has_body: false
      @write_queue << [:headers, stream_id, headers, !has_body]
    end

    def send_body stream_id, body
      body = body.b if body.encoding != Encoding::BINARY
      @write_queue << [:data, stream_id, body]
    end

    def send_file stream_id, path
      @write_queue << [:sendfile, stream_id, path]
    end

    def request headers, body: nil
      stream_id = new_stream
      send_headers stream_id, headers, has_body: !!body
      send_body stream_id, body if body
      stream_id
    end

    def finish
      @write_queue << [:goaway, 0x0]
      @write_queue << [:shutdown]
      join
    end

    def join
      @writer&.join
      @reader&.join
    end

    def connect
      @server_mode = false
      @io.write CONNECTION_PREFACE
      @io.write Frames::Settings::DEFAULT_ENCODED
      start_write_thread
      start_read_thread
    end

    def receive(preface_verified: false)
      @server_mode = true
      unless preface_verified
        preface = @io.read CONNECTION_PREFACE.bytesize
        if preface != CONNECTION_PREFACE
          send_goaway_frame @io, 0x1 # PROTOCOL_ERROR
          @io.close
          return
        end
      end
      @io.write Frames::Settings::DEFAULT_ENCODED
      start_write_thread
      start_read_thread
    end

    def ping
      ts = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)
      @write_queue << [:ping, [ts].pack("Q>")]
    end

    private

    def validate_headers headers, stream_id, is_trailer
      # Track pseudo-headers and regular headers
      seen_regular_header = false
      content_length = nil

      pseudo_headers = 0

      headers.each do |name, value|
        if name.getbyte(0) == 58 # starts with :
          raise Errors::StreamError.new("Pseudo-header in trailers", stream_id) if is_trailer
          raise Errors::StreamError.new("Pseudo-header after regular header", stream_id) if seen_regular_header

          case name
          when ":method"
            raise Errors::StreamError.new("Duplicate pseudo-header", stream_id) if pseudo_headers.odd?
            pseudo_headers |= 0x01
          when ":scheme"
            raise Errors::StreamError.new("Duplicate pseudo-header", stream_id) if pseudo_headers[1].positive?
            pseudo_headers |= 0x02
          when ":path"
            raise Errors::StreamError.new("Duplicate pseudo-header", stream_id) if pseudo_headers[2].positive?
            raise Errors::StreamError.new("Empty :path", stream_id) if value.empty?
            pseudo_headers |= 0x04
          when ":authority"
            raise Errors::StreamError.new("Duplicate pseudo-header", stream_id) if pseudo_headers[3].positive?
            pseudo_headers |= 0x08
          when ":status"
            raise Errors::StreamError.new("Duplicate pseudo-header", stream_id) if pseudo_headers[4].positive?
            raise Errors::StreamError.new("Response pseudo-header in request", stream_id) if @server_mode
            pseudo_headers |= 0x10
          else
            raise Errors::StreamError.new("Unknown pseudo-header", stream_id)
          end
        else
          seen_regular_header = true
          case name
            # Connection-specific headers that are not allowed
          when "connection", "keep-alive", "proxy-connection", "transfer-encoding upgrade"
            raise Errors::StreamError.new("Forbidden connection header", stream_id)
          when "te"
            raise Errors::StreamError.new("Invalid TE value", stream_id) if value != "trailers"
          when "content-length"
            content_length = value.to_i
          end
        end
      end

      # Check required pseudo-headers for requests (server mode)
      if @server_mode && !is_trailer
        unless pseudo_headers & 0x7 == 0x7
          raise Errors::StreamError.new("Missing required pseudo-header", stream_id)
        end
      end

      content_length
    end

    # ── Write thread ──────────────────────────────────────────────────────

    def start_write_thread
      @writer = Thread.new {
        Thread.current.name = "writer - " + @name
        write_loop(@io)
      }
    end

    def write_loop io
      wbuf = String.new(encoding: Encoding::BINARY, capacity: WRITE_BUFFER_SIZE)

      while (cmd = @write_queue.pop)
        case cmd[0]
        when :headers
          _, stream_id, headers, end_stream = cmd
          stream = @streams[stream_id]
          next unless stream

          hpack = @encoding_table.encode headers
          len = hpack.bytesize
          len_type = (len << 8) | 0x1
          flags = 0x04 # END_HEADERS
          flags |= 0x01 if end_stream

          [len_type, flags, stream_id].pack("NCN", buffer: wbuf)
          wbuf << hpack

          if stream.idle?
            stream.open!
            @open_stream_count += 1
          end

          if end_stream
            stream.half_close_local!
            if stream.closed?
              @streams.delete(stream_id)
              @open_stream_count -= 1
            end
          end

        when :data
          _, stream_id, data = cmd
          stream = @streams[stream_id]
          next unless stream

          stream.body = Body::Buffer.new(data)
          @pending_body_size += data.bytesize
          flush_pending wbuf

        when :sendfile
          _, stream_id, path = cmd
          stream = @streams[stream_id]
          next unless stream

          stream.body = Body::File.new(path)
          @pending_body_size += stream.body.bytesize
          flush_pending wbuf

        when :ping
          _, payload = cmd
          wbuf << "\x00\x00\x08\x06\x00\x00\x00\x00\x00"
          wbuf << payload

        when :ping_ack
          _, payload = cmd
          wbuf << "\x00\x00\x08\x06\x01\x00\x00\x00\x00"
          wbuf << payload

        when :settings_ack
          wbuf << "\x00\x00\x00\x04\x01\x00\x00\x00\x00"

        when :rst_stream
          _, stream_id, error_code = cmd
          [(4 << 8) | 0x3, 0, stream_id, error_code].pack("NCNN", buffer: wbuf)

        when :goaway
          _, error_code = cmd
          [(8 << 8) | 0x7, 0, 0, @highest_stream_id, error_code].pack("NCNNN", buffer: wbuf)

        when :window_update
          _, stream_id, increment = cmd
          stream_overflow = false
          if stream_id.zero?
            @connection_window += increment
            if @connection_window > 0x7FFF_FFFF
              [(8 << 8) | 0x7, 0, 0, @highest_stream_id, 0x3].pack("NCNNN", buffer: wbuf)
              break
            end
          else
            stream = @streams[stream_id]
            if stream
              stream.window_size += increment
              if stream.window_size > 0x7FFF_FFFF
                [(4 << 8) | 0x3, 0, stream_id, 0x3].pack("NCNN", buffer: wbuf)
                stream_overflow = true
              end
            end
          end
          flush_pending wbuf unless stream_overflow

        when :settings
          _, settings = cmd
          old_initial_window_size = @peer_settings.initial_window_size
          settings.each do |ident, value|
            @peer_settings[ident] = value if ident < @peer_settings.length
          end

          new_initial_window_size = @peer_settings.initial_window_size
          if new_initial_window_size != old_initial_window_size
            delta = new_initial_window_size - old_initial_window_size
            overflow = false
            @streams.each_value do |stream|
              next if stream.idle? || stream.closed?
              stream.window_size += delta
              if stream.window_size > 0x7FFF_FFFF
                [(8 << 8) | 0x7, 0, 0, @highest_stream_id, 0x3].pack("NCNNN", buffer: wbuf)
                overflow = true
                break
              end
            end
            break if overflow
          end
          flush_pending wbuf

        when :send_window_update
          _, stream_id, increment = cmd
          # Connection-level WINDOW_UPDATE (stream 0)
          [(4 << 8) | 0x8, 0, 0, increment].pack("NCNN", buffer: wbuf)
          # Stream-level WINDOW_UPDATE
          [(4 << 8) | 0x8, 0, stream_id, increment].pack("NCNN", buffer: wbuf)

        when :close_stream
          _, stream = cmd
          if stream.body
            @pending_body_size -= stream.body.bytesize
            stream.body.close
            stream.body = nil
          end

        when :shutdown
          break
        end

        # Flush when queue is drained (about to block) or buffer is large
        if wbuf.bytesize > 0 && (@write_queue.empty? || wbuf.bytesize >= WRITE_BUFFER_SIZE)
          io.write wbuf
          wbuf.clear
        end
      end
    rescue IOError, Errno::ECONNRESET
      # Connection closed, exit write loop
    ensure
      io.write wbuf rescue nil if wbuf.bytesize > 0
      io.close rescue nil
    end

    def flush_pending wbuf
      @streams.each_value do |stream|
        next unless stream.body
        next if stream.body.empty?

        while stream.body && !stream.body.empty?
          max_frame = @peer_settings.max_frame_size
          send_size = [stream.body.bytesize, max_frame, stream.window_size, @connection_window].min

          if send_size <= 0
            if @pending_body_size > MAX_PENDING_BODY_SIZE
              [(4 << 8) | 0x3, 0, stream.id, 0x7].pack("NCNN", buffer: wbuf)
              @pending_body_size -= stream.body.bytesize
              stream.body.close
              stream.body = nil
              stream.close!
              @streams.delete(stream.id)
              @open_stream_count -= 1
            end
            break
          end

          chunk = stream.body.read(send_size)
          is_last = stream.body.empty?

          flags = is_last ? 0x01 : 0x00
          len_type = (chunk.bytesize << 8) | 0x0

          [len_type, flags, stream.id].pack("NCN", buffer: wbuf)
          wbuf << chunk

          stream.window_size -= send_size
          @connection_window -= send_size
          @pending_body_size -= send_size

          if is_last
            stream.body.close
            stream.body = nil
            stream.half_close_local!
            if stream.closed?
              @streams.delete(stream.id)
              @open_stream_count -= 1
            end
          end
        end
      end
    end

    # ── Read thread ───────────────────────────────────────────────────────

    def start_read_thread
      @reader = Thread.new {
        Thread.current.name = "reader - " + @name
        read_loop(@io)
      }
    end

    def read_loop io
      while true
        begin
          str = io.read(9)
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
            break
          when 0x8 then handle_window_update io, len, flags, stream_ident
          when 0x9 then handle_continuation io, len, flags, stream_ident
          else
            io.read(len) if len > 0 # skip unknown frame types (RFC 7540 4.1)
          end
        rescue Errors::StreamError => e
          io.read(e.remaining) if e.remaining > 0
          @write_queue << [:rst_stream, e.stream_id, e.error_code]
          @highest_stream_id = e.stream_id if e.stream_id > @highest_stream_id
        rescue Errors::ConnectionError => e
          io.read(e.remaining) if e.remaining > 0
          @write_queue << [:goaway, e.error_code]
          @write_queue << [:shutdown]
          break
        rescue IOError, Errno::ECONNRESET
          break
        end
      end
    ensure
      @write_queue << [:shutdown]
      @handler.on_close
    end

    # ── Frame writers (called only from write thread) ─────────────────────

    def send_goaway_frame io, error
      io.write [(8 << 8) | 0x7, 0, 0, @highest_stream_id, error].pack("NCNNN")
    end

    # ── Frame handlers (called only from read thread) ─────────────────────

    def handle_data io, len, flags, stream_id
      # DATA frames cannot have stream_id = 0
      if stream_id.zero?
        raise Errors::ProtocolError.new("Got DATA on stream 0", len)
      end

      begin
        stream = @streams.fetch(stream_id)
      rescue KeyError
        if stream_id <= @highest_stream_id
          raise Errors::StreamClosedError.new("DATA on closed stream", len)
        else
          raise Errors::ProtocolError.new("Invalid stream", len)
        end
      end

      raise Errors::ProtocolError.new("Invalid stream", len) if stream.idle?

      # Check stream state - DATA not allowed on closed or half_closed_remote
      if stream.closed?
        raise Errors::StreamClosedError.new("DATA on closed stream", len)
      elsif stream.half_closed_remote?
        raise Errors::StreamClosed.new("DATA on half-closed-remote stream", stream_id, len)
      end

      # Check for PADDED flag (bit 3)
      if flags[3].zero?
        # No padding, read all data
        data_len = len
        pad_length = 0
      else
        # Padded frame must have at least 1 byte for pad length
        raise Errors::ProtocolError.new("Padded DATA with zero length", 0) if len == 0
        pad_length = io.readbyte

        # Validate pad length
        if pad_length >= len
          # Pad length is invalid (too large)
          raise Errors::ProtocolError.new("Invalid pad length", len - 1)
        end

        # Read data (excluding pad length byte and padding)
        data_len = len - pad_length - 1
      end

      if data_len > 0
        chunk = io.read(data_len)
        stream.data_received += data_len
        @handler.on_data stream, chunk
        @write_queue << [:send_window_update, stream_id, data_len]
      end

      # Read and discard padding
      io.read(pad_length) if pad_length > 0

      # If END_STREAM flag is set, half-close remote
      if flags.odd? # Bottom bit is set
        # Validate content-length if specified
        if stream.content_length
          if stream.data_received != stream.content_length
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
      unless @streams.key?(stream_id)
        if @server_mode && stream_id.even?
          raise Errors::ProtocolError.new("Even stream ID from client", len)
        elsif !@server_mode && stream_id.odd?
          raise Errors::ProtocolError.new("Odd stream ID from server", len)
        end

        # Validate stream ID is increasing (unless stream already exists)
        if stream_id <= @highest_stream_id
          raise Errors::ProtocolError.new("Stream ID not increasing", len)
        end

        # Check MAX_CONCURRENT_STREAMS limit for new streams
        if @open_stream_count >= @local_max_concurrent_streams
          raise Errors::RefusedStream.new("Max concurrent streams exceeded", stream_id, len)
        end
      end

      # Check stream state
      @streams[stream_id]&.receiving_headers!(flags.odd?, len)

      # Check for PRIORITY flag (bit 5) - HEADERS can include priority data
      has_priority = flags[5].positive?
      priority_bytes = has_priority ? 5 : 0

      payload_start = 0
      payload_len = 0

      # Check for PADDED flag (bit 3)
      if flags[3].zero?
        # No padding
        if len > 0
          payload = io.read(len)
          payload_len = len
        else
          payload = "".b
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
        else
          payload = "".b
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
      if flags[2].positive?
        # Update highest stream ID seen
        if stream_id > @highest_stream_id
          @highest_stream_id = stream_id
        end

        stream = @streams[stream_id] ||= Stream.new(stream_id, nil, 0, self, :idle, @peer_settings.initial_window_size, false, nil, false)

        # Complete header block in this frame
        headers = @decoding_table.decode payload, payload_start, payload_len, max_list_size: MAX_HEADER_LIST_SIZE

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
        if flags.odd?
          # Validate content-length before closing
          if stream.content_length && stream.data_received
            if stream.data_received != stream.content_length
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
      if flags.even?
        # Peer PING: queue ACK for write thread
        @write_queue << [:ping_ack, payload]
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
      if flags.odd?
        raise Errors::FrameSizeError.new("SETTINGS ACK with payload", len) if len.positive?
        return
      end

      raise Errors::FrameSizeError.new("SETTINGS length not multiple of 6", len) if (len % 6) != 0

      read = 0
      s = "\0".b * 6
      parsed = {}

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

        parsed[ident] = value
        read += 6
      end

      @write_queue << [:settings, parsed]
      @write_queue << [:settings_ack]
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

      # Validate stream exists and is not idle (for stream-level updates)
      unless stream_ident.zero?
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
      end

      @write_queue << [:window_update, stream_ident, increment]
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
      stream.rst_received = true
      stream.close!
      @streams.delete(stream_id)
      @open_stream_count -= 1
      @write_queue << [:close_stream, stream]
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
      if flags[2].positive?
        # Complete header block
        @expecting_continuation = false
        complete_payload = @header_buffer
        saved_flags = @continuation_flags # Use flags from original HEADERS frame
        @header_buffer = nil
        @continuation_stream_id = nil
        @continuation_flags = nil

        stream = @streams[stream_id] ||= Stream.new(stream_id, nil, 0, self, :idle, @peer_settings.initial_window_size, false, nil, false)

        headers = @decoding_table.decode complete_payload, 0, complete_payload.bytesize, max_list_size: MAX_HEADER_LIST_SIZE

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
        if saved_flags.odd?
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
