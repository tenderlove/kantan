# frozen_string_literal: true

require "openssl"
require "kantan/h3/frames"
require "kantan/qpack"
require "kantan/stream"

module Kantan
  module H3
    # Single-threaded H3 session driven by SSL_poll.
    # Translates the OpenSSL demo pattern:
    #   io.wait_readable(event_timeout) → handle_events → SSL_poll(NO_HANDLE_EVENTS, 0)
    #
    # No threads — all I/O happens in #run via non-blocking SSL calls.
    # Safe for use with OSSL_QUIC_server_method and Ractors.
    class PollSession
      include OpenSSL::SSL

      ALL_EVENTS = 0xFFFFFFFFFFFFFFFF

      def initialize(conn_ssl, io:, handler:)
        @conn = conn_ssl
        @conn.default_stream_mode = :none
        @conn.incoming_stream_policy = INCOMING_STREAM_POLICY_ACCEPT
        @io = io
        @handler = handler

        @encoder = QPACK::Encoder.new(0)
        @decoder = QPACK::Decoder.new(4096, 100)

        @streams = {}       # stream_id => Kantan::Stream
        @ssl_map = {}       # ssl object_id => SSL stream object
        @readers = {}       # stream_id => reader state hash
        @tracked = []       # all SSL objects to poll

        @encoder_stream = nil
        @decoder_stream = nil
        @server_streams_opened = false
        @closed = false
      end

      def run
        track(@conn)

        until @closed
          # 1. Wait for network activity, using OpenSSL's desired timeout
          @io.wait_readable(@conn.event_timeout)

          # 2. Process QUIC events for this connection
          @conn.handle_events

          # 3. Poll all tracked objects (non-blocking, no event processing)
          poll_items = @tracked.map { |ssl| [ssl, ALL_EVENTS] }
          ready = SSLSocket.poll(poll_items, 0, POLL_FLAG_NO_HANDLE_EVENTS)
          next if ready.empty?

          # 4. Dispatch events
          ready.each { |ssl, revents| dispatch(ssl, revents) }
        end
      rescue IOError, OpenSSL::SSL::SSLError
        # connection closed
      ensure
        @handler.on_close
      end

      def send_headers(stream_id, headers, has_body: false)
        ssl = @ssl_map[stream_id] or return

        _enc_data, field_section = @encoder.encode(stream_id, headers)

        buf = "".b
        Frames.write(buf, Frames::HEADERS, field_section)
        ssl.syswrite(buf)

        stream = @streams[stream_id]
        stream&.open! if stream&.idle?
        unless has_body
          ssl.stream_conclude rescue nil
          stream&.half_close_local!
        end
      rescue OpenSSL::SSL::SSLError, IOError
        # write failed
      end

      def send_body(stream_id, body)
        ssl = @ssl_map[stream_id] or return

        body = body.b if body.encoding != Encoding::BINARY
        buf = "".b
        Frames.write(buf, Frames::DATA, body)
        ssl.syswrite(buf)

        ssl.stream_conclude rescue nil
        @streams[stream_id]&.half_close_local!
      rescue OpenSSL::SSL::SSLError, IOError
        # write failed
      end

      private

      def track(ssl)
        @tracked << ssl
      end

      def untrack(ssl)
        @tracked.delete_if { |s| s.equal?(ssl) }
      end

      def dispatch(ssl, revents)
        # Incoming connection (listener events — not used here,
        # connection is already accepted before PollSession)

        # Outgoing streams available — create server H3 streams
        if !@server_streams_opened && revents & POLL_EVENT_OSU != 0
          open_server_streams
          @server_streams_opened = true
        end

        # Incoming streams
        if revents & (POLL_EVENT_ISB | POLL_EVENT_ISU) != 0
          accept_and_read_streams(ssl)
        end

        # Readable stream
        if revents & POLL_EVENT_R != 0
          sid = ssl.stream_id
          read_stream(ssl, sid) if @readers[sid]
        end

        # Read exception — stream closed by peer
        if revents & POLL_EVENT_ER != 0
          sid = ssl.stream_id
          feed_fin(sid)
        end

        # Connection drained or failure
        if revents & (POLL_EVENT_ECD | POLL_EVENT_F) != 0
          @closed = true
        end

        # Connection exception (peer closing)
        if revents & POLL_EVENT_EC != 0
          @closed = true
        end
      end

      def accept_and_read_streams(ssl)
        while (stream_ssl = @conn.accept_stream(0))
          sid = stream_ssl.stream_id
          @ssl_map[sid] = stream_ssl
          track(stream_ssl)

          if sid & 0x02 == 0
            # Bidi — request stream
            @streams[sid] = Stream.new(sid, nil, 0, self, :open, nil, false, nil, false)
            @readers[sid] = { type: :bidi, reader: Frames::FrameReader.new, fin: false, done: false }
          else
            # Uni — type not yet known
            @readers[sid] = { type: :unknown_uni, buf: "".b }
          end

          # Read immediately (like the demo's quic_server_read after accept)
          read_stream(stream_ssl, sid)
        end
      end

      def open_server_streams
        ctrl = @conn.new_stream(STREAM_FLAG_UNI)
        buf = "".b
        Varint.encode(buf, Frames::CONTROL)
        Frames.write(buf, Frames::SETTINGS, Frames.encode_settings({
          Frames::QPACK_MAX_TABLE_CAPACITY => 4096,
          Frames::QPACK_BLOCKED_STREAMS => 100,
        }))
        ctrl.syswrite(buf)

        @encoder_stream = @conn.new_stream(STREAM_FLAG_UNI)
        @encoder_stream.syswrite([Frames::QPACK_ENCODER].pack("C"))

        @decoder_stream = @conn.new_stream(STREAM_FLAG_UNI)
        @decoder_stream.syswrite([Frames::QPACK_DECODER].pack("C"))
      end

      def read_stream(ssl, sid)
        data = ssl.sysread(16384)
        feed_data(sid, data)
      rescue EOFError
        feed_fin(sid)
        untrack(ssl)
      rescue IOError, OpenSSL::SSL::SSLError
        feed_fin(sid)
        untrack(ssl)
      end

      def feed_data(sid, data)
        state = @readers[sid] or return

        case state[:type]
        when :unknown_uni
          state[:buf] << data
          classify_uni(sid, state)
        when :qpack_encoder
          @decoder.feed_encoder(data)
        when :qpack_decoder
          # ignore
        when :control
          state[:reader].feed(data)
          process_control(state)
        when :bidi
          state[:reader].feed(data)
          process_bidi(sid, state)
        end
      end

      def feed_fin(sid)
        state = @readers[sid] or return

        if state[:type] == :bidi && !state[:done]
          state[:fin] = true
          process_bidi(sid, state)
        end
      end

      def classify_uni(sid, state)
        result = Varint.safe_decode(state[:buf], 0)
        return unless result

        stream_type, pos = result
        remaining = state[:buf].byteslice(pos..) || "".b

        case stream_type
        when Frames::CONTROL
          state[:type] = :control
          state[:reader] = Frames::FrameReader.new
          state.delete(:buf)
          if remaining.bytesize > 0
            state[:reader].feed(remaining)
            process_control(state)
          end
        when Frames::QPACK_ENCODER
          state[:type] = :qpack_encoder
          state.delete(:buf)
          @decoder.feed_encoder(remaining) if remaining.bytesize > 0
        when Frames::QPACK_DECODER
          state[:type] = :qpack_decoder
          state.delete(:buf)
        else
          state[:type] = :ignored
          state.delete(:buf)
        end
      end

      def process_control(state)
        while (frame = state[:reader].next_frame)
          type, payload = frame
          case type
          when Frames::SETTINGS
            Frames.decode_settings(payload)
          when Frames::GOAWAY
            @closed = true
          end
        end
      end

      def process_bidi(sid, state)
        return if state[:done]

        stream = @streams[sid]

        while (frame = state[:reader].next_frame)
          type, payload = frame
          case type
          when Frames::HEADERS
            result = @decoder.feed_header(sid, payload)
            if result
              decoder_data, headers = result
              @decoder_stream.syswrite(decoder_data) if decoder_data.bytesize > 0
              stream.headers = headers
              @handler.on_headers(stream)
            end
          when Frames::DATA
            stream.data_received += payload.bytesize
            @handler.on_data(stream, payload)
          end
        end

        if state[:fin] && !state[:done]
          state[:done] = true
          stream.half_close_remote!
          @handler.on_request(stream)
        end
      end
    end
  end
end
