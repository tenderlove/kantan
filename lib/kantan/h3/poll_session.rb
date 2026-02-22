# frozen_string_literal: true

require "openssl"
require "kantan/h3/frames"
require "kantan/h3/protocol"
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
      include Protocol

      ALL_EVENTS = 0xFFFFFFFFFFFFFFFF

      def initialize conn_ssl, io:, handler:
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
        @tracked = {}       # all SSL objects to poll

        @encoder_stream = nil
        @decoder_stream = nil
        @server_streams_opened = false
        @closed = false
      end

      def run
        track(@conn)

        until @closed
          # 1. Wait for network activity (read or write), using OpenSSL's desired timeout
          rfds = [@io]
          wfds = @conn.net_write_desired? ? [@io] : []
          timeout = @conn.event_timeout
          timeout = [timeout, 0.01].min if timeout  # ensure frequent ticking
          IO.select(rfds, wfds, nil, timeout)

          # 2. Process QUIC events for this connection
          @conn.handle_events

          # 3. Poll all tracked objects (non-blocking, no event processing)
          poll_items = @tracked.values
          ready = SSLSocket.poll(poll_items, 0, POLL_FLAG_NO_HANDLE_EVENTS)

          # 4. Dispatch events (may write response data)
          ready.each { |ssl, revents| dispatch(ssl, revents) }

          # 5. Flush any writes from dispatch
          @conn.handle_events
        end
      rescue IOError, Errno::EBADF, OpenSSL::SSL::SSLError
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

      def track ssl
        @tracked[ssl] = [ssl, ALL_EVENTS]
      end

      def untrack ssl
        @tracked.delete(ssl)
      end

      def dispatch ssl, revents
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

      def accept_and_read_streams ssl
        while stream_ssl = @conn.accept_stream(0)
          sid = stream_ssl.stream_id
          @ssl_map[sid] = stream_ssl
          track(stream_ssl)

          if sid & 0x02 == 0
            # Bidi — request stream
            @streams[sid] = Stream.new(sid, nil, 0, self, :open, nil, false, nil, false)
            @readers[sid] = init_bidi_reader(sid)
          else
            # Uni — type not yet known
            @readers[sid] = init_uni_reader
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
        @encoder_stream.syswrite(Frames::QPACK_ENCODER.chr)

        @decoder_stream = @conn.new_stream(STREAM_FLAG_UNI)
        @decoder_stream.syswrite(Frames::QPACK_DECODER.chr)
      end

      def read_stream ssl, sid
        data = ssl.sysread(16384)
        feed_data(sid, data)
      rescue EOFError
        feed_fin(sid)
        untrack(ssl)
      rescue IOError, OpenSSL::SSL::SSLError
        feed_fin(sid)
        untrack(ssl)
      end

      # ── Protocol adapter ───────────────────────────────────────────

      def write_decoder_data data
        @decoder_stream.syswrite(data)
      end
    end
  end
end
