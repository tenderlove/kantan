# frozen_string_literal: true

require "kantan/h3/frames"
require "kantan/h3/protocol"
require "kantan/h3/session"
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
    class PollSession < Session
      ALL_EVENTS = 0xFFFFFFFFFFFFFFFF

      def init
        @tracked = {}       # all SSL objects to poll
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

      private

      def track ssl
        @tracked[ssl] = [ssl, ALL_EVENTS]
      end

      def untrack ssl
        @tracked.delete(ssl)
      end

      def dispatch ssl, revents
        # Outgoing streams available — create server H3 streams
        if !@control_stream && revents & POLL_EVENT_OSU != 0
          open_streams
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

      def read_stream ssl, sid
        loop do
          data = ssl.read_nonblock(16384, exception: false)
          case data
          when :wait_readable then break
          when nil
            feed_fin(sid)
            untrack(ssl)
            break
          else
            feed_data(sid, data)
          end
        end
      rescue EOFError
        feed_fin(sid)
        untrack(ssl)
      rescue IOError, OpenSSL::SSL::SSLError
        feed_fin(sid)
        untrack(ssl)
      end
    end
  end
end
