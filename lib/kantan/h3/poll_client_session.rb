# frozen_string_literal: true

require "kantan/h3/session"

module Kantan
  module H3
    # H3 client session driven by IO.select + wakeup pipe.
    # Uses quic: :client (non-threaded) — event loop thread handles reads.
    #
    # Usage mirrors H2::Session:
    #   session.connect
    #   sid = session.new_stream
    #   session.send_headers(sid, headers, has_body: true)
    #   session.send_body(sid, body)
    #   session.finish
    class PollClientSession < Session
      def connect
        @thread = Thread.new do
          event_loop
        rescue IOError, Errno::EBADF, OpenSSL::SSL::SSLError
          # connection closed
        ensure
          @wakeup_r.close rescue nil
          @wakeup_w.close rescue nil
          @handler.on_close
        end
      end

      def new_stream
        ssl = @conn.new_stream(0) # bidi
        sid = ssl.stream_id
        @ssl_map[sid] = ssl
        @streams[sid] = Stream.new(sid, nil, 0, self, :idle, nil, false, nil, false)
        @readers[sid] = init_bidi_reader(sid)
        @wakeup_w.write_nonblock(".") rescue nil
        sid
      end

      def send_headers stream_id, headers, has_body: false
        super
        @wakeup_w.write_nonblock(".") rescue nil
      end

      def send_body stream_id, body
        super
        @wakeup_w.write_nonblock(".") rescue nil
      end

      def request headers, body: nil
        stream_id = new_stream
        send_headers(stream_id, headers, has_body: !!body)
        send_body(stream_id, body) if body
        stream_id
      end

      def finish
        @closed = true
        @conn.sysclose rescue nil
        @wakeup_w.write_nonblock(".") rescue nil
        join
      end

      def join
        @thread&.join(5)
      end

      private

      def init
        super
        @wakeup_r, @wakeup_w = IO.pipe
      end

      def event_loop
        rfds = []
        wfds = []

        # Wait for handshake
        until @conn.init_finished?
          rfds.clear
          wfds.clear
          rfds << @io if @conn.net_read_desired?
          wfds << @io if @conn.net_write_desired?
          IO.select(rfds, wfds, nil, @conn.event_timeout)
          @conn.handle_events
        end

        open_streams

        until @closed
          rfds.clear
          wfds.clear

          rfds << @wakeup_r
          rfds << @io if @conn.net_read_desired?
          wfds << @io if @conn.net_write_desired?

          IO.select(rfds, wfds, nil, @conn.event_timeout)

          @wakeup_r.read_nonblock(256, exception: false)
          @conn.handle_events

          accept_streams
          read_streams

          @conn.handle_events
        end
      end
    end
  end
end
