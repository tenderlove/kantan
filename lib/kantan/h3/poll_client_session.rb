# frozen_string_literal: true

require "kantan/h3/session"
require "kantan/h3/frames"
require "kantan/h3/protocol"
require "kantan/qpack"
require "kantan/stream"

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
      def init
        @wakeup_r, @wakeup_w = IO.pipe
      end

      def connect
        open_streams
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

      def request(headers, body: nil)
        stream_id = new_stream
        send_headers(stream_id, headers, has_body: !!body)
        send_body(stream_id, body) if body
        stream_id
      end

      def finish
        @closed = true
        @wakeup_w.write_nonblock(".") rescue nil
        join
      end

      def join
        @thread&.join(5)
      end

      private

      def event_loop
        loop do
          break if @closed

          rfds = [@wakeup_r, @io]
          wfds = @conn.net_write_desired? ? [@io] : []

          IO.select(rfds, wfds, nil, @conn.event_timeout)

          @wakeup_r.read_nonblock(256) rescue nil
          @conn.handle_events

          accept_streams
          read_streams
        end
      end

      def accept_streams
        while (ssl = @conn.accept_stream(STREAM_FLAG_NO_BLOCK))
          sid = ssl.stream_id
          @ssl_map[sid] = ssl

          if sid & 0x02 == 0
            @streams[sid] = Stream.new(sid, nil, 0, self, :open, nil, false, nil, false)
            @readers[sid] = init_bidi_reader(sid)
          else
            @readers[sid] = init_uni_reader
          end
        end
      rescue OpenSSL::SSL::SSLError
        # no more streams
      end

      def read_streams
        finished = []
        @ssl_map.each do |sid, ssl|
          loop do
            data = ssl.read_nonblock(16384, exception: false)
            case data
            when :wait_readable then break
            when nil
              feed_fin(sid)
              finished << sid
              break
            else
              feed_data(sid, data)
            end
          end
        rescue EOFError
          feed_fin(sid)
          finished << sid
        rescue IOError, OpenSSL::SSL::SSLError
          feed_fin(sid)
          finished << sid
        end
        finished.each { |sid| @ssl_map.delete(sid) }
      end
    end
  end
end
