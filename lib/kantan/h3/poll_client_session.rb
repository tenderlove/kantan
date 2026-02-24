# frozen_string_literal: true

require "openssl"
require "kantan/h3/frames"
require "kantan/h3/protocol"
require "kantan/qpack"
require "kantan/stream"

module Kantan
  module H3
    # Single-threaded H3 client session driven by IO.select + wakeup pipe.
    # Uses quic: :client (non-threaded) — all SSL ops happen in the event loop.
    #
    # App threads call #request which pushes to a queue and wakes the event loop.
    # The event loop creates streams, writes frames, and reads responses.
    class PollClientSession
      include OpenSSL::SSL
      include Protocol

      def initialize(conn_ssl, io:, handler:)
        @conn = conn_ssl
        @io = io
        @handler = handler

        @encoder = QPACK::Encoder.new(0)
        @decoder = QPACK::Decoder.new(4096, 100)

        @streams = {}       # stream_id => Kantan::Stream
        @ssl_map = {}       # stream_id => SSL stream object
        @readers = {}       # stream_id => reader state hash

        @request_queue = Queue.new
        @wakeup_r, @wakeup_w = IO.pipe
        @closed = false
      end

      def connect
        open_client_streams
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

      def request(headers, body: nil)
        result = Queue.new
        @request_queue << [:request, headers, body, result]
        @wakeup_w.write_nonblock(".") rescue nil
        result.pop
      end

      def finish
        @request_queue << [:shutdown]
        @wakeup_w.write_nonblock(".") rescue nil
        join
      end

      def join
        @thread&.join(5)
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

      def open_client_streams
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

      def event_loop
        loop do
          drain_request_queue
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

      def drain_request_queue
        loop do
          cmd = @request_queue.pop(true) # non-blocking
          case cmd[0]
          when :request
            _, headers, body, result = cmd
            ssl = @conn.new_stream(0) # bidi
            sid = ssl.stream_id
            @ssl_map[sid] = ssl

            stream = Stream.new(sid, nil, 0, self, :idle, nil, false, nil, false)
            @streams[sid] = stream
            @readers[sid] = init_bidi_reader(sid)

            send_headers(sid, headers, has_body: !!body)
            send_body(sid, body) if body

            result << sid
          when :shutdown
            @closed = true
          end
        end
      rescue ThreadError
        # queue empty
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

      def write_decoder_data(data)
        @decoder_stream.syswrite(data)
      end
    end
  end
end
