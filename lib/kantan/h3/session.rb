# frozen_string_literal: true

require "openssl"
require "kantan/h3/frames"
require "kantan/qpack"
require "kantan/stream"

module Kantan
  module H3
    class Session
      include OpenSSL::SSL

      QPACK_TABLE_CAPACITY = 4096
      QPACK_BLOCKED        = 100

      def initialize conn_ssl, io:, handler:
        @conn = conn_ssl
        @conn.incoming_stream_policy = INCOMING_STREAM_POLICY_ACCEPT
        @io = io
        @handler = handler

        @encoder = QPACK::Encoder.new(0)
        @decoder = QPACK::Decoder.new(QPACK_TABLE_CAPACITY, QPACK_BLOCKED)

        @streams = {}       # stream_id => Kantan::Stream
        @ssl_map = {}       # ssl object_id => SSL stream object
        @readers = {}       # stream_id => reader state hash
        @closed = false
        @control_stream = nil
        @encoder_stream = nil
        @decoder_stream = nil

        init
      end

      def send_headers stream_id, headers, has_body: false
        ssl = @ssl_map[stream_id] or return

        _enc_data, field_section = @encoder.encode(stream_id, headers)

        buf = "".b
        Frames.write(buf, Frames::HEADERS, field_section)
        ssl.syswrite(buf)

        stream = @streams.fetch(stream_id)
        stream.open! if stream.idle?
        unless has_body
          ssl.stream_conclude rescue nil
          stream.half_close_local!
        end
      rescue OpenSSL::SSL::SSLError, IOError
        # write failed
      end

      def send_body stream_id, body
        ssl = @ssl_map[stream_id] or return

        body = body.b if body.encoding != Encoding::BINARY
        buf = "".b
        Frames.write(buf, Frames::DATA, body)
        ssl.syswrite(buf)

        ssl.stream_conclude rescue nil
        @streams.fetch(stream_id).half_close_local!
      rescue OpenSSL::SSL::SSLError, IOError
        # write failed
      end

      private

      def init
      end

      def open_streams
        @control_stream = @conn.new_stream(STREAM_FLAG_UNI)
        buf = "".b
        Varint.encode(buf, Frames::CONTROL)
        Frames.write(buf, Frames::SETTINGS, Frames.encode_settings({
          Frames::QPACK_MAX_TABLE_CAPACITY => QPACK_TABLE_CAPACITY,
          Frames::QPACK_BLOCKED_STREAMS => QPACK_BLOCKED,
        }))
        @control_stream.syswrite(buf)

        @encoder_stream = @conn.new_stream(STREAM_FLAG_UNI)
        @encoder_stream.syswrite(Frames::QPACK_ENCODER.chr)

        @decoder_stream = @conn.new_stream(STREAM_FLAG_UNI)
        @decoder_stream.syswrite(Frames::QPACK_DECODER.chr)
      end

      def register_stream ssl
        sid = ssl.stream_id
        @ssl_map[sid] = ssl
        if sid & 0x02 == 0
          @streams[sid] = Stream.new(sid, nil, 0, self, :open, nil, false, nil, false)
          @readers[sid] = init_bidi_reader(sid)
        else
          @readers[sid] = init_uni_reader
        end
        sid
      end

      def read_stream ssl, sid
        loop do
          data = ssl.read_nonblock(16384, exception: false)
          case data
          when :wait_readable then break
          when nil
            close_stream(ssl, sid)
            break
          else
            feed_data(sid, data)
          end
        end
      rescue EOFError
        close_stream(ssl, sid)
      rescue IOError, OpenSSL::SSL::SSLError
        close_stream(ssl, sid)
      end

      def close_stream ssl, sid
        feed_fin(sid)
        @ssl_map.delete(sid)
      end

      # -- H3 protocol: frame/stream processing --

      def feed_data sid, data
        state = @readers[sid] or return

        case state[:type]
        when :unknown_uni
          state[:buf] << data
          classify_uni(sid, state)
        when :qpack_encoder
          process_qpack_encoder(data)
        when :qpack_decoder
          process_qpack_decoder(data)
        when :control
          state[:reader].feed(data) if data.bytesize > 0
          process_control(state)
        when :bidi
          state[:reader].feed(data) if data.bytesize > 0
          process_bidi(sid, state)
        end
      end

      def feed_fin sid
        state = @readers[sid] or return

        if state[:type] == :bidi && !state[:done]
          state[:fin] = true
          process_bidi(sid, state)
        end
      end

      def init_bidi_reader sid
        { type: :bidi, reader: Frames::FrameReader.new, fin: false, done: false, blocked: false }
      end

      def init_uni_reader
        { type: :unknown_uni, buf: "".b }
      end

      def classify_uni sid, state
        result = Varint.safe_decode(state[:buf], 0)
        return unless result

        stream_type, pos = result
        remaining = state[:buf].byteslice(pos..) || "".b
        state.delete(:buf)

        case stream_type
        when Frames::CONTROL
          state[:type] = :control
          state[:reader] = Frames::FrameReader.new
          feed_data(sid, remaining) if remaining.bytesize > 0
        when Frames::QPACK_ENCODER
          state[:type] = :qpack_encoder
          feed_data(sid, remaining) if remaining.bytesize > 0
        when Frames::QPACK_DECODER
          state[:type] = :qpack_decoder
        else
          state[:type] = :ignored
        end
      end

      def process_qpack_encoder data
        return if data.empty?
        unblocked = @decoder.feed_encoder(data)
        unblocked.each { |sid| retry_blocked_stream(sid) }
      end

      def process_qpack_decoder data
        return if data.empty?
        @encoder.feed_decoder(data)
      end

      def process_control state
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

      def process_bidi sid, state
        return if state[:done] || state[:blocked]

        stream = @streams[sid]

        while (frame = state[:reader].next_frame)
          type, payload = frame

          case type
          when Frames::HEADERS
            result = try_decode_headers(sid, payload)
            unless result
              state[:blocked] = true
              return
            end
            decoder_data, headers = result
            write_decoder_data(decoder_data) if decoder_data.bytesize > 0
            stream.headers = headers
            @handler.on_headers(stream)

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

      def try_decode_headers stream_id, payload
        @decoder.feed_header(stream_id, payload)
      rescue QPACK::StreamBlocked
        nil
      end

      def retry_blocked_stream stream_id
        state = @readers[stream_id]
        return unless state && state[:blocked]

        begin
          decoder_data, headers = @decoder.resume_header(stream_id)
          write_decoder_data(decoder_data) if decoder_data.bytesize > 0
          @streams[stream_id].headers = headers
          state[:blocked] = false
          @handler.on_headers(@streams[stream_id])
          process_bidi(stream_id, state)
        rescue QPACK::StreamBlocked, QPACK::DecompressionFailed
          # Still blocked
        end
      end

      def write_decoder_data data
        @decoder_stream&.syswrite(data)
      end
    end
  end
end
