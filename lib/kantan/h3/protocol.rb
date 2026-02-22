# frozen_string_literal: true

require "kantan/h3/frames"
require "kantan/qpack"

module Kantan
  module H3
    # Shared H3 protocol logic for frame/stream processing.
    # Including classes must provide:
    #   @readers  — Hash of stream_id => reader state
    #   @streams  — Hash of stream_id => Kantan::Stream
    #   @decoder  — QPACK::Decoder
    #   @encoder  — QPACK::Encoder
    #   @handler  — handler responding to on_headers, on_data, on_request
    #   @closed   — boolean
    #   #write_decoder_data(data) — write to QPACK decoder stream
    module Protocol
      def feed_data(sid, data)
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

      def feed_fin(sid)
        state = @readers[sid] or return

        if state[:type] == :bidi && !state[:done]
          state[:fin] = true
          process_bidi(sid, state)
        end
      end

      def init_bidi_reader(sid)
        { type: :bidi, reader: Frames::FrameReader.new, fin: false, done: false, blocked: false }
      end

      def init_uni_reader
        { type: :unknown_uni, buf: "".b }
      end

      private

      def classify_uni(sid, state)
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

      def process_qpack_encoder(data)
        return if data.empty?
        unblocked = @decoder.feed_encoder(data)
        unblocked.each { |sid| retry_blocked_stream(sid) }
      end

      def process_qpack_decoder(data)
        return if data.empty?
        @encoder.feed_decoder(data)
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

      def try_decode_headers(stream_id, payload)
        @decoder.feed_header(stream_id, payload)
      rescue QPACK::StreamBlocked
        nil
      end

      def retry_blocked_stream(stream_id)
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
    end
  end
end
