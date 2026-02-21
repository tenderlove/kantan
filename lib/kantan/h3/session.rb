# frozen_string_literal: true

require "kantan/h3/frames"
require "kantan/qpack"
require "kantan/stream"

module Kantan
  module H3
    class Session
      QPACK_TABLE_CAPACITY = 4096
      QPACK_BLOCKED        = 100

      def initialize conn, handler:
        @conn = conn
        @handler = handler

        @encoder = QPACK::Encoder.new(0)  # static table only until encoder stream ordering is reliable
        @decoder = QPACK::Decoder.new(QPACK_TABLE_CAPACITY, QPACK_BLOCKED)
        @encoder_mu = Mutex.new
        @decoder_mu = Mutex.new
        @decoder_cv = ConditionVariable.new

        @streams = {}        # stream_id => Kantan::Stream
        @quic_streams = {}   # stream_id => QuicStream

        @write_queue = Thread::Queue.new
        @threads = []

        @our_encoder_stream = nil
        @our_decoder_stream = nil
        @our_control_stream = nil

        @server_mode = nil
        @closed = false
      end

      # Server entry point: open control/QPACK streams, then accept.
      def receive
        @server_mode = true
        open_outgoing_streams
        start_write_thread
        accept_loop
      end

      # Client entry point: open control/QPACK streams, then accept.
      def connect
        @server_mode = false
        open_outgoing_streams
        start_write_thread
        accept_loop
      end

      # Initiate a client request.  Returns stream_id.
      def request headers, body: nil
        qs = @conn.open_stream(bidi: true)
        stream_id = qs.id
        @quic_streams[stream_id] = qs
        stream = Stream.new(stream_id, nil, 0, self, :idle, nil, false, nil, false)
        @streams[stream_id] = stream

        # Spawn a reader thread for the response on this bidi stream
        t = Thread.new(qs, stream) { |q, s| handle_response_stream(q, s) }
        @threads << t

        send_headers(stream_id, headers, has_body: !!body)
        send_body(stream_id, body) if body
        stream_id
      end

      def send_headers stream_id, headers, has_body: false
        @write_queue << [:headers, stream_id, headers, !has_body]
      end

      def send_body stream_id, body
        body = body.b if body.encoding != Encoding::BINARY
        @write_queue << [:data, stream_id, body, true]
      end

      def send_file stream_id, path
        @write_queue << [:sendfile, stream_id, path]
      end

      def finish
        @write_queue << [:shutdown]
        join
      end

      def join
        @writer&.join
        @accept_thread&.join
        @threads.each { _1.join rescue nil }
      end

      private

      # ── Startup ────────────────────────────────────────────────────────

      def open_outgoing_streams
        # Control stream
        @our_control_stream = @conn.open_stream(bidi: false)
        ctrl_buf = "".b
        Varint.encode(ctrl_buf, Frames::CONTROL)
        settings_payload = Frames.encode_settings({
          Frames::QPACK_MAX_TABLE_CAPACITY => QPACK_TABLE_CAPACITY,
          Frames::QPACK_BLOCKED_STREAMS => QPACK_BLOCKED,
        })
        Frames.write(ctrl_buf, Frames::SETTINGS, settings_payload)
        @our_control_stream.write(ctrl_buf)

        # QPACK encoder stream
        @our_encoder_stream = @conn.open_stream(bidi: false)
        enc_buf = "".b
        Varint.encode(enc_buf, Frames::QPACK_ENCODER)
        @our_encoder_stream.write(enc_buf)

        # QPACK decoder stream
        @our_decoder_stream = @conn.open_stream(bidi: false)
        dec_buf = "".b
        Varint.encode(dec_buf, Frames::QPACK_DECODER)
        @our_decoder_stream.write(dec_buf)
      end

      # ── Write thread ──────────────────────────────────────────────────

      def start_write_thread
        @writer = Thread.new { write_loop }
      end

      def write_loop
        while (cmd = @write_queue.pop)
          case cmd[0]
          when :headers
            _, stream_id, headers, end_stream = cmd
            qs = @quic_streams[stream_id]
            next unless qs

            enc_data, field_section = @encoder_mu.synchronize { @encoder.encode(stream_id, headers) }

            if enc_data.bytesize > 0
              @our_encoder_stream.write(enc_data)
            end

            buf = "".b
            Frames.write(buf, Frames::HEADERS, field_section)
            qs.write(buf)

            stream = @streams[stream_id]
            if stream
              stream.open! if stream.idle?
              if end_stream
                qs.close
                stream.half_close_local!
              end
            end

          when :data
            _, stream_id, data, end_stream = cmd
            qs = @quic_streams[stream_id]
            next unless qs

            buf = "".b
            Frames.write(buf, Frames::DATA, data)
            qs.write(buf)

            if end_stream
              qs.close
              stream = @streams[stream_id]
              stream&.half_close_local!
            end

          when :sendfile
            _, stream_id, path = cmd
            qs = @quic_streams[stream_id]
            next unless qs

            body = Body::File.new(path)
            buf = "".b
            until body.empty?
              chunk = body.read(16384)
              Frames.write(buf, Frames::DATA, chunk)
            end
            body.close
            qs.write(buf)
            qs.close
            stream = @streams[stream_id]
            stream&.half_close_local!

          when :shutdown
            break
          end
        end
      rescue IOError, Errno::EPIPE
        # Connection closed
      ensure
        @conn.close rescue nil
      end

      # ── Accept loop (read thread) ────────────────────────────────────

      def accept_loop
        @accept_thread = Thread.current
        while (qs = @conn.accept_stream)
          if qs.id & 0x02 == 0
            # Bidirectional stream → request
            t = Thread.new(qs) { |s| handle_request_stream(s) }
            @threads << t
          else
            # Unidirectional stream → control / QPACK
            t = Thread.new(qs) { |s| handle_uni_stream(s) }
            @threads << t
          end
        end
      rescue IOError, Errno::EPIPE
        # Connection closed
      ensure
        @closed = true
        @write_queue << [:shutdown]
        @decoder_cv.broadcast  # wake any threads blocked on QPACK
        @handler.on_close
      end

      # ── Request stream handling (server: peer-initiated bidi) ────────

      def handle_request_stream qs
        stream_id = qs.id
        @quic_streams[stream_id] = qs
        stream = Stream.new(stream_id, nil, 0, self, :open, nil, false, nil, false)
        @streams[stream_id] = stream

        read_stream_frames(qs, stream)
      rescue IOError, EOFError
        # Stream closed
      end

      # ── Response stream handling (client: self-initiated bidi) ───────

      def handle_response_stream qs, stream
        read_stream_frames(qs, stream)
      rescue IOError, EOFError
        # Stream closed
      end

      # ── Shared frame reading for bidi streams ────────────────────────

      def read_stream_frames qs, stream
        stream_id = stream.id

        while (frame = Frames.read(qs))
          type, payload = frame

          case type
          when Frames::HEADERS
            decoder_data, headers = decode_headers(stream_id, payload)
            if decoder_data.bytesize > 0
              @our_decoder_stream.write(decoder_data)
            end
            stream.headers = headers
            @handler.on_headers(stream)

          when Frames::DATA
            stream.data_received += payload.bytesize
            @handler.on_data(stream, payload)
          end
        end

        # QUIC FIN received — stream complete
        stream.half_close_remote!
        @handler.on_request(stream)
      end

      # Decode headers, waiting if the stream is blocked on QPACK dynamic table.
      def decode_headers stream_id, payload
        @decoder_mu.synchronize do
          @decoder.feed_header(stream_id, payload)
        end
      rescue QPACK::StreamBlocked
        # Wait for encoder stream data to unblock us
        @decoder_mu.synchronize do
          loop do
            raise IOError, "connection closed" if @closed
            begin
              return @decoder.resume_header(stream_id)
            rescue QPACK::DecompressionFailed
              @decoder_cv.wait(@decoder_mu)
            end
          end
        end
      end

      # ── Unidirectional stream handling ────────────────────────────────

      def handle_uni_stream qs
        stream_type = Varint.read(qs)

        case stream_type
        when Frames::CONTROL
          handle_control_stream(qs)
        when Frames::QPACK_ENCODER
          handle_qpack_encoder_stream(qs)
        when Frames::QPACK_DECODER
          handle_qpack_decoder_stream(qs)
        end
      rescue IOError, EOFError
        # Stream closed
      end

      def handle_control_stream qs
        frame = Frames.read(qs)
        return unless frame
        type, payload = frame
        return unless type == Frames::SETTINGS

        _settings = Frames.decode_settings(payload)

        while (frame = Frames.read(qs))
          # GOAWAY, etc. — first pass just ignores
        end
      end

      def handle_qpack_encoder_stream qs
        loop do
          data = qs.readpartial(4096)
          unblocked = @decoder_mu.synchronize { @decoder.feed_encoder(data) }
          @decoder_cv.broadcast if unblocked.any?
        end
      rescue EOFError
        # Stream closed
      end

      def handle_qpack_decoder_stream qs
        loop do
          data = qs.readpartial(4096)
          @encoder_mu.synchronize { @encoder.feed_decoder(data) }
        end
      rescue EOFError
        # Stream closed
      end
    end
  end
end
