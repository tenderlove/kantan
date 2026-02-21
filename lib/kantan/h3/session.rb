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

        @streams = {}        # stream_id => Kantan::Stream
        @quic_streams = {}   # stream_id => QuicStream
        @readers = {}        # stream_id => per-stream state hash

        @write_queue = Thread::Queue.new
        @events = Thread::Queue.new

        @our_encoder_stream = nil
        @our_decoder_stream = nil
        @our_control_stream = nil

        @server_mode = nil
        @closed = false
      end

      # Server entry point: open control/QPACK streams, then run event loop.
      def receive
        @server_mode = true
        open_outgoing_streams
        start_write_thread
        start_accept_fwd
        event_loop
      end

      # Client entry point: open control/QPACK streams, then run event loop.
      def connect
        @server_mode = false
        open_outgoing_streams
        start_write_thread
        start_accept_fwd
        event_loop
      end

      # Initiate a client request.  Returns stream_id.
      def request headers, body: nil
        qs = @conn.open_stream(bidi: true)
        stream_id = qs.id
        @quic_streams[stream_id] = qs
        stream = Stream.new(stream_id, nil, 0, self, :idle, nil, false, nil, false)
        @streams[stream_id] = stream

        register_stream(qs)

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
        @events << [:shutdown]
        join
      end

      def join
        @writer&.join
        @event_thread&.join if @event_thread != Thread.current
        @accept_fwd&.join
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

      # ── Write thread (unchanged) ────────────────────────────────────

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

      # ── Accept-forwarding thread ───────────────────────────────────

      def start_accept_fwd
        @accept_fwd = Thread.new do
          while (qs = @conn.accept_stream)
            @events << [:new_stream, qs]
          end
        rescue IOError, Errno::EPIPE
          # Connection closed
        ensure
          @events << [:shutdown]
        end
      end

      # ── Event loop ─────────────────────────────────────────────────

      def event_loop
        @event_thread = Thread.current

        while (event = @events.pop)
          case event[0]
          when :new_stream then register_stream(event[1])
          when :data       then process_data(event[1])
          when :shutdown   then break
          end
        end
      rescue IOError, Errno::EPIPE
        # Connection error
      ensure
        @closed = true
        @write_queue << [:shutdown]
        @handler.on_close
      end

      # ── Stream registration ────────────────────────────────────────

      def register_stream(qs)
        stream_id = qs.id
        @quic_streams[stream_id] = qs

        if stream_id & 0x02 == 0
          # Bidirectional stream
          unless @streams[stream_id]
            stream = Stream.new(stream_id, nil, 0, self, :open, nil, false, nil, false)
            @streams[stream_id] = stream
          end
          @readers[stream_id] = {
            type: :bidi,
            reader: Frames::FrameReader.new,
            stream: @streams[stream_id],
            fin: false,
            done: false,
            blocked: false,
          }
        else
          # Unidirectional stream — type not yet known
          @readers[stream_id] = {
            type: :unknown_uni,
            buf: "".b,
          }
        end

        qs.on_readable = -> { @events << [:data, stream_id] }
        @events << [:data, stream_id]  # drain any data already buffered
      end

      # ── Event dispatch ─────────────────────────────────────────────

      def process_data(stream_id)
        state = @readers[stream_id]
        return unless state
        return if state[:done]

        qs = @quic_streams[stream_id]
        result = qs.drain
        return unless result

        data, fin = result

        case state[:type]
        when :unknown_uni  then classify_uni(state, stream_id, data, fin)
        when :qpack_encoder then process_qpack_encoder(data)
        when :qpack_decoder then process_qpack_decoder(data)
        when :control       then process_control(state, data, fin)
        when :bidi          then process_bidi(state, data, fin)
        end
      end

      # ── Unidirectional stream classification ───────────────────────

      def classify_uni(state, stream_id, data, fin)
        state[:buf] << data

        result = Varint.safe_decode(state[:buf], 0)
        return unless result

        stream_type, pos = result
        remaining = pos < state[:buf].bytesize ? state[:buf].byteslice(pos, state[:buf].bytesize - pos) : "".b

        case stream_type
        when Frames::CONTROL
          state[:type] = :control
          state[:reader] = Frames::FrameReader.new
          state.delete(:buf)
          process_control(state, remaining, fin) if remaining.bytesize > 0 || fin
        when Frames::QPACK_ENCODER
          state[:type] = :qpack_encoder
          state.delete(:buf)
          process_qpack_encoder(remaining) if remaining.bytesize > 0
        when Frames::QPACK_DECODER
          state[:type] = :qpack_decoder
          state.delete(:buf)
          process_qpack_decoder(remaining) if remaining.bytesize > 0
        else
          # Unknown uni stream type — ignore
          state.delete(:buf)
        end
      end

      # ── QPACK encoder stream ───────────────────────────────────────

      def process_qpack_encoder(data)
        return if data.empty?
        unblocked = @decoder.feed_encoder(data)
        unblocked.each { |sid| retry_blocked_stream(sid) }
      end

      # ── QPACK decoder stream ───────────────────────────────────────

      def process_qpack_decoder(data)
        return if data.empty?
        @encoder_mu.synchronize { @encoder.feed_decoder(data) }
      end

      # ── Control stream ─────────────────────────────────────────────

      def process_control(state, data, fin)
        state[:reader].feed(data) if data.bytesize > 0
        while (frame = state[:reader].next_frame)
          type, payload = frame
          case type
          when Frames::SETTINGS
            _settings = Frames.decode_settings(payload)
          when Frames::GOAWAY
            # Handle GOAWAY
          end
        end
      end

      # ── Bidirectional stream ───────────────────────────────────────

      def process_bidi(state, data, fin)
        return if state[:done]

        state[:reader].feed(data) if data.bytesize > 0
        state[:fin] = true if fin

        drain_bidi_frames(state)
      end

      def drain_bidi_frames(state)
        return if state[:blocked] || state[:done]

        stream = state[:stream]

        while (frame = state[:reader].next_frame)
          type, payload = frame

          case type
          when Frames::HEADERS
            result = try_decode_headers(stream.id, payload)
            unless result
              state[:blocked] = true
              return
            end
            decoder_data, headers = result
            @our_decoder_stream.write(decoder_data) if decoder_data.bytesize > 0
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

      # ── QPACK header decoding ──────────────────────────────────────

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
          @our_decoder_stream.write(decoder_data) if decoder_data.bytesize > 0
          state[:stream].headers = headers
          state[:blocked] = false
          @handler.on_headers(state[:stream])
          drain_bidi_frames(state)
        rescue QPACK::StreamBlocked, QPACK::DecompressionFailed
          # Still blocked
        end
      end
    end
  end
end
