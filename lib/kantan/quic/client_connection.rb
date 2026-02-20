# frozen_string_literal: true

require "socket"
require "kantan/quic/crypto"
require "kantan/quic/packet"
require "kantan/quic/frames"
require "kantan/quic/client_tls"
require "kantan/quic/stream"

module Kantan
  module QUIC
    class ClientConnection
      INITIAL     = :initial
      HANDSHAKE   = :handshake
      ESTABLISHED = :established
      CLOSED      = :closed

      def initialize(host, port)
        @socket = UDPSocket.new
        @socket.connect(host, port)

        @our_scid = OpenSSL::Random.random_bytes(8)
        @initial_dcid = OpenSSL::Random.random_bytes(8)
        @server_scid = nil

        @tls = ClientTLS.new(host)
        @tls.our_scid = @our_scid

        @state = INITIAL

        # Initial keys derived from the client-chosen DCID
        client_initial_secret, server_initial_secret = Crypto.derive_initial_secrets(@initial_dcid)
        @initial_keys = {
          client: Crypto.derive_keys(client_initial_secret),
          server: Crypto.derive_keys(server_initial_secret),
        }
        @handshake_keys = nil
        @app_keys = nil

        # Packet number counters
        @pn_initial = 0
        @pn_handshake = 0
        @pn_app = 0
        @send_mu = Mutex.new

        # Stream management
        @streams = {}
        @accept_queue = Thread::Queue.new
        @next_bidi_id = 0   # Client bidi: 0, 4, 8...
        @next_uni_id = 2    # Client uni: 2, 6, 10...
        @stream_mu = Mutex.new

        # CRYPTO frame reassembly
        @crypto_buf = { INITIAL => "".b, HANDSHAKE => "".b }
        @crypto_fragments = { INITIAL => [], HANDSHAKE => [] }

        @closed = false

        # Write notification
        @write_signal = Thread::Queue.new

        # Handshake completion signal
        @handshake_complete = Thread::Queue.new
      end

      # ── Public interface (same as server Connection) ────────────────────

      # Blocking connect. Returns when handshake is complete.
      def connect
        ch_msg = @tls.build_client_hello

        @send_mu.synchronize do
          frames = [Frames.build_crypto(0, ch_msg)]
          pkt = Packet.build_initial(
            dcid: @initial_dcid,
            scid: @our_scid,
            pn: @pn_initial,
            frames: frames,
            keys: @initial_keys[:client],
            pad: true,
          )
          @pn_initial += 1
          @socket.send(pkt, 0)
        end

        start_receive_thread
        start_write_thread

        @handshake_complete.pop
      end

      def accept_stream
        @accept_queue.pop
      end

      def open_stream(bidi:)
        @stream_mu.synchronize do
          if bidi
            id = @next_bidi_id
            @next_bidi_id += 4
          else
            id = @next_uni_id
            @next_uni_id += 4
          end
          stream = Stream.new(id, self)
          @streams[id] = stream
          stream
        end
      end

      def close
        return if @closed
        @closed = true
        @accept_queue.close
        @write_signal.close rescue nil
        @socket.close rescue nil
      end

      def notify_stream_data(stream)
        @write_signal << stream.id rescue nil
      end

      private

      # ── Receive thread ─────────────────────────────────────────────────

      def start_receive_thread
        Thread.new do
          until @closed
            data = @socket.recv(65535).b
            receive_datagram(data)
          end
        rescue IOError, Errno::EBADF
          # Socket closed
        rescue => e
          $stderr.puts "QUIC client recv: #{e.message}" if $DEBUG
        ensure
          @handshake_complete << nil rescue nil
        end
      end

      def receive_datagram(data)
        pos = 0
        while pos < data.bytesize
          first_byte = data.getbyte(pos)
          break if first_byte.nil?

          if first_byte & 0x80 != 0
            pos = process_long_header(data, pos)
          else
            process_short_header(data, pos)
            break
          end
        end
      rescue OpenSSL::Cipher::CipherError => e
        $stderr.puts "QUIC client: decryption failed: #{e.message}" if $DEBUG
      end

      def process_long_header(data, offset)
        info = Packet.parse_long_header(data, offset)
        packet_end = info[:header_end]

        case info[:type]
        when Packet::INITIAL
          process_initial(data, offset, info)
        when Packet::HANDSHAKE
          process_handshake(data, offset, info)
        end

        packet_end
      end

      def process_initial(data, offset, info)
        decrypted_info, plaintext = Packet.decrypt_long(data, @initial_keys[:server], offset)

        @server_scid ||= info[:scid]

        frames = Frames.parse(plaintext)
        frames.each do |frame|
          case frame[0]
          when :crypto
            _, foffset, fdata = frame
            append_crypto(INITIAL, foffset, fdata)
          end
        end

        # ACK the server's Initial (padded to 1200B per RFC 9000 §14.1,
        # which gives the server amplification credit to send more data)
        send_initial_ack(decrypted_info[:pn])

        return unless @state == INITIAL

        sh_data = @crypto_buf[INITIAL]
        return if sh_data.bytesize < 4

        msg_len = (sh_data.getbyte(1) << 16) | (sh_data.getbyte(2) << 8) | sh_data.getbyte(3)
        return if sh_data.bytesize < 4 + msg_len

        result = @tls.process_server_hello(sh_data)
        @handshake_keys = result[:handshake_keys]
        @state = HANDSHAKE
      end

      def process_handshake(data, offset, info)
        return unless @handshake_keys

        decrypted_info, plaintext = Packet.decrypt_long(data, @handshake_keys[:server], offset)

        frames = Frames.parse(plaintext)
        frames.each do |frame|
          case frame[0]
          when :crypto
            _, foffset, fdata = frame
            append_crypto(HANDSHAKE, foffset, fdata)
          end
        end

        return unless @state == HANDSHAKE

        hs_data = @crypto_buf[HANDSHAKE]
        return if hs_data.empty?

        # Check that all handshake messages (EE+Cert+CV+Finished) are complete
        pos = 0
        msg_count = 0
        while pos < hs_data.bytesize
          break if pos + 4 > hs_data.bytesize
          msg_len = (hs_data.getbyte(pos + 1) << 16) | (hs_data.getbyte(pos + 2) << 8) | hs_data.getbyte(pos + 3)
          break if pos + 4 + msg_len > hs_data.bytesize
          pos += 4 + msg_len
          msg_count += 1
        end
        if msg_count < 4
          # ACK to prompt server to send more data (amplification credit)
          send_handshake_ack(decrypted_info[:pn])
          return
        end

        result = @tls.process_handshake_crypto(hs_data)
        @app_keys = result[:app_keys]
        @state = ESTABLISHED

        # Send client Finished in a Handshake packet
        @send_mu.synchronize do
          hs_frames = [
            Frames.build_ack(decrypted_info[:pn]),
            Frames.build_crypto(0, result[:client_finished]),
          ]
          hs_pkt = Packet.build_handshake(
            dcid: @server_scid,
            scid: @our_scid,
            pn: @pn_handshake,
            frames: hs_frames,
            keys: @handshake_keys[:client],
          )
          @pn_handshake += 1
          @socket.send(hs_pkt, 0)
        end
      end

      def process_short_header(data, offset)
        return unless @app_keys

        _info, plaintext = Packet.decrypt_short(
          data.byteslice(offset, data.bytesize - offset),
          @app_keys[:server],
          @our_scid.bytesize
        )

        frames = Frames.parse(plaintext)
        frames.each do |frame|
          case frame[0]
          when :handshake_done
            @handshake_complete << true rescue nil
          when :stream
            _, stream_id, soffset, sdata, fin = frame
            deliver_stream_data(stream_id, soffset, sdata, fin)
          when :connection_close
            close
            @handshake_complete << nil rescue nil
            return
          end
        end

        send_ack_1rtt(_info[:pn])
      end

      # ── Stream delivery ────────────────────────────────────────────────

      def deliver_stream_data(stream_id, offset, data, fin)
        stream = @stream_mu.synchronize do
          @streams[stream_id] ||= begin
            s = Stream.new(stream_id, self)
            @accept_queue << s
            s
          end
        end
        stream.receive_data(data, offset, fin)
      end

      # ── CRYPTO reassembly ──────────────────────────────────────────────

      def append_crypto(level, offset, data)
        @crypto_fragments[level] << [offset, data]
        reassemble_crypto(level)
      end

      def reassemble_crypto(level)
        frags = @crypto_fragments[level]
        frags.sort_by! { |o, _| o }

        expected = @crypto_buf[level].bytesize

        frags.reject! do |frag_offset, frag_data|
          frag_end = frag_offset + frag_data.bytesize
          if frag_offset <= expected && frag_end > expected
            skip = expected - frag_offset
            @crypto_buf[level] << frag_data.byteslice(skip, frag_data.bytesize - skip)
            expected = frag_end
            true
          elsif frag_end <= expected
            true
          else
            false
          end
        end
      end

      # ── Write thread ───────────────────────────────────────────────────

      def start_write_thread
        @pending_flush = []
        Thread.new do
          while (msg = @write_signal.pop)
            if msg == :flush_pending
              until @pending_flush.empty?
                flush_stream(@pending_flush.shift)
              end
            elsif @app_keys
              until @pending_flush.empty?
                flush_stream(@pending_flush.shift)
              end
              flush_stream(msg)
            else
              @pending_flush << msg
            end
          end
        rescue IOError, ClosedQueueError
          # Connection closed
        end
      end

      # ── Sending ────────────────────────────────────────────────────────

      def send_initial_ack(server_pn)
        @send_mu.synchronize do
          frames = [Frames.build_ack(server_pn)]
          pkt = Packet.build_initial(
            dcid: @server_scid || @initial_dcid,
            scid: @our_scid,
            pn: @pn_initial,
            frames: frames,
            keys: @initial_keys[:client],
            pad: true,
          )
          @pn_initial += 1
          @socket.send(pkt, 0)
        end
      end

      def send_handshake_ack(server_pn)
        @send_mu.synchronize do
          return unless @handshake_keys
          frames = [Frames.build_ack(server_pn)]
          pkt = Packet.build_handshake(
            dcid: @server_scid,
            scid: @our_scid,
            pn: @pn_handshake,
            frames: frames,
            keys: @handshake_keys[:client],
          )
          @pn_handshake += 1
          @socket.send(pkt, 0)
        end
      end

      def send_ack_1rtt(pn)
        @send_mu.synchronize do
          frames = [Frames.build_ack(pn)]
          pkt = Packet.build_short(
            dcid: @server_scid,
            pn: @pn_app,
            frames: frames,
            keys: @app_keys[:client],
          )
          @pn_app += 1
          @socket.send(pkt, 0)
        end
      end

      def flush_stream(stream_id)
        return unless @app_keys

        stream = @stream_mu.synchronize { @streams[stream_id] }
        return unless stream

        data, offset, fin = stream.drain_send
        return if data.empty? && !fin

        @send_mu.synchronize do
          frames = []
          if data.bytesize > 0 || fin
            frames << Frames.build_stream(stream_id, offset, data, fin: fin)
            stream.mark_fin_sent! if fin
          end

          return if frames.empty?

          pkt = Packet.build_short(
            dcid: @server_scid,
            pn: @pn_app,
            frames: frames,
            keys: @app_keys[:client],
          )
          @pn_app += 1
          @socket.send(pkt, 0)
        end
      end
    end
  end
end
