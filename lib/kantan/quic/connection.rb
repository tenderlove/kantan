# frozen_string_literal: true

require "kantan/quic/crypto"
require "kantan/quic/packet"
require "kantan/quic/frames"
require "kantan/quic/tls"
require "kantan/quic/stream"

module Kantan
  module QUIC
    class Connection
      INITIAL     = :initial
      HANDSHAKE   = :handshake
      ESTABLISHED = :established
      CLOSED      = :closed

      def initialize(socket, client_addr, initial_dcid, cert, key)
        @socket = socket
        @client_addr = client_addr
        @initial_dcid = initial_dcid

        @tls = TLS.new(cert, key)

        @our_scid = OpenSSL::Random.random_bytes(8)
        @tls.original_dcid = initial_dcid
        @tls.our_scid = @our_scid

        @client_dcid = nil # learned from client's SCID
        @state = INITIAL

        # Key sets
        client_initial_secret, server_initial_secret = Crypto.derive_initial_secrets(initial_dcid)
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
        @next_bidi_id = 1   # Server bidi: 1, 5, 9...
        @next_uni_id = 3    # Server uni: 3, 7, 11...
        @stream_mu = Mutex.new

        # CRYPTO frame reassembly (handles out-of-order fragments)
        @crypto_buf = { INITIAL => "".b, HANDSHAKE => "".b }
        @crypto_fragments = { INITIAL => [], HANDSHAKE => [] }

        @closed = false

        # Write notification
        @write_signal = Thread::Queue.new
      end

      # ── MockQuic-compatible interface ──────────────────────────────────

      def accept_stream
        stream = @accept_queue.pop
        stream # nil means closed
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
      end

      # ── Datagram processing (called by server) ────────────────────────

      def receive_datagram(data)
        pos = 0
        while pos < data.bytesize
          first_byte = data.getbyte(pos)
          break if first_byte.nil?

          if first_byte & 0x80 != 0
            # Long header
            pos = process_long_header(data, pos)
          else
            # Short header (1-RTT)
            process_short_header(data, pos)
            break # short header packets extend to end of datagram
          end
        end
      rescue OpenSSL::Cipher::CipherError => e
        # Decryption failed — ignore packet
        $stderr.puts "QUIC: decryption failed: #{e.message}" if $DEBUG
      end

      # ── Stream data notification ──────────────────────────────────────

      def notify_stream_data(stream)
        @write_signal << stream.id rescue nil
      end

      # Start the write-flush thread. Processes stream data into packets.
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

      private

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
        decrypted_info, plaintext = Packet.decrypt_long(data, @initial_keys[:client], offset)

        @client_dcid = info[:scid]

        frames = Frames.parse(plaintext)
        frames.each do |frame|
          case frame[0]
          when :crypto
            _, foffset, fdata = frame
            append_crypto(INITIAL, foffset, fdata)
          end
        end

        return unless @state == INITIAL

        # Check if we have a complete ClientHello
        ch_data = @crypto_buf[INITIAL]
        if ch_data.bytesize < 4
          # Not enough data yet — ACK to prompt more
          send_initial_ack(decrypted_info[:pn])
          return
        end

        msg_len = (ch_data.getbyte(1) << 16) | (ch_data.getbyte(2) << 8) | ch_data.getbyte(3)
        if ch_data.bytesize < 4 + msg_len
          # ClientHello incomplete — ACK to prompt client to send more
          send_initial_ack(decrypted_info[:pn])
          return
        end

        result = @tls.process_client_hello(ch_data)
        @handshake_keys = result[:handshake_keys]
        @pending_app_keys = result[:app_keys]  # don't expose until HANDSHAKE_DONE sent

        # Send server Initial (ACK + ServerHello CRYPTO) + Handshake (EE+Cert+CV+Finished CRYPTO)
        send_server_hello(result, decrypted_info[:pn])

        @state = HANDSHAKE
      end

      def process_handshake(data, offset, info)
        return unless @handshake_keys

        decrypted_info, plaintext = Packet.decrypt_long(data, @handshake_keys[:client], offset)

        frames = Frames.parse(plaintext)
        frames.each do |frame|
          case frame[0]
          when :crypto
            _, foffset, fdata = frame
            append_crypto(HANDSHAKE, foffset, fdata)
          end
        end

        return unless @state == HANDSHAKE

        # Verify client Finished
        finished_data = @crypto_buf[HANDSHAKE]
        return if finished_data.empty?

        if @tls.verify_client_finished(finished_data)
          @state = ESTABLISHED

          # Expose app keys now and send HANDSHAKE_DONE as PN 0 (first 1-RTT packet)
          @app_keys = @pending_app_keys

          # ACK the client's Handshake + send HANDSHAKE_DONE (coalesced)
          send_handshake_completion(decrypted_info[:pn])

          # Kick the write thread to flush pending streams
          @write_signal << :flush_pending rescue nil
        end
      end

      def process_short_header(data, offset)
        return unless @app_keys

        _info, plaintext = Packet.decrypt_short(data.byteslice(offset, data.bytesize - offset), @app_keys[:client], @our_scid.bytesize)

        frames = Frames.parse(plaintext)
        frames.each do |frame|
          case frame[0]
          when :stream
            _, stream_id, soffset, sdata, fin = frame
            deliver_stream_data(stream_id, soffset, sdata, fin)
          when :connection_close
            close
            return
          end
        end

        # ACK every received packet
        send_ack_1rtt(_info[:pn])
      end

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

      # ── CRYPTO reassembly (handles out-of-order fragments) ────────────

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
            # This fragment extends our buffer
            skip = expected - frag_offset
            @crypto_buf[level] << frag_data.byteslice(skip, frag_data.bytesize - skip)
            expected = frag_end
            true
          elsif frag_end <= expected
            true # already have this data
          else
            false # gap — keep for later
          end
        end
      end

      # ── Sending ───────────────────────────────────────────────────────

      def send_initial_ack(client_pn)
        @send_mu.synchronize do
          frames = [Frames.build_ack(client_pn)]
          pkt = Packet.build_initial(
            dcid: @client_dcid,
            scid: @our_scid,
            pn: @pn_initial,
            frames: frames,
            keys: @initial_keys[:server],
          )
          @pn_initial += 1
          send_datagram(pkt)
        end
      end

      def send_server_hello(result, client_pn)
        @send_mu.synchronize do
          # Initial packet: ACK + CRYPTO(ServerHello)
          initial_frames = [
            Frames.build_ack(client_pn),
            Frames.build_crypto(0, result[:server_hello]),
          ]
          initial_pkt = Packet.build_initial(
            dcid: @client_dcid,
            scid: @our_scid,
            pn: @pn_initial,
            frames: initial_frames,
            keys: @initial_keys[:server],
          )
          @pn_initial += 1

          # Handshake packet: CRYPTO(EE+Cert+CV+Finished)
          hs_frames = [
            Frames.build_crypto(0, result[:handshake_crypto]),
          ]
          hs_pkt = Packet.build_handshake(
            dcid: @client_dcid,
            scid: @our_scid,
            pn: @pn_handshake,
            frames: hs_frames,
            keys: @handshake_keys[:server],
          )
          @pn_handshake += 1

          # Coalesce Initial + Handshake in one datagram
          # Pad to at least 1200 bytes (RFC 9000 §14.1)
          datagram = initial_pkt + hs_pkt
          if datagram.bytesize < 1200
            datagram << ("\x00" * (1200 - datagram.bytesize))
          end
          send_datagram(datagram)
        end
      end

      def send_handshake_completion(client_hs_pn)
        @send_mu.synchronize do
          # Handshake-level ACK for client's Handshake packet
          hs_frames = [Frames.build_ack(client_hs_pn)]
          hs_pkt = Packet.build_handshake(
            dcid: @client_dcid,
            scid: @our_scid,
            pn: @pn_handshake,
            frames: hs_frames,
            keys: @handshake_keys[:server],
          )
          @pn_handshake += 1

          # 1-RTT HANDSHAKE_DONE (PN 0 — first 1-RTT packet)
          done_frames = [Frames.build_handshake_done]
          done_pkt = Packet.build_short(
            dcid: @client_dcid,
            pn: @pn_app,
            frames: done_frames,
            keys: @app_keys[:server],
          )
          @pn_app += 1

          # Coalesce into one datagram
          send_datagram(hs_pkt + done_pkt)
        end
      end

      def send_ack_1rtt(pn)
        @send_mu.synchronize do
          frames = [Frames.build_ack(pn)]
          pkt = Packet.build_short(
            dcid: @client_dcid,
            pn: @pn_app,
            frames: frames,
            keys: @app_keys[:server],
          )
          @pn_app += 1
          send_datagram(pkt)
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
            dcid: @client_dcid,
            pn: @pn_app,
            frames: frames,
            keys: @app_keys[:server],
          )
          @pn_app += 1
          send_datagram(pkt)
        end
      end

      def send_datagram(data)
        @socket.send(data, 0, @client_addr[0], @client_addr[1])
      rescue IOError, Errno::EBADF
        # Socket closed
      end
    end
  end
end
