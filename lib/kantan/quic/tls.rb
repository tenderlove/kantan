# frozen_string_literal: true

require "openssl"
require "kantan/quic/crypto"
require "kantan/h3/varint"

module Kantan
  module QUIC
    class TLS
      Varint = H3::Varint

      # TLS extension types
      EXT_SERVER_NAME            = 0x0000
      EXT_SUPPORTED_GROUPS       = 0x000a
      EXT_SIGNATURE_ALGORITHMS   = 0x000d
      EXT_ALPN                   = 0x0010
      EXT_SUPPORTED_VERSIONS     = 0x002b
      EXT_KEY_SHARE              = 0x0033
      EXT_QUIC_TRANSPORT_PARAMS  = 0x0039

      # X25519 group ID
      X25519 = 0x001d

      def initialize cert, key
        @cert = cert
        @key = key
        @server_ecdh = OpenSSL::PKey.generate_key("X25519")
      end

      # Parse a raw ClientHello message (without the record/handshake header).
      # +data+ is the body after type(1)+length(3).
      def parse_client_hello data
        pos = 0
        _legacy_version = data.byteslice(pos, 2).unpack1("n"); pos += 2
        random = data.byteslice(pos, 32); pos += 32
        session_id_len = data.getbyte(pos); pos += 1
        session_id = data.byteslice(pos, session_id_len); pos += session_id_len
        cipher_suites_len = data.byteslice(pos, 2).unpack1("n"); pos += 2
        _cipher_suites = data.byteslice(pos, cipher_suites_len); pos += cipher_suites_len
        comp_len = data.getbyte(pos); pos += 1
        pos += comp_len # compression methods

        extensions_len = data.byteslice(pos, 2).unpack1("n"); pos += 2
        ext_end = pos + extensions_len

        result = { random: random, session_id: session_id }

        while pos < ext_end
          ext_type = data.byteslice(pos, 2).unpack1("n"); pos += 2
          ext_len = data.byteslice(pos, 2).unpack1("n"); pos += 2
          ext_data = data.byteslice(pos, ext_len); pos += ext_len

          case ext_type
          when EXT_KEY_SHARE
            parse_key_share(ext_data, result)
          when EXT_ALPN
            parse_alpn(ext_data, result)
          when EXT_SUPPORTED_VERSIONS
            result[:supported_versions] = ext_data
          when EXT_QUIC_TRANSPORT_PARAMS
            result[:transport_params] = ext_data
          end
        end
        result
      end

      # Process the full ClientHello and produce all server messages + keys.
      # +ch_data+ is the raw CRYPTO frame data (the full handshake message including type+length).
      # Returns a hash:
      #   server_hello:      raw bytes for ServerHello CRYPTO frame (in Initial)
      #   handshake_crypto:  raw bytes for EE+Cert+CV+Finished (in Handshake CRYPTO)
      #   handshake_keys:    { server: {key,iv,hp}, client: {key,iv,hp} }
      #   app_keys:          { server: {key,iv,hp}, client: {key,iv,hp} }
      def process_client_hello ch_data
        # Parse the ClientHello body (skip type + 3-byte length)
        ch = parse_client_hello(ch_data.byteslice(4, ch_data.bytesize - 4))

        # X25519 key exchange
        peer_pub_raw = ch[:key_share_x25519]
        peer_pub = OpenSSL::PKey.new_raw_public_key("X25519", peer_pub_raw)
        shared_secret = @server_ecdh.derive(peer_pub)

        # Build ServerHello
        server_hello_body = build_server_hello(ch[:session_id])
        server_hello_msg = tls_handshake_message(0x02, server_hello_body) # type 2 = ServerHello

        # Key schedule: early → handshake → master
        zeros32 = "\x00".b * 32
        empty_hash = OpenSSL::Digest::SHA256.digest("")

        # 1. early_secret
        early_secret = Crypto.hkdf_extract(zeros32, zeros32)

        # 2. derived1
        derived1 = derive_secret(early_secret, "derived", empty_hash)

        # 3. handshake_secret
        handshake_secret = Crypto.hkdf_extract(derived1, shared_secret)

        # 4. transcript up to CH+SH
        transcript_ch_sh = OpenSSL::Digest::SHA256.digest(ch_data + server_hello_msg)

        # 5. handshake traffic secrets
        client_hs_secret = derive_secret(handshake_secret, "c hs traffic", transcript_ch_sh)
        server_hs_secret = derive_secret(handshake_secret, "s hs traffic", transcript_ch_sh)

        # 6. handshake keys
        handshake_keys = {
          server: Crypto.derive_keys(server_hs_secret),
          client: Crypto.derive_keys(client_hs_secret),
        }

        # Build Encrypted Extensions
        ee_body = build_encrypted_extensions(ch_data.byteslice(4, ch_data.bytesize - 4))
        ee_msg = tls_handshake_message(0x08, ee_body)

        # Build Certificate
        cert_body = build_certificate
        cert_msg = tls_handshake_message(0x0b, cert_body)

        # Build CertificateVerify
        transcript_for_cv = OpenSSL::Digest::SHA256.digest(ch_data + server_hello_msg + ee_msg + cert_msg)
        cv_body = build_certificate_verify(transcript_for_cv)
        cv_msg = tls_handshake_message(0x0f, cv_body)

        # Build Finished
        transcript_for_fin = OpenSSL::Digest::SHA256.digest(ch_data + server_hello_msg + ee_msg + cert_msg + cv_msg)
        finished_body = build_finished(server_hs_secret, transcript_for_fin)
        finished_msg = tls_handshake_message(0x14, finished_body)

        # 7. derived2 → master_secret → app keys
        derived2 = derive_secret(handshake_secret, "derived", empty_hash)
        master_secret = Crypto.hkdf_extract(derived2, zeros32)

        # transcript including server Finished
        transcript_sf = OpenSSL::Digest::SHA256.digest(
          ch_data + server_hello_msg + ee_msg + cert_msg + cv_msg + finished_msg
        )

        client_app_secret = derive_secret(master_secret, "c ap traffic", transcript_sf)
        server_app_secret = derive_secret(master_secret, "s ap traffic", transcript_sf)

        app_keys = {
          server: Crypto.derive_keys(server_app_secret),
          client: Crypto.derive_keys(client_app_secret),
        }

        # Store for verifying client Finished
        @client_hs_secret = client_hs_secret
        @expected_transcript = ch_data + server_hello_msg + ee_msg + cert_msg + cv_msg + finished_msg

        {
          server_hello: server_hello_msg,
          handshake_crypto: ee_msg + cert_msg + cv_msg + finished_msg,
          handshake_keys: handshake_keys,
          app_keys: app_keys,
        }
      end

      # Verify the client's Finished message.
      # +data+ is the raw Finished handshake message (type + length + verify_data).
      def verify_client_finished data
        verify_data = data.byteslice(4, data.bytesize - 4)
        finished_key = Crypto.hkdf_expand_label(@client_hs_secret, "finished", "", 32)
        transcript_hash = OpenSSL::Digest::SHA256.digest(@expected_transcript)
        expected = OpenSSL::HMAC.digest("SHA256", finished_key, transcript_hash)
        verify_data == expected
      end

      private

      def derive_secret secret, label, transcript_hash
        Crypto.hkdf_expand_label(secret, label, transcript_hash, 32)
      end

      def tls_handshake_message type, body
        msg = "".b
        msg << type
        msg << [body.bytesize].pack("N").byteslice(1, 3) # 3-byte length
        msg << body
      end

      def build_server_hello session_id
        body = "".b
        body << [0x0303].pack("n") # legacy version TLS 1.2
        body << OpenSSL::Random.random_bytes(32) # server random
        body << [session_id.bytesize].pack("C") << session_id # echo session_id
        body << [0x1301].pack("n") # cipher suite TLS_AES_128_GCM_SHA256
        body << "\x00" # compression method null

        # Extensions
        exts = "".b

        # supported_versions: TLS 1.3
        ext_sv = [0x0304].pack("n")
        exts << [EXT_SUPPORTED_VERSIONS].pack("n") << [ext_sv.bytesize].pack("n") << ext_sv

        # key_share: X25519
        pub_raw = @server_ecdh.raw_public_key
        ks_entry = [X25519].pack("n") + [pub_raw.bytesize].pack("n") + pub_raw
        exts << [EXT_KEY_SHARE].pack("n") << [ks_entry.bytesize].pack("n") << ks_entry

        body << [exts.bytesize].pack("n") << exts
        body
      end

      def build_encrypted_extensions ch_body
        exts = "".b

        # ALPN: h3
        alpn_proto = "\x02h3".b
        alpn_list = [alpn_proto.bytesize].pack("n") + alpn_proto
        exts << [EXT_ALPN].pack("n") << [alpn_list.bytesize].pack("n") << alpn_list

        # QUIC transport parameters
        tp = build_transport_params
        exts << [EXT_QUIC_TRANSPORT_PARAMS].pack("n") << [tp.bytesize].pack("n") << tp

        [exts.bytesize].pack("n") + exts
      end

      def build_transport_params
        buf = "".b
        # original_destination_connection_id (0x00)
        add_transport_param(buf, 0x00, @original_dcid || "".b)
        # max_idle_timeout (0x01) — 30 seconds in ms
        add_transport_param_varint(buf, 0x01, 30_000)
        # initial_max_data (0x04)
        add_transport_param_varint(buf, 0x04, 1_048_576)
        # initial_max_stream_data_bidi_local (0x05)
        add_transport_param_varint(buf, 0x05, 262_144)
        # initial_max_stream_data_bidi_remote (0x06)
        add_transport_param_varint(buf, 0x06, 262_144)
        # initial_max_stream_data_uni (0x07)
        add_transport_param_varint(buf, 0x07, 262_144)
        # initial_max_streams_bidi (0x08)
        add_transport_param_varint(buf, 0x08, 100)
        # initial_max_streams_uni (0x09)
        add_transport_param_varint(buf, 0x09, 100)
        # active_connection_id_limit (0x0e)
        add_transport_param_varint(buf, 0x0e, 2)
        # initial_source_connection_id (0x0f)
        add_transport_param(buf, 0x0f, @our_scid || "".b)
        buf
      end

      def add_transport_param buf, id, value
        Varint.encode(buf, id)
        Varint.encode(buf, value.bytesize)
        buf << value
      end

      def add_transport_param_varint buf, id, value
        val_buf = "".b
        Varint.encode(val_buf, value)
        add_transport_param(buf, id, val_buf)
      end

      def build_certificate
        body = "".b
        body << "\x00" # request_context length = 0
        der = @cert.to_der
        # cert_list: 3-byte total length
        entry = "".b
        entry << [der.bytesize].pack("N").byteslice(1, 3)
        entry << der
        entry << [0].pack("n") # 0 extensions
        body << [entry.bytesize].pack("N").byteslice(1, 3) << entry
        body
      end

      def build_certificate_verify transcript_hash
        # Signature input: 64 spaces + context string + 0x00 + transcript hash
        sig_input = (" " * 64).b + "TLS 1.3, server CertificateVerify\x00".b + transcript_hash

        sig = @key.sign("SHA256", sig_input)

        body = "".b
        body << [0x0403].pack("n") # ecdsa_secp256r1_sha256
        body << [sig.bytesize].pack("n") << sig
        body
      end

      def build_finished hs_secret, transcript_hash
        finished_key = Crypto.hkdf_expand_label(hs_secret, "finished", "", 32)
        OpenSSL::HMAC.digest("SHA256", finished_key, transcript_hash)
      end

      def parse_key_share data, result
        pos = 0
        total_len = data.byteslice(pos, 2).unpack1("n"); pos += 2
        end_pos = pos + total_len
        while pos < end_pos
          group = data.byteslice(pos, 2).unpack1("n"); pos += 2
          key_len = data.byteslice(pos, 2).unpack1("n"); pos += 2
          key_data = data.byteslice(pos, key_len); pos += key_len
          if group == X25519
            result[:key_share_x25519] = key_data
          end
        end
      end

      def parse_alpn data, result
        pos = 0
        list_len = data.byteslice(pos, 2).unpack1("n"); pos += 2
        end_pos = pos + list_len
        protocols = []
        while pos < end_pos
          proto_len = data.getbyte(pos); pos += 1
          protocols << data.byteslice(pos, proto_len); pos += proto_len
        end
        result[:alpn] = protocols
      end

      public

      # Set connection IDs for transport parameters
      attr_writer :original_dcid, :our_scid
    end
  end
end
