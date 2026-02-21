# frozen_string_literal: true

require "openssl"
require "kantan/quic/crypto"
require "kantan/h3/varint"

module Kantan
  module QUIC
    class ClientTLS
      Varint = H3::Varint

      # TLS extension types
      EXT_SERVER_NAME            = 0x0000
      EXT_SUPPORTED_GROUPS       = 0x000a
      EXT_SIGNATURE_ALGORITHMS   = 0x000d
      EXT_ALPN                   = 0x0010
      EXT_SUPPORTED_VERSIONS     = 0x002b
      EXT_KEY_SHARE              = 0x0033
      EXT_QUIC_TRANSPORT_PARAMS  = 0x0039

      X25519 = 0x001d

      def initialize host = nil
        @host = host
        @ecdh = OpenSSL::PKey.generate_key("X25519")
      end

      attr_writer :our_scid

      # Build a ClientHello handshake message. Returns raw bytes (type+length+body).
      def build_client_hello
        body = "".b
        body << [0x0303].pack("n")                     # legacy version TLS 1.2
        body << OpenSSL::Random.random_bytes(32)        # client random
        body << "\x00"                                  # session_id: empty for QUIC (RFC 9001 §8.4)
        body << [2].pack("n")                           # cipher suites length
        body << [0x1301].pack("n")                      # TLS_AES_128_GCM_SHA256
        body << "\x01\x00"                              # compression: 1 method, null

        exts = build_extensions
        body << [exts.bytesize].pack("n") << exts

        @ch_msg = tls_handshake_message(0x01, body)
      end

      # Process ServerHello. +sh_msg+ is the full handshake message (type+length+body).
      # Returns { handshake_keys: { client:, server: } }.
      def process_server_hello sh_msg
        data = sh_msg.byteslice(4, sh_msg.bytesize - 4)
        server_pub_raw = parse_server_hello(data)

        # X25519 key exchange
        peer_pub = OpenSSL::PKey.new_raw_public_key("X25519", server_pub_raw)
        shared_secret = @ecdh.derive(peer_pub)

        # Key schedule
        zeros32 = "\x00".b * 32
        empty_hash = OpenSSL::Digest::SHA256.digest("")

        early_secret = Crypto.hkdf_extract(zeros32, zeros32)
        derived1 = derive_secret(early_secret, "derived", empty_hash)
        @handshake_secret = Crypto.hkdf_extract(derived1, shared_secret)

        transcript_ch_sh = OpenSSL::Digest::SHA256.digest(@ch_msg + sh_msg)

        @client_hs_secret = derive_secret(@handshake_secret, "c hs traffic", transcript_ch_sh)
        @server_hs_secret = derive_secret(@handshake_secret, "s hs traffic", transcript_ch_sh)

        @sh_msg = sh_msg

        {
          handshake_keys: {
            client: Crypto.derive_keys(@client_hs_secret),
            server: Crypto.derive_keys(@server_hs_secret),
          }
        }
      end

      # Process concatenated EE+Cert+CV+Finished from Handshake CRYPTO.
      # Returns { app_keys: { client:, server: }, client_finished: bytes }.
      def process_handshake_crypto data
        ee_msg, cert_msg, cv_msg, finished_msg, server_cert, cv_body, finished_body =
          parse_handshake_messages(data)

        # Verify CertificateVerify
        transcript_for_cv = OpenSSL::Digest::SHA256.digest(@ch_msg + @sh_msg + ee_msg + cert_msg)
        verify_certificate_verify(cv_body, server_cert, transcript_for_cv)

        # Verify server Finished
        transcript_for_fin = OpenSSL::Digest::SHA256.digest(
          @ch_msg + @sh_msg + ee_msg + cert_msg + cv_msg
        )
        verify_finished(@server_hs_secret, finished_body, transcript_for_fin)

        # Derive app keys
        zeros32 = "\x00".b * 32
        empty_hash = OpenSSL::Digest::SHA256.digest("")

        derived2 = derive_secret(@handshake_secret, "derived", empty_hash)
        master_secret = Crypto.hkdf_extract(derived2, zeros32)

        transcript_sf = OpenSSL::Digest::SHA256.digest(
          @ch_msg + @sh_msg + ee_msg + cert_msg + cv_msg + finished_msg
        )

        client_app_secret = derive_secret(master_secret, "c ap traffic", transcript_sf)
        server_app_secret = derive_secret(master_secret, "s ap traffic", transcript_sf)

        # Build client Finished
        client_finished_body = build_finished(@client_hs_secret, transcript_sf)

        {
          app_keys: {
            client: Crypto.derive_keys(client_app_secret),
            server: Crypto.derive_keys(server_app_secret),
          },
          client_finished: tls_handshake_message(0x14, client_finished_body),
        }
      end

      private

      def derive_secret secret, label, transcript_hash
        Crypto.hkdf_expand_label(secret, label, transcript_hash, 32)
      end

      def tls_handshake_message type, body
        msg = "".b
        msg << type
        msg << [body.bytesize].pack("N").byteslice(1, 3)
        msg << body
      end

      def build_finished hs_secret, transcript_hash
        finished_key = Crypto.hkdf_expand_label(hs_secret, "finished", "", 32)
        OpenSSL::HMAC.digest("SHA256", finished_key, transcript_hash)
      end

      # ── Extensions ─────────────────────────────────────────────────────

      def build_extensions
        exts = "".b

        # server_name (SNI)
        if @host
          host = @host.b
          write_ext exts, EXT_SERVER_NAME,
            [3 + host.bytesize, 0, host.bytesize].pack("nCn") << host
        end

        # supported_versions: TLS 1.3 only
        write_ext exts, EXT_SUPPORTED_VERSIONS, [2, 0x0304].pack("Cn")

        # supported_groups: X25519
        write_ext exts, EXT_SUPPORTED_GROUPS, [2, X25519].pack("nn")

        # signature_algorithms: ECDSA P-256 + RSA-PSS SHA-256/384/512
        write_ext exts, EXT_SIGNATURE_ALGORITHMS,
          [8, 0x0403, 0x0804, 0x0805, 0x0806].pack("n5")

        # key_share: X25519
        pub = @ecdh.raw_public_key
        write_ext exts, EXT_KEY_SHARE,
          [4 + pub.bytesize, X25519, pub.bytesize].pack("nnn") << pub

        # ALPN: h3
        write_ext exts, EXT_ALPN, [3, 2].pack("nC") << "h3".b

        # QUIC transport parameters
        write_ext exts, EXT_QUIC_TRANSPORT_PARAMS, build_transport_params

        exts
      end

      def write_ext buf, type, data
        [type, data.bytesize].pack("nn", buffer: buf)
        buf << data
      end

      def build_transport_params
        buf = "".b
        add_transport_param_varint(buf, 0x01, 30_000)   # max_idle_timeout
        add_transport_param_varint(buf, 0x04, 1_048_576) # initial_max_data
        add_transport_param_varint(buf, 0x05, 262_144)   # initial_max_stream_data_bidi_local
        add_transport_param_varint(buf, 0x06, 262_144)   # initial_max_stream_data_bidi_remote
        add_transport_param_varint(buf, 0x07, 262_144)   # initial_max_stream_data_uni
        add_transport_param_varint(buf, 0x08, 100)       # initial_max_streams_bidi
        add_transport_param_varint(buf, 0x09, 100)       # initial_max_streams_uni
        add_transport_param_varint(buf, 0x0e, 2)         # active_connection_id_limit
        add_transport_param(buf, 0x0f, @our_scid || "".b) # initial_source_connection_id
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

      # ── Parsing ─────────────────────────────────────────────────────────

      def parse_server_hello data
        pos = 0
        pos += 2   # legacy_version
        pos += 32  # server random
        sid_len = data.getbyte(pos); pos += 1 + sid_len
        pos += 2   # cipher suite
        pos += 1   # compression

        ext_len = data.byteslice(pos, 2).unpack1("n"); pos += 2
        ext_end = pos + ext_len
        server_pub_raw = nil

        while pos < ext_end
          ext_type = data.byteslice(pos, 2).unpack1("n"); pos += 2
          ext_data_len = data.byteslice(pos, 2).unpack1("n"); pos += 2
          ext_data = data.byteslice(pos, ext_data_len); pos += ext_data_len

          if ext_type == EXT_KEY_SHARE
            group = ext_data.byteslice(0, 2).unpack1("n")
            key_len = ext_data.byteslice(2, 2).unpack1("n")
            server_pub_raw = ext_data.byteslice(4, key_len) if group == X25519
          end
        end

        server_pub_raw
      end

      def parse_handshake_messages data
        pos = 0
        ee_msg = cert_msg = cv_msg = finished_msg = nil
        server_cert = nil
        cv_body = finished_body = nil

        while pos < data.bytesize
          type = data.getbyte(pos)
          msg_len = (data.getbyte(pos + 1) << 16) | (data.getbyte(pos + 2) << 8) | data.getbyte(pos + 3)
          full_msg = data.byteslice(pos, 4 + msg_len)
          body = data.byteslice(pos + 4, msg_len)
          pos += 4 + msg_len

          case type
          when 0x08 then ee_msg = full_msg
          when 0x0b then cert_msg = full_msg; server_cert = parse_certificate(body)
          when 0x0f then cv_msg = full_msg; cv_body = body
          when 0x14 then finished_msg = full_msg; finished_body = body
          end
        end

        [ee_msg, cert_msg, cv_msg, finished_msg, server_cert, cv_body, finished_body]
      end

      def parse_certificate body
        pos = 0
        ctx_len = body.getbyte(pos); pos += 1
        pos += ctx_len if ctx_len > 0
        pos += 3 # cert list length
        cert_len = (body.getbyte(pos) << 16) | (body.getbyte(pos + 1) << 8) | body.getbyte(pos + 2)
        pos += 3
        OpenSSL::X509::Certificate.new(body.byteslice(pos, cert_len))
      end

      # ── Verification ───────────────────────────────────────────────────

      def verify_certificate_verify body, cert, transcript_hash
        pos = 0
        sig_scheme = body.byteslice(pos, 2).unpack1("n"); pos += 2
        sig_len = body.byteslice(pos, 2).unpack1("n"); pos += 2
        signature = body.byteslice(pos, sig_len)

        sig_input = (" " * 64).b + "TLS 1.3, server CertificateVerify\x00".b + transcript_hash

        ok = case sig_scheme
        when 0x0403 # ecdsa_secp256r1_sha256
          cert.public_key.verify("SHA256", signature, sig_input)
        when 0x0804 # rsa_pss_rsae_sha256
          cert.public_key.verify_pss("SHA256", signature, sig_input, salt_length: :auto, mgf1_hash: "SHA256")
        when 0x0805 # rsa_pss_rsae_sha384
          cert.public_key.verify_pss("SHA384", signature, sig_input, salt_length: :auto, mgf1_hash: "SHA384")
        when 0x0806 # rsa_pss_rsae_sha512
          cert.public_key.verify_pss("SHA512", signature, sig_input, salt_length: :auto, mgf1_hash: "SHA512")
        else
          raise "Unsupported signature scheme: 0x#{sig_scheme.to_s(16)}"
        end

        raise "TLS CertificateVerify failed" unless ok
      end

      def verify_finished hs_secret, verify_data, transcript_hash
        finished_key = Crypto.hkdf_expand_label(hs_secret, "finished", "", 32)
        expected = OpenSSL::HMAC.digest("SHA256", finished_key, transcript_hash)
        unless verify_data == expected
          raise "TLS server Finished verification failed"
        end
      end
    end
  end
end
