# frozen_string_literal: true

require "openssl"

module Kantan
  module QUIC
    module Crypto
      # QUIC v1 initial salt (RFC 9001 §5.2)
      INITIAL_SALT = ["38762cf7f55934b34d179ae6a4c80cadccbb7f0a"].pack("H*").freeze

      def self.hkdf_extract(salt, ikm)
        OpenSSL::HMAC.digest("SHA256", salt, ikm)
      end

      def self.hkdf_expand(prk, info, length)
        # RFC 5869 HKDF-Expand
        n = (length.to_f / 32).ceil
        okm = "".b
        t = "".b
        1.upto(n) do |i|
          t = OpenSSL::HMAC.digest("SHA256", prk, t + info + [i].pack("C"))
          okm << t
        end
        okm[0, length]
      end

      def self.hkdf_expand_label(secret, label, context, length)
        # TLS 1.3 HKDF-Expand-Label
        hkdf_label = [length].pack("n")
        full_label = "tls13 #{label}"
        hkdf_label << [full_label.bytesize].pack("C") << full_label.b
        hkdf_label << [context.bytesize].pack("C") << context.b
        hkdf_expand(secret, hkdf_label, length)
      end

      def self.derive_initial_secrets(dcid)
        initial_secret = hkdf_extract(INITIAL_SALT, dcid)
        client_secret = hkdf_expand_label(initial_secret, "client in", "", 32)
        server_secret = hkdf_expand_label(initial_secret, "server in", "", 32)
        [client_secret, server_secret]
      end

      def self.derive_keys(secret)
        {
          key: hkdf_expand_label(secret, "quic key", "", 16),
          iv: hkdf_expand_label(secret, "quic iv", "", 12),
          hp: hkdf_expand_label(secret, "quic hp", "", 16),
        }
      end

      def self.aead_encrypt(key, iv, pn, aad, plaintext)
        nonce = build_nonce(iv, pn)
        cipher = OpenSSL::Cipher::AES.new(128, :GCM).encrypt
        cipher.key = key
        cipher.iv = nonce
        cipher.auth_data = aad
        cipher.update(plaintext) + cipher.final + cipher.auth_tag
      end

      def self.aead_decrypt(key, iv, pn, aad, ciphertext)
        nonce = build_nonce(iv, pn)
        tag = ciphertext[-16..]
        ct = ciphertext[0...-16]
        cipher = OpenSSL::Cipher::AES.new(128, :GCM).decrypt
        cipher.key = key
        cipher.iv = nonce
        cipher.auth_tag = tag
        cipher.auth_data = aad
        cipher.update(ct) + cipher.final
      end

      def self.apply_header_protection(hp_key, sample, header, pn_offset, pn_length)
        mask = hp_mask(hp_key, sample)
        header = header.dup
        if header.getbyte(0) & 0x80 != 0
          # Long header
          header.setbyte(0, header.getbyte(0) ^ (mask.getbyte(0) & 0x0F))
        else
          # Short header
          header.setbyte(0, header.getbyte(0) ^ (mask.getbyte(0) & 0x1F))
        end
        pn_length.times do |i|
          header.setbyte(pn_offset + i, header.getbyte(pn_offset + i) ^ mask.getbyte(1 + i))
        end
        header
      end

      def self.remove_header_protection(hp_key, sample, header, pn_offset)
        mask = hp_mask(hp_key, sample)
        header = header.dup
        if header.getbyte(0) & 0x80 != 0
          header.setbyte(0, header.getbyte(0) ^ (mask.getbyte(0) & 0x0F))
          pn_length = (header.getbyte(0) & 0x03) + 1
        else
          header.setbyte(0, header.getbyte(0) ^ (mask.getbyte(0) & 0x1F))
          pn_length = (header.getbyte(0) & 0x03) + 1
        end
        pn_length.times do |i|
          header.setbyte(pn_offset + i, header.getbyte(pn_offset + i) ^ mask.getbyte(1 + i))
        end
        [header, pn_length]
      end

      def self.hp_mask(hp_key, sample)
        cipher = OpenSSL::Cipher::AES.new(128, :ECB).encrypt
        cipher.key = hp_key
        cipher.padding = 0
        cipher.update(sample)
      end

      def self.build_nonce(iv, pn)
        nonce = iv.dup
        # XOR packet number (left-padded to 12 bytes) with IV
        pn_bytes = [pn].pack("Q>")  # 8 bytes, big-endian
        # Pad to 12 bytes
        pn_padded = ("\x00" * 4 + pn_bytes).b
        12.times { |i| nonce.setbyte(i, nonce.getbyte(i) ^ pn_padded.getbyte(i)) }
        nonce
      end
      private_class_method :build_nonce, :hp_mask
    end
  end
end
