# frozen_string_literal: true

require "kantan/quic/crypto"
require "kantan/h3/varint"

module Kantan
  module QUIC
    module Packet
      INITIAL   = 0x00
      HANDSHAKE = 0x02
      VERSION_1 = 0x00000001

      Varint = H3::Varint

      # Parse a long header packet. Returns hash with parsed fields.
      # Does NOT decrypt — caller must remove header protection and decrypt.
      def self.parse_long_header(data, offset = 0)
        first_byte = data.getbyte(offset)
        version = data.byteslice(offset + 1, 4).unpack1("N")
        dcid_len = data.getbyte(offset + 5)
        dcid = data.byteslice(offset + 6, dcid_len)
        pos = offset + 6 + dcid_len
        scid_len = data.getbyte(pos); pos += 1
        scid = data.byteslice(pos, scid_len); pos += scid_len

        type = (first_byte & 0x30) >> 4

        token = "".b
        if type == INITIAL
          token_len, pos = Varint.decode(data, pos)
          token = data.byteslice(pos, token_len) if token_len > 0
          pos += token_len
        end

        payload_length, pos = Varint.decode(data, pos)
        pn_offset = pos

        {
          first_byte: first_byte,
          type: type,
          version: version,
          dcid: dcid,
          scid: scid,
          token: token,
          pn_offset: pn_offset,
          payload_length: payload_length,
          header_end: pn_offset + payload_length,
        }
      end

      def self.parse_short_header(data, dcid_len)
        first_byte = data.getbyte(0)
        dcid = data.byteslice(1, dcid_len)
        pn_offset = 1 + dcid_len
        {
          first_byte: first_byte,
          dcid: dcid,
          pn_offset: pn_offset,
        }
      end

      def self.build_initial(dcid:, scid:, pn:, frames:, keys:, token: "".b, pad: false)
        payload = frames.map { |f| f.is_a?(String) ? f : f }.join.b
        build_long(INITIAL, dcid: dcid, scid: scid, pn: pn, payload: payload, keys: keys, token: token, pad: pad)
      end

      def self.build_handshake(dcid:, scid:, pn:, frames:, keys:)
        payload = frames.map { |f| f.is_a?(String) ? f : f }.join.b
        build_long(HANDSHAKE, dcid: dcid, scid: scid, pn: pn, payload: payload, keys: keys)
      end

      def self.build_short(dcid:, pn:, frames:, keys:)
        payload = frames.join.b
        # First byte: 0100_0011 = fixed bit + 4-byte PN
        first_byte = 0x40 | 0x03 # spin=0, reserved=0, key_phase=0, pn_len=4
        header = "".b
        header << first_byte
        header << dcid
        pn_offset = header.bytesize
        header << [pn].pack("N") # 4-byte PN

        encrypted = Crypto.aead_encrypt(keys[:key], keys[:iv], pn, header, payload)
        packet = header + encrypted

        # Apply header protection
        sample_offset = pn_offset + 4
        sample = packet.byteslice(sample_offset, 16)
        protected_header = Crypto.apply_header_protection(keys[:hp], sample, packet.byteslice(0, pn_offset + 4), pn_offset, 4)
        protected_header + packet.byteslice(pn_offset + 4, packet.bytesize - pn_offset - 4)
      end

      # Decrypt a received long header packet. Returns [header_info, plaintext_frames].
      def self.decrypt_long(data, keys, offset = 0)
        info = parse_long_header(data, offset)
        pn_offset = info[:pn_offset]

        # Sample starts 4 bytes after PN offset
        sample_offset = pn_offset + 4
        sample = data.byteslice(sample_offset, 16)

        # We need enough header to include the max PN length (4 bytes)
        header_with_pn = data.byteslice(offset, pn_offset + 4 - offset)
        unprotected, pn_length = Crypto.remove_header_protection(keys[:hp], sample, header_with_pn, pn_offset - offset)

        # Reconstruct the actual packet number
        pn = 0
        pn_length.times do |i|
          pn = (pn << 8) | unprotected.getbyte(pn_offset - offset + i)
        end

        # AAD is the unprotected header up to and including the PN
        aad = unprotected.byteslice(0, pn_offset - offset + pn_length)
        # Ciphertext starts after PN
        ct_start = pn_offset + pn_length
        ct_length = info[:payload_length] - pn_length
        ciphertext = data.byteslice(ct_start, ct_length)

        plaintext = Crypto.aead_decrypt(keys[:key], keys[:iv], pn, aad, ciphertext)

        info[:pn] = pn
        info[:pn_length] = pn_length
        [info, plaintext]
      end

      # Decrypt a received short header packet.
      def self.decrypt_short(data, keys, dcid_len)
        info = parse_short_header(data, dcid_len)
        pn_offset = info[:pn_offset]

        sample_offset = pn_offset + 4
        sample = data.byteslice(sample_offset, 16)

        header_with_pn = data.byteslice(0, pn_offset + 4)
        unprotected, pn_length = Crypto.remove_header_protection(keys[:hp], sample, header_with_pn, pn_offset)

        pn = 0
        pn_length.times do |i|
          pn = (pn << 8) | unprotected.getbyte(pn_offset + i)
        end

        aad = unprotected.byteslice(0, pn_offset + pn_length)
        ct_start = pn_offset + pn_length
        ciphertext = data.byteslice(ct_start, data.bytesize - ct_start)

        plaintext = Crypto.aead_decrypt(keys[:key], keys[:iv], pn, aad, ciphertext)

        info[:pn] = pn
        info[:pn_length] = pn_length
        [info, plaintext]
      end

      private

      def self.build_long(type, dcid:, scid:, pn:, payload:, keys:, token: "".b, pad: false)
        # byte 0: 1100_PP11 for Initial (type=0), 1110_PP11 for Handshake (type=2)
        # PP = pn_length - 1 = 3 (4-byte PN) — will be masked by header protection
        first_byte = 0xC0 | (type << 4) | 0x03

        header = "".b
        header << first_byte
        header << [VERSION_1].pack("N")
        header << dcid.bytesize << dcid
        header << scid.bytesize << scid

        if type == INITIAL
          Varint.encode(header, token.bytesize)
          header << token
        end

        # Payload = PN (4 bytes) + encrypted frames + 16-byte AEAD tag
        # For Initial packets, pad to at least 1200 bytes total
        if pad
          min_payload = 1200 - header.bytesize - 2 # -2 for length varint (2 bytes is enough)
          needed = min_payload - 4 - 16 # subtract PN and tag
          if needed > payload.bytesize
            payload = payload + Kantan::QUIC::Frames.build_padding(needed - payload.bytesize)
          end
        end

        payload_length = 4 + payload.bytesize + 16 # PN + data + tag
        Varint.encode(header, payload_length)

        pn_offset = header.bytesize
        header << [pn].pack("N") # 4-byte PN

        encrypted = Crypto.aead_encrypt(keys[:key], keys[:iv], pn, header, payload)
        packet = header + encrypted

        # Apply header protection
        sample_offset = pn_offset + 4
        sample = packet.byteslice(sample_offset, 16)
        protected_header = Crypto.apply_header_protection(keys[:hp], sample, packet.byteslice(0, pn_offset + 4), pn_offset, 4)
        protected_header + packet.byteslice(pn_offset + 4, packet.bytesize - pn_offset - 4)
      end

      class << self
        private :build_long
      end
    end
  end
end
