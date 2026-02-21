# frozen_string_literal: true

module Kantan
  module H3
    module Varint
      # Encode a QUIC variable-length integer (RFC 9000 §16) into +out+.
      def self.encode out, value
        if value < 0x40
          out << value
        elsif value < 0x4000
          [0x4000 | value].pack("n", buffer: out)
        elsif value < 0x40000000
          [0x80000000 | value].pack("N", buffer: out)
        else
          [0xC000000000000000 | value].pack("Q>", buffer: out)
        end
      end

      # Decode a varint from a buffer at +pos+, returning nil if insufficient data.
      def self.safe_decode buf, pos = 0
        return nil if pos >= buf.bytesize
        len = 1 << (buf.getbyte(pos) >> 6) # 1, 2, 4, or 8
        return nil if buf.bytesize < pos + len

        case len
        when 1 then [buf.getbyte(pos) & 0x3F, pos + 1]
        when 2 then [buf.unpack1("n", offset: pos) & 0x3FFF, pos + 2]
        when 4 then [buf.unpack1("N", offset: pos) & 0x3FFFFFFF, pos + 4]
        when 8 then [buf.unpack1("Q>", offset: pos) & 0x3FFFFFFFFFFFFFFF, pos + 8]
        end
      end

      # Decode a varint from a buffer at +pos+.  Returns [value, new_pos].
      def self.decode buf, pos = 0
        safe_decode buf, pos
      end
    end
  end
end
