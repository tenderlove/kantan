# frozen_string_literal: true

module Kantan
  module H3
    module Varint
      # Encode a QUIC variable-length integer (RFC 9000 §16) into +out+.
      def self.encode(out, value)
        if value < 0x40
          out << value
        elsif value < 0x4000
          out << [0x4000 | value].pack("n")
        elsif value < 0x40000000
          out << [0x80000000 | value].pack("N")
        else
          out << [0xC000000000000000 | value].pack("Q>")
        end
      end

      # Read a varint from an IO-like object (must support readbyte + read).
      def self.read(io)
        first = io.readbyte
        prefix = first >> 6
        value = first & 0x3F

        case prefix
        when 0 then value
        when 1
          (value << 8) | io.readbyte
        when 2
          rest = io.read(3)
          (value << 24) | (rest.getbyte(0) << 16) | (rest.getbyte(1) << 8) | rest.getbyte(2)
        when 3
          rest = io.read(7)
          (value << 56) | ("\0".b << rest).unpack1("Q>")
        end
      end

      # Decode a varint from a buffer at +pos+, returning nil if insufficient data.
      def self.safe_decode(buf, pos = 0)
        return nil if pos >= buf.bytesize
        first = buf.getbyte(pos)
        prefix = first >> 6
        value = first & 0x3F

        case prefix
        when 0
          [value, pos + 1]
        when 1
          return nil if pos + 1 >= buf.bytesize
          value = (value << 8) | buf.getbyte(pos + 1)
          [value, pos + 2]
        when 2
          return nil if pos + 3 >= buf.bytesize
          value = (value << 24) |
            (buf.getbyte(pos + 1) << 16) |
            (buf.getbyte(pos + 2) << 8) |
            buf.getbyte(pos + 3)
          [value, pos + 4]
        when 3
          return nil if pos + 7 >= buf.bytesize
          value = (value << 56) |
            (buf.getbyte(pos + 1) << 48) |
            (buf.getbyte(pos + 2) << 40) |
            (buf.getbyte(pos + 3) << 32) |
            (buf.getbyte(pos + 4) << 24) |
            (buf.getbyte(pos + 5) << 16) |
            (buf.getbyte(pos + 6) << 8) |
            buf.getbyte(pos + 7)
          [value, pos + 8]
        end
      end

      # Decode a varint from a buffer at +pos+.  Returns [value, new_pos].
      def self.decode(buf, pos = 0)
        first = buf.getbyte(pos)
        prefix = first >> 6
        value = first & 0x3F

        case prefix
        when 0
          [value, pos + 1]
        when 1
          value = (value << 8) | buf.getbyte(pos + 1)
          [value, pos + 2]
        when 2
          value = (value << 24) |
            (buf.getbyte(pos + 1) << 16) |
            (buf.getbyte(pos + 2) << 8) |
            buf.getbyte(pos + 3)
          [value, pos + 4]
        when 3
          value = (value << 56) |
            (buf.getbyte(pos + 1) << 48) |
            (buf.getbyte(pos + 2) << 40) |
            (buf.getbyte(pos + 3) << 32) |
            (buf.getbyte(pos + 4) << 24) |
            (buf.getbyte(pos + 5) << 16) |
            (buf.getbyte(pos + 6) << 8) |
            buf.getbyte(pos + 7)
          [value, pos + 8]
        end
      end
    end
  end
end
