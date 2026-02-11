# frozen_string_literal: true

require "http2/huffman"

module HTWO
  class HPACK
    # Static table as defined in RFC 7541
    STATIC_TABLE = Ractor.make_shareable([
      [":authority", ""],
      [":method", "GET"],
      [":method", "POST"],
      [":path", "/"],
      [":path", "/index.html"],
      [":scheme", "http"],
      [":scheme", "https"],
      [":status", "200"],
      [":status", "204"],
      [":status", "206"],
      [":status", "304"],
      [":status", "400"],
      [":status", "404"],
      [":status", "500"],
      ["accept-charset", ""],
      ["accept-encoding", "gzip, deflate"],
      ["accept-language", ""],
      ["accept-ranges", ""],
      ["accept", ""],
      ["access-control-allow-origin", ""],
      ["age", ""],
      ["allow", ""],
      ["authorization", ""],
      ["cache-control", ""],
      ["content-disposition", ""],
      ["content-encoding", ""],
      ["content-language", ""],
      ["content-length", ""],
      ["content-location", ""],
      ["content-range", ""],
      ["content-type", ""],
      ["cookie", ""],
      ["date", ""],
      ["etag", ""],
      ["expect", ""],
      ["expires", ""],
      ["from", ""],
      ["host", ""],
      ["if-match", ""],
      ["if-modified-since", ""],
      ["if-none-match", ""],
      ["if-range", ""],
      ["if-unmodified-since", ""],
      ["last-modified", ""],
      ["link", ""],
      ["location", ""],
      ["max-forwards", ""],
      ["proxy-authenticate", ""],
      ["proxy-authorization", ""],
      ["range", ""],
      ["referer", ""],
      ["refresh", ""],
      ["retry-after", ""],
      ["server", ""],
      ["set-cookie", ""],
      ["strict-transport-security", ""],
      ["transfer-encoding", ""],
      ["user-agent", ""],
      ["vary", ""],
      ["via", ""],
      ["www-authenticate", ""]
    ])

    # Headers whose values change frequently — don't add to dynamic table
    NO_INDEX_NAMES = Set.new(%w[:path content-length etag location set-cookie]).freeze

    def initialize table_size = 4096
      @table_size = table_size
      @dynamic_table = []
      @dynamic_table_size = 0
    end

    def encode headers
      out = "".b
      headers.each do |name, value|
        # Check static table for full match
        idx = STATIC_TABLE.index([name, value])
        if idx
          encode_integer(out, idx + 1, 7, 0x80)
          next
        end

        # Check dynamic table for full match
        idx = @dynamic_table.index([name, value])
        if idx
          encode_integer(out, idx + STATIC_TABLE.length + 1, 7, 0x80)
          next
        end

        # Name match — prefer static table (smaller indices)
        name_idx = STATIC_TABLE.index { |n, _| n == name }
        name_idx = name_idx + 1 if name_idx
        unless name_idx
          name_idx = @dynamic_table.index { |n, _| n == name }
          name_idx = name_idx + STATIC_TABLE.length + 1 if name_idx
        end

        if NO_INDEX_NAMES.include?(name)
          # Literal without indexing
          if name_idx
            encode_integer(out, name_idx, 4, 0x00)
          else
            out << "\x00".b
            encode_string(out, name)
          end
          encode_string(out, value)
        else
          # Literal with incremental indexing
          if name_idx
            encode_integer(out, name_idx, 6, 0x40)
          else
            out << "\x40".b
            encode_string(out, name)
          end
          encode_string(out, value)
          add_to_dynamic_table name, value
        end
      end
      out
    end

    def decode buffer
      headers = []
      pos = 0

      while pos < buffer.bytesize
        byte = buffer.getbyte(pos)
        pos += 1
        if byte[7].positive?
          idx = byte & 0x7F
          if idx == 127
            remainder, pos = buffer.unpack("R^", offset: pos)
            idx = 127 + remainder
          end
          headers << lookup(idx)
        elsif byte[6].positive?
          name_idx = byte & 0x3F
          if name_idx == 63
            remainder, pos = buffer.unpack("R^", offset: pos)
            name_idx = 63 + remainder
          end

          if name_idx == 0
            len = buffer.getbyte(pos)
            huffman = len[7].positive?
            len &= 0x7F
            pos += 1
            if len == 127
              remainder, pos = buffer.unpack("R^", offset: pos)
              len = 127 + remainder
            end
            name = buffer.byteslice(pos, len)
            name = Huffman.decode(name) if huffman
            pos += len
          else
            name = lookup(name_idx).first
          end

          len = buffer.getbyte(pos)
          huffman = len[7].positive?
          len &= 0x7F
          pos += 1
          if len == 127
            remainder, pos = buffer.unpack("R^", offset: pos)
            len = 127 + remainder
          end
          value = buffer.byteslice(pos, len)
          value = Huffman.decode(value) if huffman
          pos += len

          headers << [name, value]
          add_to_dynamic_table name, value
        elsif byte[5].positive?  # Dynamic table size update
          new_size = byte & 0x1F
          if new_size == 31
            remainder, pos = buffer.unpack("R^", offset: pos)
            new_size = 31 + remainder
          end
          @table_size = new_size
          while @dynamic_table_size > @table_size && !@dynamic_table.empty?
            evicted = @dynamic_table.pop
            @dynamic_table_size -= evicted[0].bytesize + evicted[1].bytesize + 32
          end
        else
          never_indexed = byte & 0xF0 == 0x10
          name_idx = byte & 0x0F
          if name_idx == 15
            remainder, pos = buffer.unpack("R^", offset: pos)
            name_idx = 15 + remainder
          end

          if name_idx == 0
            len = buffer.getbyte(pos)
            huffman = len[7].positive?
            len &= 0x7F
            pos += 1
            if len == 127
              remainder, pos = buffer.unpack("R^", offset: pos)
              len = 127 + remainder
            end
            name = buffer.byteslice(pos, len)
            name = Huffman.decode(name) if huffman
            pos += len
          else
            name = lookup(name_idx).first
          end

          len = buffer.getbyte(pos)
          huffman = len[7].positive?
          len &= 0x7F
          pos += 1
          if len == 127
            remainder, pos = buffer.unpack("R^", offset: pos)
            len = 127 + remainder
          end
          value = buffer.byteslice(pos, len)
          value = Huffman.decode(value) if huffman
          pos += len

          headers << [name, value]
        end
      end

      headers
    end

    private

    def lookup idx
      if idx <= STATIC_TABLE.length
        STATIC_TABLE[idx - 1]
      else
        @dynamic_table[idx - STATIC_TABLE.length - 1]
      end
    end

    def encode_integer(out, value, prefix_bits, pattern)
      max = (1 << prefix_bits) - 1
      if value < max
        [pattern | value].pack("C", buffer: out)
      else
        [pattern | max].pack("C", buffer: out)
        [value - max].pack("R", buffer: out)
      end
    end

    def encode_string(out, str)
      huffed = Huffman.encode(str)
      if huffed.bytesize < str.bytesize
        len = huffed.bytesize
        if len < 127
          [0x80 | len].pack("C", buffer: out)
        else
          [0xFF].pack("C", buffer: out)
          [len - 127].pack("R", buffer: out)
        end
        out << huffed
      else
        len = str.bytesize
        if len < 127
          [len].pack("C", buffer: out)
        else
          [0x7F].pack("C", buffer: out)
          [len - 127].pack("R", buffer: out)
        end
        out << str
      end
    end

    def add_to_dynamic_table name, value
      entry_size = name.bytesize + value.bytesize + 32
      @dynamic_table.unshift([name, value])
      @dynamic_table_size += entry_size

      # Evict entries if over size limit
      while @dynamic_table_size > @table_size && !@dynamic_table.empty?
        evicted = @dynamic_table.pop
        @dynamic_table_size -= evicted[0].bytesize + evicted[1].bytesize + 32
      end
    end
  end
end
