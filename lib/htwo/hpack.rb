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

    def initialize table_size = 4096
      @table_size = table_size
      @dynamic_table = []
      @dynamic_table_size = 0
    end

    def encode headers
      out = "".b
      headers.each do |name, value|
        index = STATIC_TABLE.index([name, value])
        if index
          # Indexed header field
          [0x80 | (index + 1)].pack("C", buffer: out)
        else
          # Try to find name match
          index = STATIC_TABLE.index { |n, _| n == name }

          raise unless index

          # Incremental indexing
          [0x40 | (index + 1)].pack("C", buffer: out)

          if value.bytesize >= 127
            raise NotImplementedError
          else
            [value.bytesize].pack("C", buffer: out)
            out << value
            add_to_dynamic_table name, value
          end
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
          headers << lookup(byte & 0x7F)
        elsif byte[6].positive?
          name_idx = byte & 0x3F

          if name_idx == 0
            len = buffer.getbyte(pos)
            huffman = len[7].positive?
            len &= 0x7F
            raise NotImplementedError if len == 127
            name = buffer.byteslice(pos + 1, len)
            name = Huffman.decode(name) if huffman
            pos += len + 1
          else
            name = lookup(name_idx).first
          end

          len = buffer.getbyte(pos)
          huffman = len[7].positive?
          len &= 0x7F
          raise NotImplementedError if len == 127
          value = buffer.byteslice(pos + 1, len)
          value = Huffman.decode(value) if huffman
          pos += len + 1

          headers << [name, value]
          add_to_dynamic_table name, value
        elsif byte[5].positive?  # Dynamic table size update
          raise NotImplementedError
        else
          name_idx = if byte & 0xF0 == 0
            byte & 0x0F
          else
            raise NotImplementedError
          end

          if name_idx == 0
            len = buffer.getbyte(pos)
            huffman = len[7].positive?
            len &= 0x7F
            raise NotImplementedError if len == 127
            name = buffer.byteslice(pos + 1, len)
            name = Huffman.decode(name) if huffman
            pos += len + 1
          else
            name = lookup(name_idx).first
          end

          len = buffer.getbyte(pos)
          huffman = len[7].positive?
          len &= 0x7F
          raise NotImplementedError if len == 127
          value = buffer.byteslice(pos + 1, len)
          value = Huffman.decode(value) if huffman
          pos += len + 1

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
