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
          headers << STATIC_TABLE[(byte & 0x7F) - 1]
        elsif byte[6].positive?
          name = STATIC_TABLE[(byte & 0x3F) - 1].first

          len = buffer.getbyte(pos)

          huffman = len[7].positive?

          len &= 0x7F

          if len == 127
            raise NotImplementedError
          end

          value = buffer.byteslice(pos + 1, len & 0x7F)
          value = Huffman.decode(value) if huffman

          headers << [name, value]
          pos += len + 1

          add_to_dynamic_table name, value
        elsif byte[5].positive?  # Dynamic table size update
          raise NotImplementedError
        else
          name = if byte & 0xF0 == 0
            STATIC_TABLE[(byte & 0x3F) - 1].first
          else
            raise NotImplementedError
          end

          len = buffer.getbyte(pos)

          huffman = len[7].positive?

          len &= 0x7F

          if len == 127
            raise NotImplementedError
          end

          value = buffer.byteslice(pos + 1, len & 0x7F)
          value = Huffman.decode(value) if huffman

          headers << [name, value]
          pos += len + 1
        end
      end

      headers
    end

    private

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
