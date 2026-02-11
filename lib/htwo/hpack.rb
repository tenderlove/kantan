# frozen_string_literal: true

require "htwo/huffman"

module HTWO
  class HPACK
    class DynamicTable # :nodoc:
      def initialize max_size
        @entries = []
        @seqs = []
        @size = 0
        @max_size = max_size
        @seq = 0
        @full_index = {}
        @name_index = {}
      end

      def add name, value
        @entries.unshift([name, value])
        @seqs.unshift(@seq)
        (@full_index[name] ||= {})[value] = @seq
        @name_index[name] = @seq
        @seq += 1
        @size += name.bytesize + value.bytesize + 32
        evict
      end

      def find name, value
        seq_num = @full_index.dig(name, value)
        return unless seq_num
        62 + (@seq - 1 - seq_num)
      end

      def find_name name
        seq_num = @name_index[name]
        return unless seq_num
        62 + (@seq - 1 - seq_num)
      end

      def lookup idx
        @entries[idx - 62]
      end

      def resize new_max
        @max_size = new_max
        evict
      end

      private

      def evict
        while @size > @max_size && !@entries.empty?
          evicted_name, evicted_value = @entries.pop
          evicted_seq = @seqs.pop
          @size -= evicted_name.bytesize + evicted_value.bytesize + 32
          if (inner = @full_index[evicted_name]) && inner[evicted_value] == evicted_seq
            inner.delete(evicted_value)
            @full_index.delete(evicted_name) if inner.empty?
          end
          @name_index.delete(evicted_name) if @name_index[evicted_name] == evicted_seq
        end
      end
    end

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
      @dynamic_table = DynamicTable.new(table_size)
    end

    def encode headers
      out = "".b
      headers.each do |name, value|
        idx = key_value_index(name, value)
        if idx
          encode_integer(out, idx, 7, 0x80)
          next
        end

        # Name match — prefer static table (smaller indices)
        name_idx = key_index(name)

        case name
          # Headers whose values change frequently — don't add to dynamic table
        when ":path", "content-length", "etag", "location", "set-cookie"
          # Literal without indexing
          if name_idx
            encode_integer(out, name_idx, 4, 0x00)
          else
            out << 0x00
            encode_string(out, name)
          end
          encode_string(out, value)
        else
          # Literal with incremental indexing
          if name_idx
            encode_integer(out, name_idx, 6, 0x40)
          else
            out << 0x40
            encode_string(out, name)
          end
          encode_string(out, value)
          @dynamic_table.add(name, value)
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

          if name_idx.zero?
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
          @dynamic_table.add(name, value)
        elsif byte[5].positive?  # Dynamic table size update
          new_size = byte & 0x1F
          if new_size == 31
            remainder, pos = buffer.unpack("R^", offset: pos)
            new_size = 31 + remainder
          end
          @dynamic_table.resize(new_size)
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

    m = STATIC_TABLE.each_with_object({}).with_index do |((k, v), o), i|
      (o[k] ||= {})[v] = i
    end

    kv_code = "case key\n" + m.map { |key, values|
      "when #{key.dump}" +
      if values.length == 1
        " then value == #{values.keys.first.dump} ? #{values.values.first} : nil"
      else
        "\n  case value\n" +
          values.map { |v, n| "  when #{v.dump} then #{n}" }.join("\n") +
          "\n  else\n    nil\n  end"
      end
    }.join("\n") + "\nelse\nend"

    class_eval "def static_key_value_index key, value\n#{kv_code}\nend", __FILE__, __LINE__

    key_code = "case key\n" + m.map { |key, values|
      "when #{key.dump} then #{values.values.first}"
    }.join("\n") + "\nelse\nend"

    class_eval "def static_key_index key\n#{key_code}\nend", __FILE__, __LINE__

    def key_value_index key, value
      idx = static_key_value_index key, value
      return idx + 1 if idx

      @dynamic_table.find(key, value)
    end

    def key_index key
      idx = static_key_index key
      return idx + 1 if idx

      @dynamic_table.find_name(key)
    end

    def lookup idx
      if idx < 62 # STATIC_TABLE.length + 1
        STATIC_TABLE[idx - 1]
      else
        @dynamic_table.lookup(idx)
      end
    end

    def encode_integer out, value, prefix_bits, pattern
      max = (1 << prefix_bits) - 1
      if value < max
        [pattern | value].pack("C", buffer: out)
      else
        [pattern | max, value - max].pack("CR", buffer: out)
      end
    end

    def encode_string out, str
      huffed = Huffman.encode(str)
      if huffed.bytesize < str.bytesize
        len = huffed.bytesize
        if len < 127
          [0x80 | len].pack("C", buffer: out)
        else
          [0xFF, len - 127].pack("CR", buffer: out)
        end
        out << huffed
      else
        len = str.bytesize
        if len < 127
          [len].pack("C", buffer: out)
        else
          [0x7F, len - 127].pack("CR", buffer: out)
        end
        out << str
      end
    end
  end
end
