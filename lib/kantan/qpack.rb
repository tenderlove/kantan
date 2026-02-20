# frozen_string_literal: true

require "kantan/huffman"

module Kantan
  module QPACK
    class EncoderStreamError < StandardError; end
    class DecompressionFailed < StandardError; end

    class StreamBlocked < StandardError
      attr_reader :stream_id

      def initialize stream_id
        @stream_id = stream_id
        super("stream #{stream_id} blocked")
      end
    end

    # QPACK static table (RFC 9204 Appendix A), 0-indexed, 99 entries.
    STATIC_TABLE = Ractor.make_shareable([
      [":authority", ""],                             # 0
      [":path", "/"],                                 # 1
      ["age", "0"],                                   # 2
      ["content-disposition", ""],                     # 3
      ["content-length", "0"],                         # 4
      ["cookie", ""],                                  # 5
      ["date", ""],                                    # 6
      ["etag", ""],                                    # 7
      ["if-modified-since", ""],                       # 8
      ["if-none-match", ""],                           # 9
      ["last-modified", ""],                           # 10
      ["link", ""],                                    # 11
      ["location", ""],                                # 12
      ["referer", ""],                                 # 13
      ["set-cookie", ""],                              # 14
      [":method", "CONNECT"],                          # 15
      [":method", "DELETE"],                           # 16
      [":method", "GET"],                              # 17
      [":method", "HEAD"],                             # 18
      [":method", "OPTIONS"],                          # 19
      [":method", "POST"],                             # 20
      [":method", "PUT"],                              # 21
      [":scheme", "http"],                             # 22
      [":scheme", "https"],                            # 23
      [":status", "103"],                              # 24
      [":status", "200"],                              # 25
      [":status", "304"],                              # 26
      [":status", "404"],                              # 27
      [":status", "503"],                              # 28
      ["accept", "*/*"],                               # 29
      ["accept", "application/dns-message"],           # 30
      ["accept-encoding", "gzip, deflate, br"],        # 31
      ["accept-ranges", "bytes"],                      # 32
      ["access-control-allow-headers", "cache-control"], # 33
      ["access-control-allow-headers", "content-type"],  # 34
      ["access-control-allow-origin", "*"],            # 35
      ["cache-control", "max-age=0"],                  # 36
      ["cache-control", "max-age=2592000"],            # 37
      ["cache-control", "max-age=604800"],             # 38
      ["cache-control", "no-cache"],                   # 39
      ["cache-control", "no-store"],                   # 40
      ["cache-control", "public, max-age=31536000"],   # 41
      ["content-encoding", "br"],                      # 42
      ["content-encoding", "gzip"],                    # 43
      ["content-type", "application/dns-message"],     # 44
      ["content-type", "application/javascript"],      # 45
      ["content-type", "application/json"],            # 46
      ["content-type", "application/x-www-form-urlencoded"], # 47
      ["content-type", "image/gif"],                   # 48
      ["content-type", "image/jpeg"],                  # 49
      ["content-type", "image/png"],                   # 50
      ["content-type", "text/css"],                    # 51
      ["content-type", "text/html; charset=utf-8"],    # 52
      ["content-type", "text/plain"],                  # 53
      ["content-type", "text/plain;charset=utf-8"],    # 54
      ["range", "bytes=0-"],                           # 55
      ["strict-transport-security", "max-age=31536000"], # 56
      ["strict-transport-security", "max-age=31536000; includesubdomains"], # 57
      ["strict-transport-security", "max-age=31536000; includesubdomains; preload"], # 58
      ["vary", "accept-encoding"],                     # 59
      ["vary", "origin"],                              # 60
      ["x-content-type-options", "nosniff"],           # 61
      ["x-xss-protection", "1; mode=block"],           # 62
      [":status", "100"],                              # 63
      [":status", "204"],                              # 64
      [":status", "206"],                              # 65
      [":status", "302"],                              # 66
      [":status", "400"],                              # 67
      [":status", "403"],                              # 68
      [":status", "421"],                              # 69
      [":status", "425"],                              # 70
      [":status", "500"],                              # 71
      ["accept-language", ""],                         # 72
      ["access-control-allow-credentials", "FALSE"],   # 73
      ["access-control-allow-credentials", "TRUE"],    # 74
      ["access-control-allow-headers", "*"],           # 75
      ["access-control-allow-methods", "get"],         # 76
      ["access-control-allow-methods", "get, post, options"], # 77
      ["access-control-allow-methods", "options"],     # 78
      ["access-control-expose-headers", "content-length"], # 79
      ["access-control-request-headers", "content-type"],  # 80
      ["access-control-request-method", "get"],        # 81
      ["access-control-request-method", "post"],       # 82
      ["alt-svc", "clear"],                            # 83
      ["authorization", ""],                           # 84
      ["content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none'"], # 85
      ["early-data", "1"],                             # 86
      ["expect-ct", ""],                               # 87
      ["forwarded", ""],                               # 88
      ["if-range", ""],                                # 89
      ["origin", ""],                                  # 90
      ["purpose", "prefetch"],                         # 91
      ["server", ""],                                  # 92
      ["timing-allow-origin", "*"],                    # 93
      ["upgrade-insecure-requests", "1"],              # 94
      ["user-agent", ""],                              # 95
      ["x-forwarded-for", ""],                         # 96
      ["x-frame-options", "deny"],                     # 97
      ["x-frame-options", "sameorigin"],               # 98
    ])

    class Decoder
      def initialize max_table_capacity, blocked_streams
        @max_table_capacity = max_table_capacity
        @blocked_streams = blocked_streams
        @capacity = max_table_capacity
        @entries = []
        @dropped = 0
        @size = 0
        @total_inserts = 0
        @blocked = {} # stream_id => [data]
        @known_received_count = 0
        @encoder_buf = "".b
      end

      # Process encoder stream data. Updates the dynamic table.
      # Handles partial data — incomplete instructions are buffered for the next call.
      # Returns array of stream IDs that became unblocked.
      def feed_encoder data
        if @encoder_buf.bytesize > 0
          data = @encoder_buf + data
          @encoder_buf = "".b
        end

        pos = 0
        final = data.bytesize

        while pos < final
          start_pos = pos

          begin
            byte = data.getbyte(pos)

            if byte >= 0x80
              # 1T______ — Insert with name reference (6-bit prefix)
              static = byte & 0x40 != 0
              idx = byte & 0x3F
              if idx == 63
                idx, pos = read_continuation(data, pos + 1, 63, EncoderStreamError)
              else
                pos += 1
              end

              if static
                raise EncoderStreamError, "invalid static index #{idx}" if idx >= STATIC_TABLE.length
                name = STATIC_TABLE[idx][0]
              else
                abs = @total_inserts - idx - 1
                raise EncoderStreamError, "invalid dynamic index" if abs < @dropped || abs >= @total_inserts
                name = @entries[abs - @dropped][0]
              end

              value, pos = read_string(data, pos)
              insert(name, value)

            elsif byte >= 0x40
              # 01H_____ — Insert with literal name (5-bit prefix)
              name, pos = read_string_with_prefix(data, pos, 5, 0x1F)
              value, pos = read_string(data, pos)
              insert(name, value)

            elsif byte >= 0x20
              # 001_____ — Set dynamic table capacity (5-bit prefix)
              capacity = byte & 0x1F
              if capacity == 31
                capacity, pos = read_continuation(data, pos + 1, 31, EncoderStreamError)
              else
                pos += 1
              end
              raise EncoderStreamError, "capacity #{capacity} exceeds max #{@max_table_capacity}" if capacity > @max_table_capacity
              @capacity = capacity
              evict

            else
              # 000_____ — Duplicate (5-bit prefix)
              rel = byte & 0x1F
              if rel == 31
                rel, pos = read_continuation(data, pos + 1, 31, EncoderStreamError)
              else
                pos += 1
              end
              abs = @total_inserts - rel - 1
              raise EncoderStreamError, "invalid duplicate index" if abs < @dropped || abs >= @total_inserts
              entry = @entries[abs - @dropped]
              insert(entry[0], entry[1])
            end

          rescue DecompressionFailed, EncoderStreamError => e
            raise unless e.message.include?("truncated")
            # Truncated instruction — buffer remaining data for next call
            @encoder_buf = data.byteslice(start_pos, final - start_pos)
            break
          end
        end

        # Check which blocked streams are now unblocked
        unblocked = []
        @blocked.each do |stream_id, (_, ric)|
          unblocked << stream_id if ric <= @total_inserts
        end
        unblocked
      end

      # Decode a field section from a request/response stream.
      # Returns [decoder_stream_data, headers].
      def feed_header stream_id, data
        ric, base, pos = decode_prefix(data)

        if ric > @total_inserts
          if @blocked.length >= @blocked_streams
            raise DecompressionFailed, "blocked stream limit reached"
          end
          @blocked[stream_id] = [data, ric]
          raise StreamBlocked.new(stream_id)
        end

        headers = decode_field_lines(data, pos, data.bytesize, base)
        decoder_data = ric > 0 ? encode_section_ack(stream_id) : "".b
        update_known_received(ric)
        [decoder_data, headers]
      end

      # Resume decoding a previously blocked stream.
      def resume_header stream_id
        saved = @blocked.delete(stream_id)
        raise DecompressionFailed, "no blocked data for stream #{stream_id}" unless saved

        data, ric = saved
        raise DecompressionFailed, "stream still blocked" if ric > @total_inserts

        _, base, pos = decode_prefix(data)
        headers = decode_field_lines(data, pos, data.bytesize, base)
        decoder_data = ric > 0 ? encode_section_ack(stream_id) : "".b
        update_known_received(ric)
        [decoder_data, headers]
      end

      private

      def insert name, value
        @entries << [name, value]
        @size += name.bytesize + value.bytesize + 32
        @total_inserts += 1
        evict
      end

      def evict
        while @size > @capacity && !@entries.empty?
          name, value = @entries.shift
          @dropped += 1
          @size -= name.bytesize + value.bytesize + 32
        end
      end

      def decode_prefix data
        raise DecompressionFailed, "truncated prefix" if data.bytesize < 2

        # Required Insert Count (8-bit prefix integer)
        encoded_ric = data.getbyte(0)
        pos = 1
        if encoded_ric == 255
          encoded_ric, pos = read_continuation(data, pos, 255, DecompressionFailed)
        end

        # S bit + Delta Base (7-bit prefix integer)
        byte2 = data.getbyte(pos)
        raise DecompressionFailed, "truncated prefix" unless byte2
        sign = byte2 & 0x80 != 0
        delta_base = byte2 & 0x7F
        pos += 1
        if delta_base == 127
          delta_base, pos = read_continuation(data, pos, 127, DecompressionFailed)
        end

        if encoded_ric == 0
          raise DecompressionFailed, "invalid prefix: S must be 0 when ERIC is 0" if sign
          ric = 0
          base = delta_base
        else
          ric = decode_required_insert_count(encoded_ric)
          base = sign ? ric - delta_base - 1 : ric + delta_base
        end

        [ric, base, pos]
      end

      def decode_required_insert_count encoded
        max_entries = @max_table_capacity / 32
        full_range = 2 * max_entries
        raise DecompressionFailed, "ERIC nonzero but max_table_capacity is 0" if full_range == 0

        max_value = @total_inserts + max_entries
        max_wrapped = (max_value / full_range) * full_range
        ric = max_wrapped + encoded - 1

        if ric > max_value
          raise DecompressionFailed, "invalid required insert count" if ric <= full_range
          ric -= full_range
        end

        raise DecompressionFailed, "required insert count is 0 after decode" if ric == 0
        ric
      end

      def decode_field_lines data, pos, final, base
        headers = []

        while pos < final
          byte = data.getbyte(pos)

          if byte >= 0x80
            # 1T______ — Indexed field line (6-bit prefix)
            static = byte & 0x40 != 0
            idx = byte & 0x3F
            if idx == 63
              idx, pos = read_continuation(data, pos + 1, 63, DecompressionFailed)
            else
              pos += 1
            end

            if static
              raise DecompressionFailed, "invalid static index #{idx}" if idx >= STATIC_TABLE.length
              headers << STATIC_TABLE[idx]
            else
              abs = base - idx - 1
              headers << lookup_dynamic(abs)
            end

          elsif byte >= 0x40
            # 01NT____ — Literal with name reference (4-bit prefix)
            _never_index = byte & 0x20 != 0
            static = byte & 0x10 != 0
            name_idx = byte & 0x0F
            if name_idx == 15
              name_idx, pos = read_continuation(data, pos + 1, 15, DecompressionFailed)
            else
              pos += 1
            end

            if static
              raise DecompressionFailed, "invalid static index #{name_idx}" if name_idx >= STATIC_TABLE.length
              name = STATIC_TABLE[name_idx][0]
            else
              abs = base - name_idx - 1
              name = lookup_dynamic(abs)[0]
            end

            value, pos = read_string(data, pos)
            headers << [name, value]

          elsif byte >= 0x20
            # 001NH___ — Literal with literal name (3-bit prefix)
            name, pos = read_string_with_prefix(data, pos, 3, 0x07)
            value, pos = read_string(data, pos)
            headers << [name, value]

          elsif byte >= 0x10
            # 0001____ — Indexed with post-base index (4-bit prefix)
            idx = byte & 0x0F
            if idx == 15
              idx, pos = read_continuation(data, pos + 1, 15, DecompressionFailed)
            else
              pos += 1
            end

            abs = base + idx
            headers << lookup_dynamic(abs)

          else
            # 0000N___ — Literal with post-base name reference (3-bit prefix)
            _never_index = byte & 0x08 != 0
            idx = byte & 0x07
            if idx == 7
              idx, pos = read_continuation(data, pos + 1, 7, DecompressionFailed)
            else
              pos += 1
            end

            abs = base + idx
            name = lookup_dynamic(abs)[0]
            value, pos = read_string(data, pos)
            headers << [name, value]
          end
        end

        headers
      end

      def lookup_dynamic abs
        raise DecompressionFailed, "invalid dynamic index (abs=#{abs})" if abs < @dropped || abs >= @total_inserts
        @entries[abs - @dropped]
      end

      def read_string data, pos
        byte = data.getbyte(pos) || raise(DecompressionFailed, "truncated string")
        huffman = byte & 0x80 != 0
        len = byte & 0x7F
        pos += 1
        if len == 127
          len, pos = read_continuation(data, pos, 127, DecompressionFailed)
        end
        raise DecompressionFailed, "truncated string data" if pos + len > data.bytesize

        if huffman
          str = Huffman.decode(data, pos, len)
        else
          str = data.byteslice(pos, len)
        end
        [str, pos + len]
      end

      def read_string_with_prefix data, pos, prefix_bits, mask
        byte = data.getbyte(pos) || raise(DecompressionFailed, "truncated string")
        huffman = byte & (1 << prefix_bits) != 0
        len = byte & mask
        max = mask
        pos += 1
        if len == max
          len, pos = read_continuation(data, pos, max, DecompressionFailed)
        end
        raise DecompressionFailed, "truncated string data" if pos + len > data.bytesize

        if huffman
          str = Huffman.decode(data, pos, len)
        else
          str = data.byteslice(pos, len)
        end
        [str, pos + len]
      end

      def read_continuation data, pos, base, error_class
        remainder, pos = data.unpack("R^", offset: pos)
        raise error_class, "truncated integer" unless remainder
        [base + remainder, pos]
      end

      def encode_section_ack stream_id
        out = "".b
        encode_prefixed_integer(out, stream_id, 7, 0x80)
        out
      end

      def encode_prefixed_integer out, value, prefix_bits, pattern
        max = (1 << prefix_bits) - 1
        if value < max
          out << (pattern | value)
        else
          [pattern | max, value - max].pack("CR", buffer: out)
        end
      end

      def update_known_received ric
        @known_received_count = ric if ric > @known_received_count
      end
    end

    class Encoder
      def initialize max_table_capacity
        @max_table_capacity = max_table_capacity
        @capacity = max_table_capacity
        @entries = []
        @size = 0
        @total_inserts = 0
        @dropped = 0
        @known_received_count = 0
        @unacked_streams = {} # stream_id => required_insert_count

        # Hash indexes for fast lookup
        @full_index = {} # {name => {value => absolute_index}}
        @name_index = {} # {name => absolute_index}

        @capacity_sent = false
      end

      # Encode headers for a stream. Returns [encoder_stream_data, field_section_data].
      def encode stream_id, headers
        enc_stream = "".b
        field_lines = "".b

        # Send capacity once at start
        if !@capacity_sent && @capacity > 0
          encode_prefixed_integer(enc_stream, @capacity, 5, 0x20)
          @capacity_sent = true
        end

        base = @total_inserts
        highest_ref = -1
        lowest_ref = base # tracks lowest absolute index referenced

        headers.each do |name, value|
          # 1. Exact match in static table
          si = static_kv_index(name, value)
          if si
            encode_prefixed_integer(field_lines, si, 6, 0xC0)
            next
          end

          # 2. Exact match in dynamic table (pre-base only)
          abs = @full_index.dig(name, value)
          if abs && abs >= @dropped && abs < base
            rel = base - abs - 1
            encode_prefixed_integer(field_lines, rel, 6, 0x80)
            highest_ref = abs if abs > highest_ref
            lowest_ref = abs if abs < lowest_ref
            next
          end

          sensitive = sensitive?(name, value)
          can_insert = !sensitive && can_insert_safely?(name, value, lowest_ref)

          # 3. Name match in static table
          sni = static_name_index(name)
          if sni
            if sensitive
              encode_prefixed_integer(field_lines, sni, 4, 0x70)
            else
              encode_prefixed_integer(field_lines, sni, 4, 0x50)
            end
            encode_string(field_lines, value)

            if can_insert
              encode_prefixed_integer(enc_stream, sni, 6, 0xC0)
              encode_string(enc_stream, value)
              insert(name, value)
            end
            next
          end

          # 4. Name match in dynamic table (pre-base only)
          name_abs = @name_index[name]
          if name_abs && name_abs >= @dropped && name_abs < base
            name_rel = base - name_abs - 1
            highest_ref = name_abs if name_abs > highest_ref
            lowest_ref = name_abs if name_abs < lowest_ref
            if sensitive
              encode_prefixed_integer(field_lines, name_rel, 4, 0x60)
            else
              encode_prefixed_integer(field_lines, name_rel, 4, 0x40)
            end
            encode_string(field_lines, value)

            if can_insert
              ins_rel = @total_inserts - name_abs - 1
              encode_prefixed_integer(enc_stream, ins_rel, 6, 0x80)
              encode_string(enc_stream, value)
              insert(name, value)
            end
            next
          end

          # 5. No match — literal with literal name
          if sensitive
            encode_string_with_prefix(field_lines, name, 3, 0x30)
          else
            encode_string_with_prefix(field_lines, name, 3, 0x20)
          end
          encode_string(field_lines, value)

          if can_insert
            encode_string_with_prefix(enc_stream, name, 5, 0x40)
            encode_string(enc_stream, value)
            insert(name, value)
          end
        end

        # Build field section prefix
        ric = highest_ref >= 0 ? highest_ref + 1 : 0

        if ric == 0
          encoded_ric = 0
        else
          max_entries = @max_table_capacity / 32
          encoded_ric = (ric % (2 * max_entries)) + 1
        end

        prefix = "".b
        encode_prefixed_integer(prefix, encoded_ric, 8, 0x00)
        delta_base = ric > 0 ? base - ric : 0
        encode_prefixed_integer(prefix, delta_base, 7, 0x00)

        field_section = prefix + field_lines

        @unacked_streams[stream_id] = ric if ric > 0

        [enc_stream, field_section]
      end

      # Process decoder stream data (section acks, insert count increments).
      def feed_decoder data
        pos = 0
        final = data.bytesize

        while pos < final
          byte = data.getbyte(pos)

          if byte >= 0x80
            # Section Acknowledgment: 1 + 7-bit stream_id
            stream_id = byte & 0x7F
            if stream_id == 127
              stream_id, pos = read_continuation(data, pos + 1, 127)
            else
              pos += 1
            end

            ric = @unacked_streams.delete(stream_id)
            @known_received_count = ric if ric && ric > @known_received_count

          elsif byte >= 0x40
            # Stream Cancellation: 01 + 6-bit stream_id
            stream_id = byte & 0x3F
            if stream_id == 63
              stream_id, pos = read_continuation(data, pos + 1, 63)
            else
              pos += 1
            end
            @unacked_streams.delete(stream_id)

          else
            # Insert Count Increment: 00 + 6-bit increment
            increment = byte & 0x3F
            if increment == 63
              increment, pos = read_continuation(data, pos + 1, 63)
            else
              pos += 1
            end
            @known_received_count += increment
          end
        end
      end

      private

      SENSITIVE_NAMES = { ":path" => true, "content-length" => true, "etag" => true,
                          "set-cookie" => true, "authorization" => true }.freeze

      def sensitive? name, value
        return true if SENSITIVE_NAMES[name]
        name == "cookie" && !value.empty?
      end

      # Check if inserting would evict an entry we've referenced in this field section
      def can_insert_safely? name, value, lowest_ref
        entry_size = name.bytesize + value.bytesize + 32
        return true if @size + entry_size <= @capacity

        # Simulate eviction to see what would be dropped
        remaining = @size + entry_size - @capacity
        i = 0
        while remaining > 0 && i < @entries.length
          abs = @dropped + i
          return false if abs >= lowest_ref
          n, v = @entries[i]
          remaining -= n.bytesize + v.bytesize + 32
          i += 1
        end
        remaining <= 0
      end

      def insert name, value
        @entries << [name, value]
        @size += name.bytesize + value.bytesize + 32
        abs = @total_inserts
        (@full_index[name] ||= {})[value] = abs
        @name_index[name] = abs
        @total_inserts += 1
        evict
      end

      def evict
        while @size > @capacity && !@entries.empty?
          evicted_name, evicted_value = @entries.shift
          evicted_abs = @dropped
          @dropped += 1
          @size -= evicted_name.bytesize + evicted_value.bytesize + 32
          if (inner = @full_index[evicted_name]) && inner[evicted_value] == evicted_abs
            inner.delete(evicted_value)
            @full_index.delete(evicted_name) if inner.empty?
          end
          @name_index.delete(evicted_name) if @name_index[evicted_name] == evicted_abs
        end
      end

      def encode_prefixed_integer out, value, prefix_bits, pattern
        max = (1 << prefix_bits) - 1
        if value < max
          out << (pattern | value)
        else
          [pattern | max, value - max].pack("CR", buffer: out)
        end
      end

      def encode_string out, str
        huffed = Huffman.encode(str)
        if huffed.bytesize < str.bytesize
          len = huffed.bytesize
          if len < 127
            out << (0x80 | len)
          else
            [0xFF, len - 127].pack("CR", buffer: out)
          end
          out << huffed
        else
          len = str.bytesize
          if len < 127
            out << len
          else
            [0x7F, len - 127].pack("CR", buffer: out)
          end
          out << str
        end
      end

      def encode_string_with_prefix out, str, prefix_bits, pattern
        huffed = Huffman.encode(str)
        mask = (1 << prefix_bits) - 1
        huff_bit = 1 << prefix_bits

        if huffed.bytesize < str.bytesize
          len = huffed.bytesize
          if len < mask
            out << (pattern | huff_bit | len)
          else
            [pattern | huff_bit | mask, len - mask].pack("CR", buffer: out)
          end
          out << huffed
        else
          len = str.bytesize
          if len < mask
            out << (pattern | len)
          else
            [pattern | mask, len - mask].pack("CR", buffer: out)
          end
          out << str
        end
      end

      def read_continuation data, pos, base
        remainder, pos = data.unpack("R^", offset: pos)
        raise "truncated integer" unless remainder
        [base + remainder, pos]
      end

      # --- Static table lookups (generated) ---

      m = STATIC_TABLE.each_with_object({}).with_index do |((k, v), o), i|
        (o[k] ||= {})[v] = i
      end

      kv_code = "case name\n" + m.map { |key, values|
        "when #{key.dump}" +
        if values.length == 1
          " then value == #{values.keys.first.dump} ? #{values.values.first} : nil"
        else
          "\n  case value\n" +
            values.map { |v, n| "  when #{v.dump} then #{n}" }.join("\n") +
            "\n  end"
        end
      }.join("\n") + "\nend"

      class_eval "private def static_kv_index name, value\n#{kv_code}\nend", __FILE__, __LINE__

      name_code = "case name\n" + m.map { |key, values|
        "when #{key.dump} then #{values.values.first}"
      }.join("\n") + "\nend"

      class_eval "private def static_name_index name\n#{name_code}\nend", __FILE__, __LINE__
    end
  end
end
