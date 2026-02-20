# frozen_string_literal: true

require "minitest/autorun"
require "kantan/qpack"

module Kantan
  module QPACK
    class TestDecoder < Minitest::Test
      FIXTURE_BASE = File.expand_path("fixtures/qifs", __dir__)
      ENCODED_DIR = File.join(FIXTURE_BASE, "encoded")
      QIF_DIR = File.join(FIXTURE_BASE, "qifs")

      # Parse a QIF file into an array of header lists.
      # Each header list is an array of [name, value] pairs.
      # Header lists are separated by blank lines.
      # Lines starting with # are comments; the "# stream N" comment is ignored.
      def self.parse_qif(path)
        header_lists = []
        current = []

        File.foreach(path, chomp: true) do |line|
          if line.empty?
            header_lists << current unless current.empty?
            current = []
          elsif !line.start_with?("#")
            name, value = line.split("\t", 2)
            current << [name, value || ""]
          end
        end
        header_lists << current unless current.empty?
        header_lists
      end

      # Parse an encoded binary file into blocks.
      # Format: [stream_id (u64 BE), length (u32 BE), data (length bytes)]*
      def self.parse_encoded(path)
        data = File.binread(path)
        blocks = []
        pos = 0

        while pos < data.bytesize
          stream_id = data[pos, 8].unpack1("Q>")
          length = data[pos + 8, 4].unpack1("N")
          pos += 12
          block_data = data.byteslice(pos, length)
          blocks << [stream_id, block_data]
          pos += length
        end

        blocks
      end

      # Extract the QIF dataset name from an encoded filename.
      # e.g. "fb-req.out.256.100.0" -> "fb-req"
      # e.g. "fb-req-hq.out.256.100.0" -> "fb-req-hq"
      def self.qif_name_from_encoded(filename)
        # Remove directory, then strip .out.* suffix
        base = File.basename(filename)
        base.sub(/\.out\..*/, "").sub(/\.qif\..*/, "")
      end

      # Extract table capacity and max blocked from filename.
      # Format: {name}.out.{capacity}.{blocked}.{ack}
      def self.params_from_filename(filename)
        base = File.basename(filename)
        parts = base.split(".")
        # Find the .out. or look for numeric parts
        out_idx = parts.index("out")
        if out_idx && parts.length > out_idx + 2
          capacity = parts[out_idx + 1].to_i
          blocked = parts[out_idx + 2].to_i
          return [capacity, blocked]
        end
        # Fallback for other naming patterns (e.g. .qif.encoder.cap.blocked.ack)
        numeric_parts = parts.select { |p| p.match?(/\A\d+\z/) }
        if numeric_parts.length >= 2
          return [numeric_parts[0].to_i, numeric_parts[1].to_i]
        end
        [4096, 100] # defaults
      end

      def self.decode_fixture(encoded_path, max_table_capacity, max_blocked)
        blocks = parse_encoded(encoded_path)
        decoder = Decoder.new(max_table_capacity, max_blocked)

        decoded_headers = []
        blocked_streams = {}

        # Process blocks in order — encoder and header data interleaved
        blocks.each do |stream_id, data|
          if stream_id == 0
            unblocked = decoder.feed_encoder(data)
            unblocked.each do |sid|
              if blocked_streams[sid]
                _, headers = decoder.resume_header(sid)
                blocked_streams.delete(sid)
                decoded_headers << [sid, headers]
              end
            end
          else
            begin
              _, headers = decoder.feed_header(stream_id, data)
              decoded_headers << [stream_id, headers]
            rescue StreamBlocked
              blocked_streams[stream_id] = true
            end
          end
        end

        # Sort by original order (stream IDs in the order they appeared)
        seen_order = {}
        order_idx = 0
        blocks.each do |stream_id, _|
          next if stream_id == 0
          seen_order[stream_id] ||= (order_idx += 1)
        end

        decoded_headers.sort_by! { |sid, _| seen_order[sid] || 0 }
        decoded_headers.map(&:last)
      end

      # --- Draft examples test (hand-verified) ---
      def test_draft_examples
        path = File.join(ENCODED_DIR, "qpack-05", "draft-examples.out")
        skip "draft-examples.out not found" unless File.exist?(path)

        qif_path = File.join(QIF_DIR, "draft-examples.qif")
        expected = self.class.parse_qif(qif_path)
        actual = self.class.decode_fixture(path, 4096, 100)

        assert_equal expected.length, actual.length, "wrong number of header lists"
        expected.each_with_index do |exp_headers, i|
          assert_equal exp_headers, actual[i], "header list #{i} mismatch"
        end
      end

      # --- Generate tests for all qpack-05 fixture files ---
      qpack05_dir = File.join(ENCODED_DIR, "qpack-05")
      if File.directory?(qpack05_dir)
        Dir.glob(File.join(qpack05_dir, "**", "*")).select { |f| File.file?(f) }.sort.each do |encoded_path|
          relative = encoded_path.sub("#{qpack05_dir}/", "")
          next if relative == "draft-examples.out" # tested separately

          qif_name = qif_name_from_encoded(encoded_path)
          qif_path = File.join(QIF_DIR, "#{qif_name}.qif")
          next unless File.exist?(qif_path)

          capacity, blocked = params_from_filename(encoded_path)
          test_name = "test_qpack05_#{relative.gsub(/[^a-zA-Z0-9]/, "_")}"

          define_method(test_name) do
            expected = self.class.parse_qif(qif_path)
            actual = self.class.decode_fixture(encoded_path, capacity, blocked)

            assert_equal expected.length, actual.length,
              "#{relative}: wrong number of header lists (expected #{expected.length}, got #{actual.length})"
            expected.each_with_index do |exp_headers, i|
              assert_equal exp_headers, actual[i], "#{relative}: header list #{i} mismatch"
            end
          end
        end
      end

      # --- Error tests ---
      # err9/err10 test static table bounds from an older draft (1-based indexing)
      # where index 0 and index 62 were invalid. In RFC 9204 (0-based, 99 entries)
      # these are valid, so we skip them.
      SKIP_ERRORS = %w[err9 err10].freeze
      errors_dir = File.join(ENCODED_DIR, "errors")
      if File.directory?(errors_dir)
        Dir.glob(File.join(errors_dir, "err*")).sort.each do |error_path|
          error_name = File.basename(error_path)
          define_method("test_error_#{error_name}") do
            skip "#{error_name}: tests older draft static table bounds" if SKIP_ERRORS.include?(error_name)
            blocks = self.class.parse_encoded(error_path)
            decoder = Decoder.new(4096, 100)

            assert_raises(EncoderStreamError, DecompressionFailed) do
              blocks.each do |stream_id, data|
                if stream_id == 0
                  decoder.feed_encoder(data)
                else
                  begin
                    decoder.feed_header(stream_id, data)
                  rescue StreamBlocked
                    # not an error, just blocked
                  end
                end
              end
            end
          end
        end
      end

      # --- Unit tests ---
      def test_static_only_indexed
        decoder = Decoder.new(0, 0)
        # Field section: ERIC=0, delta_base=0, then indexed static 17 (:method GET)
        data = "\x00\x00\xd1".b
        decoder_data, headers = decoder.feed_header(1, data)
        assert_equal "", decoder_data
        assert_equal [[":method", "GET"]], headers
      end

      def test_static_literal_with_name_ref
        decoder = Decoder.new(0, 0)
        # ERIC=0, delta_base=0, literal with static name ref 1 (:path), value "/foo"
        data = "\x00\x00\x51\x04/foo".b
        _, headers = decoder.feed_header(1, data)
        assert_equal [[":path", "/foo"]], headers
      end

      def test_static_literal_with_literal_name
        decoder = Decoder.new(0, 0)
        # ERIC=0, delta_base=0, literal name+value: 001N=0 H=0 len=4 "test" + H=0 len=3 "val"
        data = "\x00\x00\x24test\x03val".b
        _, headers = decoder.feed_header(1, data)
        assert_equal [["test", "val"]], headers
      end

      def test_encoder_stream_insert_and_dynamic_lookup
        decoder = Decoder.new(4096, 100)
        # Encoder stream: set capacity 4096, insert with static name ref 0 (:authority) value "example.com"
        enc = "\x3f\xe1\x1f".b  # set capacity: 31 + R(4065) = 4096
        enc << "\xc0\x0bexample.com".b  # insert with static ref 0, value len 11
        decoder.feed_encoder(enc)

        # Field section: ERIC=2, S=1 delta_base=0 -> ric=1, base=0, post-base index 0
        # ERIC encoding: MaxEntries=4096/32=128, encoded = (1 % 256) + 1 = 2
        data = "\x02\x80\x10".b
        decoder_data, headers = decoder.feed_header(4, data)
        assert_equal [[":authority", "example.com"]], headers
        refute_empty decoder_data
      end

      def test_blocked_stream
        decoder = Decoder.new(4096, 1)
        # Try to decode a field section that references dynamic entry not yet inserted
        # ERIC=2 means ric=1 but we have 0 inserts
        data = "\x02\x80\x10".b
        err = assert_raises(StreamBlocked) { decoder.feed_header(4, data) }
        assert_equal 4, err.stream_id

        # Now feed encoder data to insert an entry
        enc = "\x3f\xe1\x1f".b  # set capacity 4096
        enc << "\xc0\x0bexample.com".b  # insert
        unblocked = decoder.feed_encoder(enc)
        assert_includes unblocked, 4

        # Resume
        _, headers = decoder.resume_header(4)
        assert_equal [[":authority", "example.com"]], headers
      end

      def test_blocked_stream_limit
        decoder = Decoder.new(4096, 0)
        # With blocked_streams=0, any blocked stream should raise DecompressionFailed
        data = "\x02\x80\x10".b
        assert_raises(DecompressionFailed) { decoder.feed_header(4, data) }
      end

      def test_feed_encoder_handles_partial_data
        decoder = Decoder.new(4096, 100)

        # Build a complete encoder instruction:
        # set capacity 4096, then insert with static ref 0 (:authority) value "example.com"
        full = "\x3f\xe1\x1f".b           # set capacity
        full << "\xc0\x0bexample.com".b    # insert

        # Split in the middle of the insert instruction (after the name ref byte)
        part1 = full.byteslice(0, 4)   # capacity + first byte of insert
        part2 = full.byteslice(4, full.bytesize - 4)  # rest of insert

        # First call: processes capacity, buffers partial insert
        decoder.feed_encoder(part1)

        # Second call: completes the insert
        decoder.feed_encoder(part2)

        # Verify the entry was inserted by decoding a field section that references it
        data = "\x02\x80\x10".b  # ERIC=2, post-base index 0
        _, headers = decoder.feed_header(4, data)
        assert_equal [[":authority", "example.com"]], headers
      end

      def test_feed_encoder_handles_single_byte_chunks
        decoder = Decoder.new(4096, 100)

        # Build encoder data: set capacity + insert
        full = "\x3f\xe1\x1f".b
        full << "\xc0\x0bexample.com".b

        # Feed one byte at a time
        full.each_byte { |b| decoder.feed_encoder([b].pack("C")) }

        # Verify the entry was inserted
        data = "\x02\x80\x10".b
        _, headers = decoder.feed_header(4, data)
        assert_equal [[":authority", "example.com"]], headers
      end
    end

    class TestEncoder < Minitest::Test
      FIXTURE_BASE = File.expand_path("fixtures/qifs", __dir__)
      QIF_DIR = File.join(FIXTURE_BASE, "qifs")

      # Helper: encode with Encoder, decode with Decoder, return decoded headers
      def round_trip headers, capacity: 4096, stream_id: 4
        encoder = Encoder.new(capacity)
        decoder = Decoder.new(capacity, 100)

        enc_data, field_section = encoder.encode(stream_id, headers)
        decoder.feed_encoder(enc_data) unless enc_data.empty?
        _, decoded = decoder.feed_header(stream_id, field_section)
        decoded
      end

      # --- Round-trip tests ---

      def test_round_trip_static_only
        headers = [
          [":method", "GET"],
          [":scheme", "https"],
          [":status", "200"],
        ]
        assert_equal headers, round_trip(headers)
      end

      def test_round_trip_static_only_no_inserts
        encoder = Encoder.new(4096)
        headers = [
          [":method", "GET"],
          [":scheme", "https"],
          [":path", "/"],
          [":status", "200"],
        ]
        enc_data, field_section = encoder.encode(4, headers)
        decoder = Decoder.new(4096, 100)
        decoder.feed_encoder(enc_data)
        _, decoded = decoder.feed_header(4, field_section)
        assert_equal headers, decoded
      end

      def test_round_trip_with_dynamic_inserts
        headers = [
          [":method", "GET"],
          [":scheme", "https"],
          [":authority", "example.com"],
          ["x-custom", "hello"],
        ]
        assert_equal headers, round_trip(headers)
      end

      def test_round_trip_sensitive_headers
        headers = [
          [":method", "POST"],
          [":path", "/api/users"],
          ["content-length", "42"],
          ["authorization", "Bearer token123"],
        ]
        assert_equal headers, round_trip(headers)
      end

      def test_round_trip_literal_names
        headers = [
          ["x-custom-one", "value1"],
          ["x-custom-two", "value2"],
        ]
        assert_equal headers, round_trip(headers)
      end

      # --- Dynamic table reuse across streams ---

      def test_dynamic_table_reuse
        encoder = Encoder.new(4096)
        decoder = Decoder.new(4096, 100)

        headers = [
          [":method", "GET"],
          [":scheme", "https"],
          [":authority", "example.com"],
        ]

        # First encode — inserts :authority example.com
        enc1, fs1 = encoder.encode(4, headers)
        decoder.feed_encoder(enc1)
        _, decoded1 = decoder.feed_header(4, fs1)
        assert_equal headers, decoded1

        # Second encode — should reuse dynamic table entry (smaller encoder stream)
        enc2, fs2 = encoder.encode(8, headers)
        decoder.feed_encoder(enc2) unless enc2.empty?
        _, decoded2 = decoder.feed_header(8, fs2)
        assert_equal headers, decoded2

        # Second encode should produce less encoder stream data (no new inserts for :authority)
        assert_operator enc2.bytesize, :<, enc1.bytesize
      end

      # --- Section acknowledgment ---

      def test_section_ack
        encoder = Encoder.new(4096)
        decoder = Decoder.new(4096, 100)

        headers = [[":method", "GET"], [":authority", "example.com"]]

        # First encode — inserts into dynamic table, but field section uses literal form
        enc1, fs1 = encoder.encode(4, headers)
        decoder.feed_encoder(enc1)
        _, _ = decoder.feed_header(4, fs1)

        # Second encode — reuses dynamic entry via indexed dynamic, producing ric > 0
        enc2, fs2 = encoder.encode(8, headers)
        decoder.feed_encoder(enc2) unless enc2.empty?
        decoder_data2, _ = decoder.feed_header(8, fs2)

        # Second field section references dynamic table, so decoder produces section ack
        refute_empty decoder_data2

        # Feed ack back to encoder
        encoder.feed_decoder(decoder_data2)
      end

      def test_insert_count_increment
        encoder = Encoder.new(4096)
        # Build an insert count increment: 00 + 6-bit value of 5
        data = "\x05".b
        encoder.feed_decoder(data)
      end

      def test_stream_cancellation
        encoder = Encoder.new(4096)
        headers = [[":method", "GET"], [":authority", "example.com"]]
        encoder.encode(4, headers)

        # Stream cancellation for stream 4: 01 + 6-bit stream_id
        data = [0x40 | 4].pack("C")
        encoder.feed_decoder(data)
      end

      # --- Zero-capacity table ---

      def test_zero_capacity
        headers = [
          [":method", "GET"],
          [":scheme", "https"],
          [":path", "/"],
        ]
        assert_equal headers, round_trip(headers, capacity: 0)
      end

      def test_zero_capacity_custom_header
        headers = [
          [":method", "GET"],
          ["x-custom", "value"],
        ]
        assert_equal headers, round_trip(headers, capacity: 0)
      end

      # --- Multiple header lists ---

      def test_multiple_header_lists
        encoder = Encoder.new(4096)
        decoder = Decoder.new(4096, 100)

        lists = [
          [[":method", "GET"], [":scheme", "https"], [":path", "/"], [":authority", "example.com"]],
          [[":method", "POST"], [":scheme", "https"], [":path", "/api"], [":authority", "example.com"]],
          [[":method", "GET"], [":scheme", "https"], [":path", "/about"], [":authority", "example.com"]],
        ]

        lists.each_with_index do |headers, i|
          stream_id = (i + 1) * 4
          enc_data, fs = encoder.encode(stream_id, headers)
          decoder.feed_encoder(enc_data) unless enc_data.empty?
          dec_data, decoded = decoder.feed_header(stream_id, fs)
          encoder.feed_decoder(dec_data) unless dec_data.empty?
          assert_equal headers, decoded, "header list #{i} mismatch"
        end
      end

      # --- QIF round-trip ---

      def self.parse_qif(path)
        header_lists = []
        current = []

        File.foreach(path, chomp: true) do |line|
          if line.empty?
            header_lists << current unless current.empty?
            current = []
          elsif !line.start_with?("#")
            name, value = line.split("\t", 2)
            current << [name, value || ""]
          end
        end
        header_lists << current unless current.empty?
        header_lists
      end

      if File.directory?(QIF_DIR)
        Dir.glob(File.join(QIF_DIR, "*.qif")).sort.each do |qif_path|
          qif_name = File.basename(qif_path, ".qif")

          define_method("test_qif_round_trip_#{qif_name}") do
            header_lists = self.class.parse_qif(qif_path)
            next if header_lists.empty?

            encoder = Encoder.new(4096)
            decoder = Decoder.new(4096, 100)

            header_lists.each_with_index do |headers, i|
              stream_id = (i + 1) * 4
              enc_data, fs = encoder.encode(stream_id, headers)
              decoder.feed_encoder(enc_data) unless enc_data.empty?
              decoder_data, decoded = decoder.feed_header(stream_id, fs)
              encoder.feed_decoder(decoder_data) unless decoder_data.empty?
              assert_equal headers, decoded, "#{qif_name}: header list #{i} mismatch"
            end
          end
        end
      end
    end
  end
end
