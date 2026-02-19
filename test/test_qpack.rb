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
    end
  end
end
