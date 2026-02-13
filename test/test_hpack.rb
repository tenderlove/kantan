# frozen_string_literal: true

require "minitest/autorun"
require "htwo/hpack"
require "json"

module HTWO
  class TestHPACK < Minitest::Test
    BASE = File.expand_path File.join(File.dirname(__FILE__), "fixtures/hpack-test-case/nghttp2/")
    Dir.entries(BASE).map { |entry|
      next if File.directory?(File.join(BASE, entry))
      File.join(BASE, entry)
    }.compact.sort.each { |entry|
      define_method("test_#{File.basename(entry, ".json")}") do
        decoder = HTWO::HPACK.new
        encoder = HTWO::HPACK.new
        round_trip_decoder = HTWO::HPACK.new
        tests = JSON.load File.read entry
        tests["cases"].each do |x|
          headers = x["headers"].map { _1.to_a.first }
          assert_equal headers, decoder.decode([x["wire"]].pack("H*"))
          encoded = encoder.encode(headers)
          assert_equal x["wire"].b, encoded.unpack("H*").first.b
          assert_equal headers, round_trip_decoder.decode(encoded)
        end
      end
    }

    def test_hpack_encoding_decoding
      encoder = HTWO::HPACK.new
      decoder = HTWO::HPACK.new

      headers = [[":method", "GET"], [":path", "/"]]
      encoded = encoder.encode(headers)
      decoded = decoder.decode(encoded)

      assert_equal headers, decoded
    end

    # With indexing
    def test_hpack_incremental_index
      encoder = HTWO::HPACK.new
      decoder = HTWO::HPACK.new
      headers = [["content-language", "English"]]
      encoded = encoder.encode(headers)

      assert_equal "\x5b\x86\xc1\x54\xd4\x19\x13\xff".b, encoded
      decoded = decoder.decode(encoded)

      assert_equal headers, decoded
    end

    # With indexing twice
    def test_hpack_incremental_index_reuse
      encoder = HTWO::HPACK.new
      decoder = HTWO::HPACK.new
      headers = [["content-language", "English"]]
      encoded = encoder.encode(headers)

      assert_equal "\x5b\x86\xc1\x54\xd4\x19\x13\xff".b, encoded
      decoded = decoder.decode(encoded)

      assert_equal headers, decoded

      encoded = encoder.encode(headers)
      assert_equal 1, encoded.bytesize
    end

    def test_truncated_header_block_name
      decoder = HTWO::HPACK.new
      # Literal header with incremental indexing, new name (0x40), then truncated
      assert_raises HTWO::Errors::CompressionError do
        decoder.decode "\x40".b
      end
    end

    def test_truncated_header_block_value
      decoder = HTWO::HPACK.new
      # Literal header with incremental indexing, indexed name (:path), then truncated before value
      assert_raises HTWO::Errors::CompressionError do
        decoder.decode "\x44".b
      end
    end

    def test_truncated_header_block_literal_name
      decoder = HTWO::HPACK.new
      # Without indexing (0x00), new name, name length 3, "foo", then truncated before value
      assert_raises HTWO::Errors::CompressionError do
        decoder.decode "\x00\x03foo".b
      end
    end

    def test_truncated_header_block_without_indexing
      decoder = HTWO::HPACK.new
      # Without indexing (0x00), new name, then truncated
      assert_raises HTWO::Errors::CompressionError do
        decoder.decode "\x00".b
      end
    end

    def test_max_list_size_exceeded
      encoder = HTWO::HPACK.new
      decoder = HTWO::HPACK.new

      # Each header entry costs name.bytesize + value.bytesize + 32
      # ":method" (7) + "GET" (3) + 32 = 42
      # ":path" (5) + "/" (1) + 32 = 38
      # Total = 80
      headers = [[":method", "GET"], [":path", "/"]]
      encoded = encoder.encode(headers)

      # Limit below total size should raise
      assert_raises HTWO::Errors::CompressionError do
        decoder.decode encoded, max_list_size: 50
      end

      # Limit at or above total size should succeed
      decoder2 = HTWO::HPACK.new
      assert_equal headers, decoder2.decode(encoded, max_list_size: 80)
    end
  end
end
