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
        tests = JSON.load File.read entry
        tests["cases"].each do |x|
          assert_equal x["headers"].map { _1.to_a.first }, decoder.decode([x["wire"]].pack("H*"))
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

      assert_equal "[\aEnglish".b, encoded
      decoded = decoder.decode(encoded)

      assert_equal headers, decoded
    end

    # With indexing twice
    def xtest_hpack_incremental_index
      encoder = HTWO::HPACK.new
      decoder = HTWO::HPACK.new
      headers = [["content-language", "English"]]
      encoded = encoder.encode(headers)

      assert_equal "[\aEnglish".b, encoded
      decoded = decoder.decode(encoded)

      assert_equal headers, decoded

      encoded = encoder.encode(headers)
      assert_equal 1, encoded.bytesize
    end
  end
end
