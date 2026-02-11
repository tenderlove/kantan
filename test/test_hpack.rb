# frozen_string_literal: true

require "minitest/autorun"
require "htwo/hpack"

module HTWO
  class TestHPACK < Minitest::Test
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
  end
end
