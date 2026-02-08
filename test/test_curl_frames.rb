# frozen_string_literal: true

require "minitest/autorun"
require "socket"
require "stringio"
require "http2"

module HTWO
  class TestCurlFrames < Minitest::Test
    def test_connection_preface
      preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".b
      assert_equal HTTP2::CONNECTION_PREFACE, preface
    end

    def test_curl_settings_frame
      # Real curl SETTINGS frame values
      settings_payload = [
        0x00, 0x03, 0x00, 0x00, 0x00, 0x64,  # max_concurrent_streams = 100
        0x00, 0x04, 0x00, 0x9f, 0xff, 0xff,  # initial_window_size = 10485760
        0x00, 0x02, 0x00, 0x00, 0x00, 0x00   # enable_push = 0
      ].pack("C*")

      pos = 0
      settings = {}
      while pos < settings_payload.bytesize
        id = settings_payload.unpack1("n", offset: pos)
        value = settings_payload.unpack1("N", offset: pos + 2)
        setting_name = HTTP2::SETTINGS.key(id)
        settings[setting_name] = value if setting_name
        pos += 6
      end

      assert_equal 0, settings[:enable_push]
      assert_equal 100, settings[:max_concurrent_streams]
    end

    def test_huffman_decoding
      # Real curl HEADERS frame with Huffman encoding
      huffman_encoded = [
        0x82,        # Indexed: :method GET
        0x86,        # Indexed: :scheme http
        0x84,        # Indexed: :path /
        0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff
      ].pack("C*")

      decoder = HTTP2::HPACK.new
      headers = decoder.decode(huffman_encoded)

      method = headers.assoc(":method").last
      path = headers.assoc(":path").last

      assert_equal "GET", method
      assert_equal "/", path
    end

    def test_server_enable_push_setting
      assert_equal 0, HTTP2::DEFAULT_SETTINGS[:enable_push]
    end
  end
end
