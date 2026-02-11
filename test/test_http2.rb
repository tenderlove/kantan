# frozen_string_literal: true

require 'minitest/autorun'
require 'socket'
require "htwo/hpack"

class TestHTTP2 < Minitest::Test
  def test_hpack_encoding_decoding
    encoder = HTWO::HPACK.new
    decoder = HTWO::HPACK.new

    headers = [[":method", "GET"], [":path", "/"]]
    encoded = encoder.encode(headers)
    decoded = decoder.decode(encoded)

    assert_equal headers, decoded
  end

  def test_frame_encoding_decoding
    frame = HTWO::Frame.new(
      type: :headers,
      flags: HTWO::FLAGS[:end_headers],
      stream_id: 1,
      payload: "test payload"
    )

    binary = frame.to_binary
    assert_equal 21, binary.bytesize

    io = StringIO.new(binary)
    decoded = HTWO::Frame.parse(io)

    assert_equal :headers, decoded.type
    assert_equal 1, decoded.stream_id
    assert_equal "test payload", decoded.payload
  end

  def test_client_server_communication
    client_sock, server_sock = Socket.pair(:UNIX, :STREAM, 0)

    server_received = []
    client_received = []

    # Server thread
    server_thread = Thread.new do
      http2 = HTWO::Server.new(server_sock)

      http2.on_headers do |stream, headers|
        server_received << { type: :headers, data: headers }
      end

      http2.on_data do |stream, data|
        server_received << { type: :data, data: data }
      end

      http2.on_stream do |stream|
        http2.send_headers(stream.id, [[":status", "200"]])
        http2.send_data(stream.id, "Hello!", end_stream: true)
      end

      http2.start rescue nil
    end

    # Client thread
    client_thread = Thread.new do
      sleep 0.1
      http2 = HTWO::Client.new(client_sock)

      http2.on_headers do |stream, headers|
        client_received << { type: :headers, data: headers }
      end

      http2.on_data do |stream, data|
        client_received << { type: :data, data: data }
      end

      http2.start

      headers = [
        [":method", "GET"],
        [":path", "/"],
        [":scheme", "https"],
        [":authority", "test"]
      ]
      http2.request(headers, body: "test")

      Thread.new { http2.run }
      sleep 1
      http2.close rescue nil
    end

    client_thread.join
    server_thread.join(2)

    # Verify server received request
    assert server_received.any? { |r| r[:type] == :headers }
    assert server_received.any? { |r| r[:type] == :data && r[:data] == "test" }

    # Verify client received response
    assert client_received.any? { |r| r[:type] == :headers }
    assert client_received.any? { |r| r[:type] == :data && r[:data] == "Hello!" }

  ensure
    client_sock&.close rescue nil
    server_sock&.close rescue nil
  end
end
