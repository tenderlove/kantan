#!/usr/bin/env ruby
# frozen_string_literal: true

require 'socket'
require_relative '../lib/http2'

# Simple test to verify HTTP/2 communication works
def test_http2_communication
  puts "Testing HTTP/2 implementation..."
  puts "=" * 60

  # Create a socket pair (simulates client-server connection)
  client_sock, server_sock = Socket.pair(:UNIX, :STREAM, 0)

  server_received = []
  client_received = []

  # Server thread
  server_thread = Thread.new do
    http2_server = HTTP2::Server.new(server_sock)

    http2_server.on_headers do |stream, headers|
      puts "[Server] Received headers on stream #{stream.id}:"
      headers.each { |name, value| puts "  #{name}: #{value}" }
      server_received << { type: :headers, stream_id: stream.id, data: headers }
    end

    http2_server.on_data do |stream, data|
      puts "[Server] Received data on stream #{stream.id}: #{data.inspect}"
      server_received << { type: :data, stream_id: stream.id, data: data }
    end

    http2_server.on_stream do |stream|
      puts "[Server] Complete request on stream #{stream.id}"

      # Send response
      response_headers = [
        [":status", "200"],
        ["content-type", "text/plain"],
        ["server", "Pure Ruby HTTP/2 Test"]
      ]

      http2_server.send_headers(stream.id, response_headers)
      http2_server.send_data(stream.id, "Hello from server!", end_stream: true)
    end

    begin
      http2_server.start
    rescue => e
      puts "[Server] Error: #{e.message}"
    end
  end

  # Client thread
  client_thread = Thread.new do
    sleep 0.1  # Give server time to start

    http2_client = HTTP2::Client.new(client_sock)

    http2_client.on_headers do |stream, headers|
      puts "[Client] Received headers on stream #{stream.id}:"
      headers.each { |name, value| puts "  #{name}: #{value}" }
      client_received << { type: :headers, stream_id: stream.id, data: headers }
    end

    http2_client.on_data do |stream, data|
      puts "[Client] Received data on stream #{stream.id}: #{data}"
      client_received << { type: :data, stream_id: stream.id, data: data }
    end

    http2_client.on_stream do |stream|
      puts "[Client] Complete response on stream #{stream.id}"
    end

    begin
      http2_client.start

      # Make a request
      request_headers = [
        [":method", "GET"],
        [":path", "/test"],
        [":scheme", "https"],
        [":authority", "localhost:8080"]
      ]

      stream = http2_client.request(request_headers, body: "Test payload")
      puts "[Client] Sent request on stream #{stream.id}"

      # Run for a bit
      Thread.new { http2_client.run }
      sleep 1

      http2_client.close
    rescue => e
      puts "[Client] Error: #{e.message}"
    end
  end

  # Wait for threads
  client_thread.join
  server_thread.join(2)

  puts "\n" + "=" * 60
  puts "TEST RESULTS"
  puts "=" * 60

  # Verify results
  success = true

  # Check server received headers
  if server_received.any? { |r| r[:type] == :headers && r[:data].any? { |n, v| n == ":method" && v == "GET" } }
    puts "✓ Server received request headers"
  else
    puts "✗ Server did not receive request headers"
    success = false
  end

  # Check server received data
  if server_received.any? { |r| r[:type] == :data && r[:data] == "Test payload" }
    puts "✓ Server received request body"
  else
    puts "✗ Server did not receive request body"
    success = false
  end

  # Check client received headers
  if client_received.any? { |r| r[:type] == :headers && r[:data].any? { |n, v| n == ":status" && v == "200" } }
    puts "✓ Client received response headers"
  else
    puts "✗ Client did not receive response headers"
    success = false
  end

  # Check client received data
  if client_received.any? { |r| r[:type] == :data && r[:data] == "Hello from server!" }
    puts "✓ Client received response body"
  else
    puts "✗ Client did not receive response body"
    success = false
  end

  puts "\n" + "=" * 60
  if success
    puts "ALL TESTS PASSED ✓"
  else
    puts "SOME TESTS FAILED ✗"
  end
  puts "=" * 60

  success
rescue => e
  puts "Test failed with error: #{e.message}"
  puts e.backtrace
  false
ensure
  client_sock&.close unless client_sock&.closed?
  server_sock&.close unless server_sock&.closed?
end

# Test with different socket types
def test_socket_abstraction
  puts "\n\nTesting socket abstraction..."
  puts "=" * 60

  # Test 1: Unix domain socket pair
  puts "\n1. Unix domain socket pair:"
  test_http2_communication

  # Test 2: StringIO (for testing frame encoding/decoding)
  puts "\n2. Frame encoding/decoding:"

  frame = HTTP2::Frame.new(
    type: :headers,
    flags: HTTP2::FLAGS[:end_headers],
    stream_id: 1,
    payload: "test payload"
  )

  binary = frame.to_binary
  puts "  Encoded frame: #{binary.bytesize} bytes"

  # Decode
  require 'stringio'
  io = StringIO.new(binary)
  decoded = HTTP2::Frame.parse(io)

  if decoded && decoded.type == :headers && decoded.stream_id == 1 && decoded.payload == "test payload"
    puts "  ✓ Frame encoding/decoding works"
  else
    puts "  ✗ Frame encoding/decoding failed"
  end

  puts "\n" + "=" * 60
end

# Test HPACK
def test_hpack
  puts "\n\nTesting HPACK implementation..."
  puts "=" * 60

  encoder = HTTP2::HPACK.new
  decoder = HTTP2::HPACK.new

  # Test 1: Static table indexed header
  headers1 = [[":method", "GET"], [":path", "/"]]
  encoded1 = encoder.encode(headers1)
  decoded1 = decoder.decode(encoded1)

  puts "\n1. Static table headers:"
  puts "  Original: #{headers1.inspect}"
  puts "  Encoded: #{encoded1.bytesize} bytes"
  puts "  Decoded: #{decoded1.inspect}"
  puts "  ✓ Match" if decoded1 == headers1

  # Test 2: Custom headers
  headers2 = [["custom-header", "custom-value"], ["another-header", "another-value"]]
  encoded2 = encoder.encode(headers2)
  decoded2 = decoder.decode(encoded2)

  puts "\n2. Custom headers:"
  puts "  Original: #{headers2.inspect}"
  puts "  Encoded: #{encoded2.bytesize} bytes"
  puts "  Decoded: #{decoded2.inspect}"
  puts "  ✓ Match" if decoded2 == headers2

  # Test 3: Full request headers
  headers3 = [
    [":method", "POST"],
    [":path", "/api/users"],
    [":scheme", "https"],
    [":authority", "example.com"],
    ["content-type", "application/json"],
    ["content-length", "42"]
  ]
  encoded3 = encoder.encode(headers3)
  decoded3 = decoder.decode(encoded3)

  puts "\n3. Full request headers:"
  puts "  Original: #{headers3.inspect}"
  puts "  Encoded: #{encoded3.bytesize} bytes"
  puts "  Decoded: #{decoded3.inspect}"
  puts "  ✓ Match" if decoded3 == headers3

  puts "\n" + "=" * 60
end

# Run all tests
if __FILE__ == $0
  puts "HTTP/2 Pure Ruby Implementation Tests"
  puts "=" * 60

  test_hpack
  test_socket_abstraction

  puts "\n\nAll tests completed!"
end
