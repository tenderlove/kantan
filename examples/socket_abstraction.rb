#!/usr/bin/env ruby
# frozen_string_literal: true

require 'socket'
require 'stringio'
require_relative '../lib/http2'

# This example demonstrates how the HTTP/2 implementation is abstracted
# from the underlying transport. You can pass ANY IO-like object that
# supports read() and write() methods.

puts "HTTP/2 Socket Abstraction Examples"
puts "=" * 60

# Example 1: Unix Domain Socket Pair
puts "\n1. Unix Domain Socket Pair (for testing)"
puts "-" * 60

client_sock, server_sock = Socket.pair(:UNIX, :STREAM, 0)

server_thread = Thread.new do
  http2 = HTTP2::Server.new(server_sock)
  http2.on_stream do |stream|
    http2.send_headers(stream.id, [[":status", "200"]])
    http2.send_data(stream.id, "Response from Unix socket", end_stream: true)
  end
  http2.start
end

client_thread = Thread.new do
  sleep 0.1
  http2 = HTTP2::Client.new(client_sock)
  http2.on_data { |stream, data| puts "  Received: #{data}" }
  http2.start
  http2.request([[":method", "GET"], [":path", "/"], [":scheme", "https"], [":authority", "test"]])
  Thread.new { http2.run }
  sleep 0.5
  http2.close
end

client_thread.join
server_thread.join(1)

client_sock.close rescue nil
server_sock.close rescue nil

# Example 2: TCP Socket
puts "\n2. TCP Socket (standard network connection)"
puts "-" * 60
puts "  Server: HTTP2::Server.new(tcp_socket)"
puts "  Client: HTTP2::Client.new(TCPSocket.new('host', port))"

# Example 3: SSL/TLS Socket
puts "\n3. SSL/TLS Socket (secure connection)"
puts "-" * 60
puts "  Server: HTTP2::Server.new(ssl_socket)"
puts "  Client: HTTP2::Client.new(OpenSSL::SSL::SSLSocket.new(...))"
puts "  See tls_example.rb for full implementation"

# Example 4: Pipe (for IPC)
puts "\n4. Pipe (inter-process communication)"
puts "-" * 60

reader, writer = IO.pipe
writer.binmode
reader.binmode

fork_pid = fork do
  writer.close
  http2 = HTTP2::Server.new(reader)
  http2.on_stream do |stream|
    http2.send_headers(stream.id, [[":status", "200"]])
    http2.send_data(stream.id, "Response from pipe", end_stream: true)
  end
  http2.start
  exit
end

reader.close

http2_client = HTTP2::Client.new(writer)
response_data = nil

http2_client.on_data do |stream, data|
  response_data = data
  puts "  Received: #{data}"
end

http2_client.start
http2_client.request([[":method", "GET"], [":path", "/"], [":scheme", "https"], [":authority", "test"]])

Thread.new { http2_client.run }
sleep 0.5

Process.wait(fork_pid)
writer.close rescue nil

# Example 5: Frame-level abstraction (using StringIO for testing)
puts "\n5. Frame-level testing (using StringIO)"
puts "-" * 60

# Create a frame
frame = HTTP2::Frame.new(
  type: :settings,
  flags: 0,
  stream_id: 0,
  payload: ""
)

# Encode to binary
binary = frame.to_binary
puts "  Frame encoded: #{binary.bytesize} bytes"

# Decode from binary using StringIO
io = StringIO.new(binary)
decoded_frame = HTTP2::Frame.parse(io)
puts "  Frame decoded: type=#{decoded_frame.type}, stream_id=#{decoded_frame.stream_id}"

puts "\n" + "=" * 60
puts "Key Takeaway: The HTTP/2 implementation works with ANY"
puts "IO-like object (Socket, TCPSocket, SSLSocket, Pipe, etc.)"
puts "as long as it supports read() and write() methods."
puts "=" * 60
