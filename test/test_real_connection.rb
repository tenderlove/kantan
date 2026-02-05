#!/usr/bin/env ruby
# frozen_string_literal: true

require 'socket'
require_relative '../lib/http2'

puts "Testing real TCP connection..."

# Start server in thread
server_thread = Thread.new do
  server = TCPServer.new(8080)
  client = server.accept

  http2 = HTTP2::Server.new(client)

  http2.on_stream do |stream|
    puts "[Server] Received request"
    headers = [[":status", "200"], ["content-type", "text/plain"]]
    body = "Hello from server!"

    http2.send_headers(stream.id, headers)
    http2.send_data(stream.id, body, end_stream: true)
    puts "[Server] Sent response"
  end

  begin
    http2.start
  rescue => e
    puts "[Server] Error: #{e.message}" unless e.message.include?("closed")
  end
end

sleep 1

# Client
socket = TCPSocket.new('localhost', 8080)
client = HTTP2::Client.new(socket)

response_received = false

client.on_headers do |stream, headers|
  puts "[Client] Response headers:"
  headers.each { |n, v| puts "  #{n}: #{v}" }
end

client.on_data do |stream, data|
  puts "[Client] Response body: #{data}"
  response_received = true
end

client.start

headers = [
  [":method", "GET"],
  [":path", "/"],
  [":scheme", "https"],
  [":authority", "localhost:8080"]
]

client.request(headers)
puts "[Client] Request sent"

Thread.new { client.run }

sleep 2

puts "\nSuccess: #{response_received}"

socket.close rescue nil
server_thread.join(1)
