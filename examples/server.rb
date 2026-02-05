#!/usr/bin/env ruby
# frozen_string_literal: true

require 'socket'
require_relative '../lib/http2'

# Create a TCP server
server = TCPServer.new(8080)
puts "HTTP/2 server listening on port 8080..."
puts "Waiting for connections..."

loop do
  # Accept a client connection
  client_socket = server.accept
  puts "\nNew client connected from #{client_socket.peeraddr[2]}"

  # Create HTTP/2 server with the socket
  http2_server = HTTP2::Server.new(client_socket)

  # Handle incoming headers
  http2_server.on_headers do |stream, headers|
    puts "\n[Stream #{stream.id}] Received headers:"
    headers.each { |name, value| puts "  #{name}: #{value}" }
  end

  # Handle incoming data
  http2_server.on_data do |stream, data|
    puts "[Stream #{stream.id}] Received data: #{data.inspect}"
  end

  # Handle complete stream (request received)
  http2_server.on_stream do |stream|
    puts "[Stream #{stream.id}] Request complete"

    # Parse the request
    method = stream.received_headers.find { |n, _| n == ":method" }&.last
    path = stream.received_headers.find { |n, _| n == ":path" }&.last

    puts "[Stream #{stream.id}] #{method} #{path}"

    # Generate response based on path
    response_body = case path
    when "/"
      "Hello, HTTP/2! Welcome to the pure Ruby HTTP/2 server."
    when "/json"
      '{"message":"Hello from HTTP/2","timestamp":' + Time.now.to_i.to_s + '}'
    when "/echo"
      "You sent: #{stream.received_data}"
    else
      "404 Not Found"
    end

    # Determine status and content type
    status = path == "/" || path == "/json" || path == "/echo" ? "200" : "404"
    content_type = path == "/json" ? "application/json" : "text/plain"

    # Send response headers
    response_headers = [
      [":status", status],
      ["content-type", content_type],
      ["content-length", response_body.bytesize.to_s],
      ["server", "Pure Ruby HTTP/2"]
    ]

    http2_server.send_headers(stream.id, response_headers)

    # Send response body
    http2_server.send_data(stream.id, response_body, end_stream: true)

    puts "[Stream #{stream.id}] Response sent"
  end

  # Handle connection close
  http2_server.on_close do
    puts "\nClient disconnected"
  end

  # Start the HTTP/2 connection in a new thread
  Thread.new do
    begin
      http2_server.start
    rescue => e
      puts "Error handling client: #{e.message}"
      puts e.backtrace
    end
  end
end
