#!/usr/bin/env ruby
# frozen_string_literal: true

require 'socket'
require_relative '../lib/http2'

# Connect to the server
socket = TCPSocket.new('localhost', 8080)
puts "Connected to localhost:8080"

# Create HTTP/2 client with the socket
http2_client = HTWO::Client.new(socket)

# Track responses
responses = {}

# Handle incoming headers
http2_client.on_headers do |stream, headers|
  puts "\n[Stream #{stream.id}] Response headers:"
  headers.each { |name, value| puts "  #{name}: #{value}" }
  responses[stream.id] ||= { headers: [], data: "" }
  responses[stream.id][:headers] = headers
end

# Handle incoming data
http2_client.on_data do |stream, data|
  puts "[Stream #{stream.id}] Response data: #{data}"
  responses[stream.id] ||= { headers: [], data: "" }
  responses[stream.id][:data] << data
end

# Handle complete stream
http2_client.on_stream do |stream|
  puts "[Stream #{stream.id}] Response complete"
end

# Handle connection close
http2_client.on_close do
  puts "\nConnection closed"
end

# Start the connection
http2_client.start
puts "HTTP/2 connection established"

# Make multiple requests in parallel (multiplexing)
puts "\n--- Making GET request to / ---"
stream1 = http2_client.request([
  [":method", "GET"],
  [":path", "/"],
  [":scheme", "https"],
  [":authority", "localhost:8080"]
])

puts "\n--- Making GET request to /json ---"
stream2 = http2_client.request([
  [":method", "GET"],
  [":path", "/json"],
  [":scheme", "https"],
  [":authority", "localhost:8080"]
])

puts "\n--- Making POST request to /echo ---"
stream3 = http2_client.request([
  [":method", "POST"],
  [":path", "/echo"],
  [":scheme", "https"],
  [":authority", "localhost:8080"],
  ["content-type", "text/plain"]
], body: "Hello from the client!")

puts "\nWaiting for responses..."

# Run the event loop in a separate thread
event_thread = Thread.new do
  http2_client.run
end

# Wait a bit for responses
sleep 2

# Display summary
puts "\n" + "=" * 60
puts "SUMMARY"
puts "=" * 60

responses.each do |stream_id, response|
  status = response[:headers].find { |n, _| n == ":status" }&.last
  puts "\nStream #{stream_id}:"
  puts "  Status: #{status}"
  puts "  Body: #{response[:data]}"
end

# Close the connection
http2_client.close
event_thread.join(1)

puts "\nClient closed"
