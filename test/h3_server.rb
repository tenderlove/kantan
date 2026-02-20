# frozen_string_literal: true

# Sample HTTP/3 server using MockQuic transport.
#
# Since there's no real QUIC stack yet, this demonstrates the H3 session
# by wiring a client and server together in-process over MockQuic pipes.
#
# Usage:
#   ruby -Ilib -Itest test/h3_server.rb

require "kantan"
require "kantan/h3"
require_relative "mock_quic"
require "logger"

puts PID: $$

logger = Logger.new($stderr)
logger.level = Logger::DEBUG

# ── Server handler ──────────────────────────────────────────────────

class MyHandler < Kantan::Handler
  def initialize(logger)
    @logger = logger
  end

  def on_request(stream)
    method = stream.headers.assoc(":method")&.last
    path   = stream.headers.assoc(":path")&.last
    @logger.info "#{method} #{path}"

    case path
    when "/"
      body = "Hello from HTTP/3!\n"
      stream.respond([
        [":status", "200"],
        ["content-type", "text/plain"],
      ], body: body)

    when "/echo"
      # Echo back the received data size
      body = "Received #{stream.data_received} bytes\n"
      stream.respond([
        [":status", "200"],
        ["content-type", "text/plain"],
      ], body: body)

    when "/headers"
      # Return all request headers as the response body
      body = stream.headers.map { |n, v| "#{n}: #{v}" }.join("\n") + "\n"
      stream.respond([
        [":status", "200"],
        ["content-type", "text/plain"],
      ], body: body)

    else
      stream.respond([
        [":status", "404"],
        ["content-type", "text/plain"],
      ], body: "Not Found\n")
    end
  end

  def on_close
    @logger.info "connection closed"
  end
end

# ── Client handler (collects responses) ────────────────────────────

class ClientHandler < Kantan::Handler
  attr_reader :queue

  def initialize
    @queue = Thread::Queue.new
  end

  def on_headers(stream) = @queue << [:headers, stream.headers]
  def on_data(stream, chunk) = @queue << [:data, chunk]
  def on_request(stream) = @queue << [:done, stream.id]
end

# ── Wire it up ─────────────────────────────────────────────────────

client_conn, server_conn = MockQuic.pair

server_handler = MyHandler.new(logger)
client_handler = ClientHandler.new

server_session = Kantan::H3::Session.new(server_conn, handler: server_handler)
client_session = Kantan::H3::Session.new(client_conn, handler: client_handler)

# Start server and client
server_thread = Thread.new { server_session.receive }
Thread.new { client_session.connect }

sleep 0.05 # let threads start

# Helper to send a request and print the response
def send_request(session, handler, headers, body: nil)
  session.request(headers, body: body)

  resp_headers = nil
  resp_body = String.new

  loop do
    event = handler.queue.pop
    case event[0]
    when :headers
      resp_headers = event[1]
    when :data
      resp_body << event[1]
    when :done
      break
    end
  end

  status = resp_headers&.assoc(":status")&.last
  puts "HTTP/3 #{status}"
  resp_headers&.each do |name, value|
    next if name.start_with?(":")
    puts "#{name}: #{value}"
  end
  puts
  puts resp_body
  puts "---"
end

# ── Send some requests ─────────────────────────────────────────────

puts "=== GET / ==="
send_request(client_session, client_handler, [
  [":method", "GET"],
  [":path", "/"],
  [":scheme", "https"],
  [":authority", "localhost"],
])

puts "=== GET /headers ==="
send_request(client_session, client_handler, [
  [":method", "GET"],
  [":path", "/headers"],
  [":scheme", "https"],
  [":authority", "localhost"],
  ["user-agent", "kantan-h3/0.1"],
  ["accept", "text/plain"],
])

puts "=== POST /echo ==="
send_request(client_session, client_handler, [
  [":method", "POST"],
  [":path", "/echo"],
  [":scheme", "https"],
  [":authority", "localhost"],
  ["content-type", "application/octet-stream"],
], body: "Hello, HTTP/3 world!" * 10)

puts "=== GET /missing ==="
send_request(client_session, client_handler, [
  [":method", "GET"],
  [":path", "/missing"],
  [":scheme", "https"],
  [":authority", "localhost"],
])

# ── Shut down ──────────────────────────────────────────────────────

client_session.finish
server_thread.join(2)
