# frozen_string_literal: true

# Example: fetch a page over HTTP/3 (QUIC).
#
# Usage:
#   fish -c 'chruby ruby-master; ruby -I../openssl/lib -Ilib examples/quic_fetch.rb [host] [port]'
#
# Defaults to localhost:4433.

require "kantan"
require "kantan/h3"
require "kantan/h3/poll_client_session"
require "openssl"
require "socket"

class ResponseHandler < Kantan::Handler
  def initialize
    @responses = {}
    @done = Thread::Queue.new
  end

  def on_headers(stream)
    @responses[stream.id] ||= { headers: stream.headers, body: +"" }
    @responses[stream.id][:headers] = stream.headers
  end

  def on_data(stream, chunk)
    @responses[stream.id] ||= { headers: [], body: +"" }
    @responses[stream.id][:body] << chunk
  end

  def on_request(stream)
    @done << stream.id
  end

  def on_close
    @done << nil
  end

  def wait_for_stream(stream_id)
    loop do
      id = @done.pop
      return @responses[stream_id] if id == stream_id || id.nil?
    end
  end
end

host = ARGV[0] || "localhost"
port = (ARGV[1] || 4433).to_i

sock = UDPSocket.new
sock.connect(host, port)

ctx = OpenSSL::SSL::SSLContext.quic(:client)
ctx.verify_mode = OpenSSL::SSL::VERIFY_PEER
ctx.cert_store = OpenSSL::X509::Store.new.tap(&:set_default_paths)
ctx.alpn_protocols = ["h3"]

conn = OpenSSL::SSL::SSLSocket.new(sock, ctx)
conn.hostname = host
conn.connect

handler = ResponseHandler.new
session = Kantan::H3::PollClientSession.new(conn, io: sock, handler: handler)
session.connect

stream_id = session.request([
  [":method",    "GET"],
  [":path",      "/"],
  [":scheme",    "https"],
  [":authority", host],
  ["user-agent", "kantan-quic/1.0"],
  ["accept",     "*/*"],
])

response = handler.wait_for_stream(stream_id)

status = response[:headers].find { |n, _| n == ":status" }&.last
puts "Status: #{status}"
puts
response[:headers].each { |name, value| puts "#{name}: #{value}" }
puts
puts response[:body]

session.finish
