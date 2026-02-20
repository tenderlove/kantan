require "socket"
require "openssl"
require "kantan"

class ResponseHandler < Kantan::Handler
  def initialize
    @responses = {}
    @done = Thread::Queue.new
  end

  def on_headers stream
    @responses[stream.id] ||= { headers: stream.headers, body: +"" }
    @responses[stream.id][:headers] = stream.headers
  end

  def on_data stream, chunk
    @responses[stream.id] ||= { headers: [], body: +"" }
    @responses[stream.id][:body] << chunk
  end

  def on_request stream
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

host = "www.google.com"
port = 443

tcp = TCPSocket.new(host, port)

ctx = OpenSSL::SSL::SSLContext.new
ctx.alpn_protocols = ["h2"]
ctx.verify_mode = OpenSSL::SSL::VERIFY_PEER
ctx.cert_store = OpenSSL::X509::Store.new.tap(&:set_default_paths)

ssl = OpenSSL::SSL::SSLSocket.new(tcp, ctx)
ssl.hostname = host
ssl.sync_close = true
ssl.connect

unless ssl.alpn_protocol == "h2"
  abort "Server did not negotiate HTTP/2 (got: #{ssl.alpn_protocol.inspect})"
end

handler = ResponseHandler.new
session = Kantan::H2::Session.new(ssl, handler: handler)
session.connect

stream_id = session.request([
  [":method",    "GET"],
  [":path",      "/"],
  [":scheme",    "https"],
  [":authority", host],
  ["user-agent", "kantan-demo/1.0"],
  ["accept",     "*/*"],
])

response = handler.wait_for_stream(stream_id)

status = response[:headers].find { |n, _| n == ":status" }&.last
puts "Status: #{status}"
puts
response[:headers].each { |name, value| puts "#{name}: #{value}" }
puts
puts response[:body].force_encoding("UTF-8")

session.finish
