require "htwo"
require "htwo/rack_handler"
require "socket"
require "openssl"
require "logger"
require "vernier"
require "concurrent"

logger = Logger.new $stderr

# Generate a self-signed certificate
key = OpenSSL::PKey::RSA.new(2048)
cert = OpenSSL::X509::Certificate.new
cert.version = 2
cert.serial = 1
cert.subject = OpenSSL::X509::Name.parse("/CN=localhost")
cert.issuer = cert.subject
cert.public_key = key.public_key
cert.not_before = Time.now
cert.not_after = Time.now + 3600

cert.sign(key, OpenSSL::Digest::SHA256.new)

# TLS context advertising h2
ctx = OpenSSL::SSL::SSLContext.new
ctx.key = key
ctx.cert = cert
ctx.alpn_protocols = ["h2"]
ctx.alpn_select_cb = ->(protocols) {
  protocols.include?("h2") ? "h2" : nil
}

# Simple Rack app
app = ->(env) {
  body = "Hello from HTWO over TLS!\n" \
         "Method: #{env["REQUEST_METHOD"]}\n" \
         "Path: #{env["PATH_INFO"]}\n" \
         "Query: #{env["QUERY_STRING"]}\n"
  [200, { "content-type" => "text/plain" }, [body]]
}

executor = Concurrent::FixedThreadPool.new(5)

handler = HTWO::RackHandler.new(app,
  executor: executor,
  server_name: "localhost",
  server_port: 8443,
  scheme: "https")

tcp_server = TCPServer.new("127.0.0.1", 8443)
ssl_server = OpenSSL::SSL::SSLServer.new(tcp_server, ctx)

logger.info "Listening on https://localhost:8443"
logger.info "Test with: curl -k --http2 https://localhost:8443/"

#while true
Vernier.profile(out: "time_profile.json") do
  client = ssl_server.accept
  client.to_io.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1)

  logger.info "new connection (ALPN: #{client.alpn_protocol})"
  Thread.new(client) do |c|
    session = HTWO::Session.new(c, handler: handler)
    session.receive
    session.join
  rescue => e
    logger.error "#{e.class}: #{e.message}"
  end.join
end
