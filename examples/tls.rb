#!/usr/bin/env ruby
# frozen_string_literal: true

# Example: HTTP/2 server with a self-signed TLS certificate
#
# Usage:
#   ruby examples/tls.rb
#
# Test with:
#   curl -k --http2 https://localhost:8443/

require "kantan"
require "socket"
require "openssl"
require "logger"

logger = Logger.new($stderr)

# Generate a self-signed certificate for testing
key = OpenSSL::PKey::RSA.new(2048)

cert = OpenSSL::X509::Certificate.new
cert.version = 2
cert.serial = 1
cert.subject = OpenSSL::X509::Name.parse("/CN=localhost")
cert.issuer = cert.subject
cert.public_key = key.public_key
cert.not_before = Time.now
cert.not_after = Time.now + 365 * 24 * 60 * 60

ef = OpenSSL::X509::ExtensionFactory.new
ef.subject_certificate = cert
ef.issuer_certificate = cert
cert.add_extension(ef.create_extension("subjectAltName", "DNS:localhost,IP:127.0.0.1"))
cert.sign(key, OpenSSL::Digest::SHA256.new)

# TLS context advertising h2
ctx = OpenSSL::SSL::SSLContext.new
ctx.key = key
ctx.cert = cert
ctx.alpn_protocols = ["h2"]
ctx.alpn_select_cb = ->(protocols) {
  protocols.include?("h2") ? "h2" : nil
}

class MyApp < Kantan::Handler
  def on_request stream
    path = stream.headers.find { |n, _| n == ":path" }&.last
    body = "Hello from Kantan over TLS!\nPath: #{path}\nTime: #{Time.now}\n"
    stream.respond [[":status", "200"], ["content-type", "text/plain"]], body: body
  end
end

tcp_server = TCPServer.new("127.0.0.1", 8443)

logger.info "Listening on https://localhost:8443"
logger.info "Test with: curl -k --http2 https://localhost:8443/"

loop do
  tcp_client = tcp_server.accept
  tcp_client.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1)

  ssl_socket = OpenSSL::SSL::SSLSocket.new(tcp_client, ctx)
  ssl_socket.sync_close = true
  ssl_socket.accept

  logger.info "new connection (ALPN: #{ssl_socket.alpn_protocol})"
  Thread.new(ssl_socket) do |c|
    session = Kantan::Session.new(c, handler: MyApp.new)
    session.receive
    session.join
  rescue => e
    logger.error "#{e.class}: #{e.message}"
  end
rescue OpenSSL::SSL::SSLError => e
  logger.warn "TLS handshake failed: #{e.message}"
end
