# frozen_string_literal: true

# Sample QUIC/HTTP3 server for testing with:
#   /opt/homebrew/opt/curl/bin/curl --http3 -k -v https://localhost:4433/
#
# Usage:
#   fish -c 'chruby ruby-master; ruby -I../openssl/lib -Ilib test/quic_server.rb'

require "kantan"
require "kantan/h3"
require "kantan/quic/openssl_server"
require "openssl"

# ── Generate self-signed cert ────────────────────────────────────────

key = OpenSSL::PKey::EC.generate("prime256v1")
cert = OpenSSL::X509::Certificate.new
cert.version = 2
cert.serial = 1
cert.subject = OpenSSL::X509::Name.parse("/CN=localhost")
cert.issuer = cert.subject
cert.public_key = key
cert.not_before = Time.now
cert.not_after = Time.now + 3600

ef = OpenSSL::X509::ExtensionFactory.new
ef.subject_certificate = cert
ef.issuer_certificate = cert
cert.add_extension(ef.create_extension("subjectAltName", "DNS:localhost,IP:127.0.0.1", false))
cert.add_extension(ef.create_extension("basicConstraints", "CA:FALSE", true))

cert.sign(key, "SHA256")

# ── Server handler ───────────────────────────────────────────────────

class MyHandler < Kantan::Handler
  def on_request(stream)
    method = stream.headers.assoc(":method")&.last
    path   = stream.headers.assoc(":path")&.last
    $stderr.puts "#{method} #{path}"

    case path
    when "/"
      body = "Hello from HTTP/3!\n"
      stream.respond([
        [":status", "200"],
        ["content-type", "text/plain"],
        ["content-length", body.bytesize.to_s],
      ], body: body)
    else
      body = "Not Found\n"
      stream.respond([
        [":status", "404"],
        ["content-type", "text/plain"],
        ["content-length", body.bytesize.to_s],
      ], body: body)
    end
  end

  def on_close
    $stderr.puts "H3 connection closed"
  end
end

# ── Start server ─────────────────────────────────────────────────────

server = Kantan::QUIC::OpenSSLServer.new(
  host: "0.0.0.0",
  port: 4433,
  cert: cert,
  key: key,
)

trap("INT") { server.stop; exit }

server.run do |conn|
  handler = MyHandler.new
  session = Kantan::H3::Session.new(conn, handler: handler)
  session.receive
end
