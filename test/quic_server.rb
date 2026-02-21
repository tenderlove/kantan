# frozen_string_literal: true

# Sample QUIC/HTTP3 server for testing with:
#   /opt/homebrew/opt/curl/bin/curl --http3 -k -v https://localhost:4433/
#
# Usage:
#   fish -c 'chruby ruby-master; bundle exec ruby -Ilib test/quic_server.rb'

require "kantan"
require "kantan/h3/poll_session"
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

udp = UDPSocket.new
udp.bind("0.0.0.0", 4433)

ctx = OpenSSL::SSL::SSLContext.new(quic: :server)
ctx.cert = cert
ctx.key = key
ctx.alpn_select_cb = -> (protos) { protos.include?("h3") ? "h3" : protos.first }

listener = OpenSSL::SSL::SSLSocket.new_listener(udp, context: ctx)
listener.blocking_mode = false
listener.listen

$stderr.puts "Listening on https://0.0.0.0:4433"

trap("INT") { exit }

loop do
  # Wait for a UDP packet to arrive (or a QUIC timer to fire)
  udp.wait_readable(listener.event_timeout)

  # Process the QUIC handshake — the listener reads incoming packets
  # and drives the handshake to completion over multiple round trips.
  listener.handle_events

  # Check if a connection is now ready (handshake complete)
  r = OpenSSL::SSL::SSLSocket.poll(
    [[listener, OpenSSL::SSL::POLL_EVENT_IC]],
    0, OpenSSL::SSL::POLL_FLAG_NO_HANDLE_EVENTS
  )
  next if r.empty?

  # Handshake done — accept the connection
  conn = listener.accept_connection(OpenSSL::SSL::ACCEPT_CONNECTION_NO_BLOCK)
  next unless conn

  # PollSession takes over: conn.handle_events drives I/O from here
  handler = MyHandler.new
  session = Kantan::H3::PollSession.new(conn, io: udp, handler: handler)
  session.run
end
