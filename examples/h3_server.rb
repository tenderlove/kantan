# frozen_string_literal: true

# Sample QUIC/HTTP3 server
#
# Test with:
#   /opt/homebrew/opt/curl/bin/curl --http3 -k -v https://localhost:4433/
#
# Usage:
#   ruby -I lib -I ~/git/openssl/lib examples/h3_server.rb

require "kantan"
require "kantan/h3/poll_session"
require "openssl"
require "socket"

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

class MyHandler < Kantan::Handler
  def on_request stream
    method = stream.headers.assoc(":method")&.last
    path   = stream.headers.assoc(":path")&.last
    $stderr.puts "#{method} #{path}"

    body = "Hello from HTTP/3!\n"
    stream.respond([
      [":status", "200"],
      ["content-type", "text/plain"],
      ["content-length", body.bytesize.to_s],
    ], body: body)
  end
end

udp = UDPSocket.new
udp.bind("0.0.0.0", 4433)

ctx = OpenSSL::SSL::SSLContext.quic(:server)
ctx.cert = cert
ctx.key = key
ctx.alpn_select_cb = ->(protos) { protos.include?("h3") ? "h3" : protos.first }

listener = OpenSSL::SSL::SSLSocket.new_listener(udp, context: ctx)
listener.listen

$stderr.puts "Listening on https://0.0.0.0:4433"

trap("INT") { exit }

loop do
  rfds = [udp]
  wfds = listener.net_write_desired? ? [udp] : []
  IO.select(rfds, wfds, nil, listener.event_timeout)
  listener.handle_events

  puts "waiting for connection"
  conn = nil
  loop do
    conn = listener.accept_connection_nonblock(exception: false)
    break unless conn == :wait_readable
    rfds = listener.net_read_desired? ? [server_udp] : []
    wfds = listener.net_write_desired? ? [server_udp] : []
    IO.select(rfds, wfds, nil, listener.event_timeout)
    listener.handle_events
  end

  $stderr.puts "Accepted connection"
  session = Kantan::H3::PollSession.new(conn, io: udp, handler: MyHandler.new)
  session.run
end
