# frozen_string_literal: true

# HTTP/3 benchmark — sequential requests on a single QUIC connection
#
# Usage:
#   ruby -I lib:~/git/openssl/lib benchmarks/h3.rb
#
# Environment:
#   REQUESTS     requests to measure (default: 500)
#   WARMUP       warmup requests before measuring (default: 10)
#   BODY_SIZE    response body size in bytes (default: 64)

require "kantan"
require "kantan/h3/poll_session"
require "kantan/h3/poll_client_session"
require "openssl"
require "socket"

$stdout.sync = true

REQUESTS  = (ENV["REQUESTS"]  || 1000).to_i
WARMUP    = (ENV["WARMUP"]    || 100).to_i
BODY_SIZE = (ENV["BODY_SIZE"] || 64).to_i

# ── Cert ──────────────────────────────────────────────────────────────────────

def generate_cert
  key  = OpenSSL::PKey::EC.generate("prime256v1")
  cert = OpenSSL::X509::Certificate.new
  cert.version    = 2
  cert.serial     = 1
  cert.subject    = OpenSSL::X509::Name.parse("/CN=localhost")
  cert.issuer     = cert.subject
  cert.public_key = key
  cert.not_before = Time.now
  cert.not_after  = Time.now + 3600
  ef = OpenSSL::X509::ExtensionFactory.new
  ef.subject_certificate = cert
  ef.issuer_certificate  = cert
  cert.add_extension(ef.create_extension("subjectAltName", "DNS:localhost,IP:127.0.0.1", false))
  cert.add_extension(ef.create_extension("basicConstraints", "CA:FALSE", true))
  cert.sign(key, "SHA256")
  [cert, key]
end

# ── Server ────────────────────────────────────────────────────────────────────

RESPONSE_BODY = ("x" * BODY_SIZE).freeze

class BenchServer < Kantan::Handler
  def on_request stream
    puts "responding"
    stream.respond(
      [[":status", "200"],
        ["content-type", "text/plain"],
        ["content-length", RESPONSE_BODY.bytesize.to_s]],
    body: RESPONSE_BODY
    )
  end
end

cert, key = generate_cert

server_udp = UDPSocket.new
server_udp.bind("127.0.0.1", 4433)

ctx = OpenSSL::SSL::SSLContext.quic(:server)
ctx.cert = cert
ctx.key  = key
ctx.alpn_select_cb = ->(protos) { protos.include?("h3") ? "h3" : protos.first }

listener = OpenSSL::SSL::SSLSocket.new_listener(server_udp, context: ctx)
listener.listen

stop_server = false
handler = BenchServer.new

until stop_server
  #rfds = [server_udp]
  #wfds = listener.net_write_desired? ? [server_udp] : []
  #IO.select(rfds, wfds, nil, listener.event_timeout)
  #listener.handle_events

  #conn = listener.accept_connection_nonblock(exception: false)
  #next if conn == :wait_readable
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

  session = Kantan::H3::PollSession.new(conn, io: server_udp, handler: handler)
  session.run
end
