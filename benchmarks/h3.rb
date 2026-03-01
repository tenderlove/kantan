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
    stream.respond(
      [[":status", "200"],
       ["content-type", "text/plain"],
       ["content-length", RESPONSE_BODY.bytesize.to_s]],
      body: RESPONSE_BODY
    )
  end
end

Ractor.new(Ractor.current) do |p|
  cert, key = generate_cert

  server_udp = UDPSocket.new
  server_udp.bind("127.0.0.1", 0)
  port = server_udp.addr[1]

  ctx = OpenSSL::SSL::SSLContext.quic(:server)
  ctx.cert = cert
  ctx.key  = key
  ctx.alpn_select_cb = ->(protos) { protos.include?("h3") ? "h3" : protos.first }

  p << port

  listener = OpenSSL::SSL::SSLSocket.new_listener(server_udp, context: ctx)
  listener.listen

  stop_server = false
  handler = BenchServer.new

  until stop_server
    rfds = [server_udp]
    wfds = listener.net_write_desired? ? [server_udp] : []
    IO.select(rfds, wfds, nil, listener.event_timeout || 0.1)
    listener.handle_events

    conn = listener.accept_connection_nonblock(exception: false)
    next if conn == :wait_readable

    session = Kantan::H3::PollSession.new(conn, io: server_udp, handler: handler)
    session.run
  end
end

port = Ractor.receive
p port

# ── Client ────────────────────────────────────────────────────────────────────

class BenchClientHandler < Kantan::Handler
  attr_reader :queue
  def initialize = (@queue = Queue.new)
  def on_request(stream) = @queue << stream.id
end

udp = UDPSocket.new
udp.connect("127.0.0.1", port)

client_ctx = OpenSSL::SSL::SSLContext.quic(:client)
client_ctx.verify_mode    = OpenSSL::SSL::VERIFY_NONE
client_ctx.alpn_protocols = ["h3"]

conn = OpenSSL::SSL::SSLSocket.new(udp, client_ctx)
conn.hostname = "localhost"
conn.connect

handler = BenchClientHandler.new
session = Kantan::H3::PollClientSession.new(conn, io: udp, handler: handler)
session.connect

HEADERS = [
  [":method",    "GET"],
  [":path",      "/"],
  [":scheme",    "https"],
  [":authority", "localhost"],
].freeze

# ── Warmup ────────────────────────────────────────────────────────────────────

print "Warming up (#{WARMUP} requests)... "
WARMUP.times do
  session.request(HEADERS)
  handler.queue.pop
end
puts "done"

# ── Benchmark ─────────────────────────────────────────────────────────────────

print "Running #{REQUESTS} requests... "

latencies = []
t_start = Process.clock_gettime(Process::CLOCK_MONOTONIC)

REQUESTS.times do
  t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  session.request(HEADERS)
  handler.queue.pop
  latencies << Process.clock_gettime(Process::CLOCK_MONOTONIC) - t0
end

elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - t_start
puts "done"

session.finish
udp.close

# ── Results ───────────────────────────────────────────────────────────────────

sorted = latencies.sort
total  = latencies.size
mean   = latencies.sum / total
rps    = total / elapsed

puts
puts "Requests:    #{total}"
puts "Body size:   #{BODY_SIZE} bytes"
puts "Elapsed:     #{"%.3f" % elapsed}s"
puts "Req/s:       #{"%.1f" % rps}"
puts
puts "Latency (ms)"
puts "  min:       #{"%.3f" % (sorted.first                   * 1000)}"
puts "  mean:      #{"%.3f" % (mean                           * 1000)}"
puts "  p50:       #{"%.3f" % (sorted[(total * 0.50).floor]   * 1000)}"
puts "  p95:       #{"%.3f" % (sorted[(total * 0.95).floor]   * 1000)}"
puts "  p99:       #{"%.3f" % (sorted[(total * 0.99).floor]   * 1000)}"
puts "  max:       #{"%.3f" % (sorted.last                    * 1000)}"
