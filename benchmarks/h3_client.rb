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

# ── Client ────────────────────────────────────────────────────────────────────

class BenchClientHandler < Kantan::Handler
  attr_reader :queue
  def initialize = (@queue = Queue.new)
  def on_request(stream)
    p "got response"
    @queue << stream.id
  end
end

udp = UDPSocket.new
udp.connect("127.0.0.1", 4433)

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
