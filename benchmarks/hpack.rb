# frozen_string_literal: true

require "benchmark/ips"
require "json"
require "kantan/hpack"

# Simple headers (all static table hits)
simple_headers = [
  [":method", "GET"],
  [":scheme", "https"],
  [":path", "/"],
  [":status", "200"],
]

# Typical request headers
request_headers = [
  [":method", "GET"],
  [":scheme", "https"],
  [":authority", "www.example.com"],
  [":path", "/index.html"],
  ["user-agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.8; rv:16.0) Gecko/20100101 Firefox/16.0"],
  ["accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"],
  ["accept-language", "en-US,en;q=0.5"],
  ["accept-encoding", "gzip, deflate"],
  ["cookie", "session=abc123"],
]

# Pre-encode for decode benchmarks
encoder = Kantan::HPACK.new
simple_encoded = encoder.encode(simple_headers)

encoder = Kantan::HPACK.new
request_encoded = encoder.encode(request_headers)

# Load a real-world story for multi-request benchmarks
story_path = File.join(File.dirname(__FILE__), "../test/fixtures/hpack-test-case/nghttp2/story_03.json")
story = JSON.load(File.read(story_path))
story_wires = story["cases"].map { |c| [c["wire"]].pack("H*") }
story_headers = story["cases"].map { |c| c["headers"].map { _1.to_a.first } }

puts "== Encode =="
Benchmark.ips do |x|
  x.report("encode: simple (4 static hits)") do
    Kantan::HPACK.new.encode(simple_headers)
  end

  x.report("encode: request (9 headers)") do
    Kantan::HPACK.new.encode(request_headers)
  end

  x.report("encode: story (10 requests)") do
    enc = Kantan::HPACK.new
    story_headers.each { |h| enc.encode(h) }
  end

  x.compare!
end

puts
puts "== Decode =="
Benchmark.ips do |x|
  x.report("decode: simple (4 headers)") do
    Kantan::HPACK.new.decode(simple_encoded)
  end

  x.report("decode: request (9 headers)") do
    Kantan::HPACK.new.decode(request_encoded)
  end

  x.report("decode: story (10 requests)") do
    dec = Kantan::HPACK.new
    story_wires.each { |w| dec.decode(w) }
  end

  x.compare!
end

puts
puts "== Round-trip =="
Benchmark.ips do |x|
  x.report("round-trip: request headers") do
    enc = Kantan::HPACK.new
    dec = Kantan::HPACK.new
    encoded = enc.encode(request_headers)
    dec.decode(encoded)
  end

  x.report("round-trip: full story") do
    enc = Kantan::HPACK.new
    dec = Kantan::HPACK.new
    story_headers.each do |h|
      encoded = enc.encode(h)
      dec.decode(encoded)
    end
  end

  x.compare!
end
