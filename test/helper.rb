# frozen_string_literal: true

require 'minitest/autorun'
require 'socket'
require "kantan"

def generate_cert
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
  [cert, key]
end

class TestClientHandler < Kantan::Handler
  attr_reader :queue

  def initialize
    @queue = Queue.new
  end

  def on_headers(stream) = @queue << [:headers, stream.headers]
  def on_data(stream, chunk) = @queue << [:data, chunk]
  def on_request(stream) = @queue << [:done, stream.id]
end

class TestServerHandler < Kantan::Handler
  attr_accessor :on_request_block

  def on_request(stream)
    @on_request_block&.call(stream)
  end
end

class OKServer < Kantan::Handler
  def on_request stream
    stream.respond([[":status", "200"], ["content-type", "text/plain"]], body: "OK")
  end
end

class ByteCountServer < Kantan::Handler
  def on_request stream
    stream.respond([[":status", "200"]], body: stream.data_received.to_s)
  end
end

class PathEchoServer < Kantan::Handler
  def on_request stream
    path = stream.headers.find { |n, _| n == ":path" }[1]
    stream.respond([[":status", "200"]], body: "response for #{path}")
  end
end

class HeadersOnlyServer < Kantan::Handler
  def on_request stream
    stream.respond([[":status", "200"], ["content-type", "text/plain"]])
  end
end
