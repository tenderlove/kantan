# frozen_string_literal: true

require_relative "helper"
require "openssl"
require "kantan/h3"

begin
  OpenSSL::SSL::SSLContext.new(quic: :client_thread)
  OPENSSL_QUIC_AVAILABLE = true
rescue
  OPENSSL_QUIC_AVAILABLE = false
end

require "kantan/quic/openssl_connection" if OPENSSL_QUIC_AVAILABLE

class TestOpenSSLQUIC < Minitest::Test
  def setup
    skip "OpenSSL QUIC not available" unless OPENSSL_QUIC_AVAILABLE
  end

  def test_openssl_client_get_200
    conn = Kantan::QUIC::OpenSSLConnection.new("www.google.com", 443)
    conn.connect

    handler = TestClientHandler.new
    session = Kantan::H3::Session.new(conn, handler: handler)
    Thread.new { session.connect }
    sleep 0.1

    session.request([
      [":method", "GET"],
      [":path", "/"],
      [":scheme", "https"],
      [":authority", "www.google.com"],
    ])

    headers = nil
    body = "".b
    deadline = Time.now + 10
    loop do
      assert Time.now < deadline, "timed out waiting for response"
      event = handler.queue.pop
      case event[0]
      when :headers then headers = event[1]
      when :data then body << event[1]
      when :done then break
      end
    end

    status = headers&.assoc(":status")&.last
    assert_equal "200", status
    assert body.bytesize > 0
  rescue OpenSSL::SSL::SSLError, SocketError, Errno::ENETUNREACH, Errno::ETIMEDOUT
    skip "Cannot reach www.google.com:443 over QUIC"
  ensure
    conn&.close
  end

  def test_openssl_client_response_headers
    conn = Kantan::QUIC::OpenSSLConnection.new("www.google.com", 443)
    conn.connect

    handler = TestClientHandler.new
    session = Kantan::H3::Session.new(conn, handler: handler)
    Thread.new { session.connect }
    sleep 0.1

    session.request([
      [":method", "GET"],
      [":path", "/"],
      [":scheme", "https"],
      [":authority", "www.google.com"],
    ])

    headers = nil
    deadline = Time.now + 10
    loop do
      assert Time.now < deadline, "timed out waiting for response"
      event = handler.queue.pop
      case event[0]
      when :headers then headers = event[1]
      when :done then break
      end
    end

    assert headers&.assoc("content-type")
  rescue OpenSSL::SSL::SSLError, SocketError, Errno::ENETUNREACH, Errno::ETIMEDOUT
    skip "Cannot reach www.google.com:443 over QUIC"
  ensure
    conn&.close
  end
end
