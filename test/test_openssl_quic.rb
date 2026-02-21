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

if OPENSSL_QUIC_AVAILABLE
  require "kantan/quic/openssl_connection"
  require "kantan/quic/openssl_server"
end

OPENSSL_QUIC_SERVER_AVAILABLE = OPENSSL_QUIC_AVAILABLE &&
  OpenSSL::SSL::SSLSocket.respond_to?(:new_listener)

CURL_HTTP3 = "/opt/homebrew/opt/curl/bin/curl"
CURL_HTTP3_AVAILABLE = File.executable?(CURL_HTTP3)

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

class TestOpenSSLQUICServer < Minitest::Test
  def setup
    skip "OpenSSL QUIC server not available" unless OPENSSL_QUIC_SERVER_AVAILABLE
    skip "curl with HTTP/3 not available" unless CURL_HTTP3_AVAILABLE
  end

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

  def setup_server(&handler_block)
    cert, key = generate_cert

    # Find a free port
    sock = UDPSocket.new
    sock.bind("127.0.0.1", 0)
    port = sock.addr[1]
    sock.close

    server = Kantan::QUIC::OpenSSLServer.new(
      host: "127.0.0.1",
      port: port,
      cert: cert,
      key: key,
    )

    Thread.new do
      server.run do |conn|
        handler = TestServerHandler.new
        handler.on_request_block = handler_block
        session = Kantan::H3::Session.new(conn, handler: handler)
        session.receive
      end
    rescue => e
      $stderr.puts "OpenSSL server test error: #{e.message}"
    end

    sleep 0.3
    [port, server]
  end

  def test_openssl_server_curl_get_200
    port, server = setup_server do |stream|
      body = "Hello from OpenSSL HTTP/3!\n"
      stream.respond([
        [":status", "200"],
        ["content-type", "text/plain"],
        ["content-length", body.bytesize.to_s],
      ], body: body)
    end

    output = `#{CURL_HTTP3} --http3 -k -s -o /dev/null -w '%{http_code}' https://127.0.0.1:#{port}/ 2>&1`
    assert_equal "200", output.strip
  ensure
    server&.stop
  end

  def test_openssl_server_curl_response_headers
    port, server = setup_server do |stream|
      body = "ok"
      stream.respond([
        [":status", "200"],
        ["x-custom", "quic-test"],
        ["content-type", "text/plain"],
        ["content-length", body.bytesize.to_s],
      ], body: body)
    end

    output = `#{CURL_HTTP3} --http3 -k -s -D - -o /dev/null https://127.0.0.1:#{port}/ 2>&1`
    assert_match(/x-custom: quic-test/i, output)
  ensure
    server&.stop
  end
end
