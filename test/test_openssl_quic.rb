# frozen_string_literal: true

require_relative "helper"
require "openssl"
require "kantan/h3/poll_session"

CURL_HTTP3 = "/opt/homebrew/opt/curl/bin/curl"

class TestOpenSSLQUIC < Minitest::Test
  def setup
    skip "curl with HTTP/3 not available at #{CURL_HTTP3}" unless File.executable?(CURL_HTTP3)
  end

  def setup_server(&handler_block)
    cert, key = generate_cert

    udp = UDPSocket.new
    udp.bind("127.0.0.1", 0)
    port = udp.addr[1]

    ctx = OpenSSL::SSL::SSLContext.new(quic: :server)
    ctx.cert = cert
    ctx.key = key
    ctx.alpn_select_cb = -> (protos) { protos.include?("h3") ? "h3" : protos.first }

    listener = OpenSSL::SSL::SSLSocket.new_listener(udp, context: ctx)
    listener.blocking_mode = false
    listener.listen

    Thread.new do
      loop do
        udp.wait_readable(listener.event_timeout)
        listener.handle_events
        r = OpenSSL::SSL::SSLSocket.poll(
          [[listener, OpenSSL::SSL::POLL_EVENT_IC]],
          0, OpenSSL::SSL::POLL_FLAG_NO_HANDLE_EVENTS
        )
        next if r.empty?

        conn = listener.accept_connection(OpenSSL::SSL::ACCEPT_CONNECTION_NO_BLOCK)
        next unless conn

        handler = TestServerHandler.new
        handler.on_request_block = handler_block
        session = Kantan::H3::PollSession.new(conn, io: udp, handler: handler)
        session.run
      end
    rescue IOError, OpenSSL::SSL::SSLError
      # shutdown
    end

    [port, listener, udp]
  end

  def curl(port, *extra_args)
    args = [CURL_HTTP3, "--http3", "-k", "-s", "--retry", "3", "--retry-delay", "0",
            *extra_args, "https://127.0.0.1:#{port}/"]
    IO.popen(args, err: File::NULL, &:read)
  end

  def test_curl_get_200
    port, listener, udp = setup_server do |stream|
      body = "Hello from OpenSSL HTTP/3!\n"
      stream.respond([
        [":status", "200"],
        ["content-type", "text/plain"],
        ["content-length", body.bytesize.to_s],
      ], body: body)
    end

    body = curl(port)
    assert_equal "Hello from OpenSSL HTTP/3!\n", body
  ensure
    listener&.close rescue nil
    udp&.close rescue nil
  end

  def test_curl_response_headers
    port, listener, udp = setup_server do |stream|
      body = "ok"
      stream.respond([
        [":status", "200"],
        ["x-custom", "quic-test"],
        ["content-type", "text/plain"],
        ["content-length", body.bytesize.to_s],
      ], body: body)
    end

    headers = curl(port, "-D", "-", "-o", "/dev/null")
    assert_match(/x-custom: quic-test/i, headers)
  ensure
    listener&.close rescue nil
    udp&.close rescue nil
  end
end
