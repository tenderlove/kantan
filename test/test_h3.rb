# frozen_string_literal: true

require "helper"
require "openssl"
require "kantan/h3"

OPENSSL_QUIC = OpenSSL::SSL::SSLContext.respond_to?(:quic)

class TestH3 < Minitest::Test
  # ── Varint ───────────────────────────────────────────────────────────

  def test_varint_1_byte
    [0, 1, 37, 63].each do |v|
      buf = "".b
      Kantan::H3::Varint.encode(buf, v)
      assert_equal 1, buf.bytesize, "1-byte encoding for #{v}"
      val, pos = Kantan::H3::Varint.decode(buf)
      assert_equal v, val
      assert_equal 1, pos
    end
  end

  def test_varint_2_byte
    [64, 255, 0x3FFF].each do |v|
      buf = "".b
      Kantan::H3::Varint.encode(buf, v)
      assert_equal 2, buf.bytesize, "2-byte encoding for #{v}"
      val, pos = Kantan::H3::Varint.decode(buf)
      assert_equal v, val
      assert_equal 2, pos
    end
  end

  def test_varint_4_byte
    [0x4000, 0x3FFFFFFF].each do |v|
      buf = "".b
      Kantan::H3::Varint.encode(buf, v)
      assert_equal 4, buf.bytesize, "4-byte encoding for #{v}"
      val, pos = Kantan::H3::Varint.decode(buf)
      assert_equal v, val
      assert_equal 4, pos
    end
  end

  def test_varint_8_byte
    [0x40000000, 0x3FFFFFFFFFFFFFFF].each do |v|
      buf = "".b
      Kantan::H3::Varint.encode(buf, v)
      assert_equal 8, buf.bytesize, "8-byte encoding for #{v}"
      val, pos = Kantan::H3::Varint.decode(buf)
      assert_equal v, val
      assert_equal 8, pos
    end
  end

  def test_varint_boundary_values
    [[63, 1], [64, 2], [0x3FFF, 2], [0x4000, 4], [0x3FFFFFFF, 4], [0x40000000, 8]].each do |v, expected_size|
      buf = "".b
      Kantan::H3::Varint.encode(buf, v)
      assert_equal expected_size, buf.bytesize, "boundary #{v}"
      val, _ = Kantan::H3::Varint.decode(buf)
      assert_equal v, val
    end
  end

  # ── Frames ──────────────────────────────────────────────────────────

  def test_frame_reader_data
    buf = "".b
    payload = "hello world".b
    Kantan::H3::Frames.write(buf, Kantan::H3::Frames::DATA, payload)

    reader = Kantan::H3::Frames::FrameReader.new
    reader.feed(buf)
    type, data = reader.next_frame
    assert_equal Kantan::H3::Frames::DATA, type
    assert_equal payload, data
    assert_nil reader.next_frame
  end

  def test_frame_reader_headers
    buf = "".b
    payload = "\x00\x00\xd1".b
    Kantan::H3::Frames.write(buf, Kantan::H3::Frames::HEADERS, payload)

    reader = Kantan::H3::Frames::FrameReader.new
    reader.feed(buf)
    type, data = reader.next_frame
    assert_equal Kantan::H3::Frames::HEADERS, type
    assert_equal payload, data
  end

  def test_frame_reader_incomplete
    reader = Kantan::H3::Frames::FrameReader.new
    assert_nil reader.next_frame

    # Feed partial frame (type + length but no payload)
    buf = "".b
    Kantan::H3::Varint.encode(buf, Kantan::H3::Frames::DATA)
    Kantan::H3::Varint.encode(buf, 5)
    reader.feed(buf)
    assert_nil reader.next_frame

    # Now feed the payload
    reader.feed("hello".b)
    type, data = reader.next_frame
    assert_equal Kantan::H3::Frames::DATA, type
    assert_equal "hello".b, data
  end

  def test_frames_settings_encode_decode
    settings = {
      Kantan::H3::Frames::QPACK_MAX_TABLE_CAPACITY => 4096,
      Kantan::H3::Frames::QPACK_BLOCKED_STREAMS => 100,
    }
    payload = Kantan::H3::Frames.encode_settings(settings)
    decoded = Kantan::H3::Frames.decode_settings(payload)
    assert_equal settings, decoded
  end

  # ── Session (integration with real OpenSSL QUIC) ───────────────────

  def setup_h3_pair server_handler
    channel = Ractor::Port.new

    server_ractor = Ractor.new(server_handler, channel) do |server_handler, channel|
      cert, key = generate_cert

      udp = UDPSocket.new
      udp.bind("127.0.0.1", 0)
      port = udp.addr[1]

      channel << port

      ctx = OpenSSL::SSL::SSLContext.quic(:server)
      ctx.cert = cert
      ctx.key = key
      ctx.alpn_select_cb = ->(protos) { protos.include?("h3") ? "h3" : protos.first }

      listener = OpenSSL::SSL::SSLSocket.new_listener(udp, context: ctx)
      listener.blocking_mode = false
      listener.listen

      running = true

      Thread.new {
        Ractor.receive
        running = false
        listener.close rescue nil
        udp.close rescue nil
      }

      while running
        udp.wait_readable(listener.event_timeout)
        listener.handle_events
        r = OpenSSL::SSL::SSLSocket.poll(
          [[listener, OpenSSL::SSL::POLL_EVENT_IC]],
          0, OpenSSL::SSL::POLL_FLAG_NO_HANDLE_EVENTS
        )
        next if r.empty?

        conn = listener.accept_connection(OpenSSL::SSL::ACCEPT_CONNECTION_NO_BLOCK)
        next unless conn

        session = Kantan::H3::PollSession.new(conn, io: udp, handler: server_handler)
        session.run
      end
    rescue IOError, OpenSSL::SSL::SSLError
      # shutdown
    end

    port = channel.receive

    client_udp = UDPSocket.new
    client_udp.connect("127.0.0.1", port)

    client_ctx = OpenSSL::SSL::SSLContext.quic(:client)
    client_ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE
    client_ctx.alpn_protocols = ["h3"]

    client_conn = OpenSSL::SSL::SSLSocket.new(client_udp, client_ctx)
    client_conn.hostname = "localhost"

    client_conn.connect
    client_conn.default_stream_mode = :none
    client_conn.blocking_mode = false

    client_handler = TestClientHandler.new
    client_session = Kantan::H3::PollClientSession.new(client_conn, io: client_udp, handler: client_handler)
    client_thread = Thread.new { client_session.run }

    [client_session, client_handler, client_thread, client_udp, server_ractor]
  end

  def test_simple_get
    skip "OpenSSL QUIC not available" unless OPENSSL_QUIC
    server_handler = OKServer.new

    client_session, client_handler, client_thread, client_udp, server = setup_h3_pair(server_handler)

    stream_id = client_session.request([
      [":method", "GET"],
      [":path", "/"],
      [":scheme", "https"],
      [":authority", "localhost"],
    ])

    event = client_handler.queue.pop
    assert_equal :headers, event[0]
    headers = event[1]
    status = headers.find { |n, _| n == ":status" }
    assert_equal "200", status[1]

    event = client_handler.queue.pop
    assert_equal :data, event[0]
    assert_equal "OK", event[1]

    event = client_handler.queue.pop
    assert_equal :done, event[0]
    assert_equal stream_id, event[1]

    client_session.finish
    client_thread.join(5)
    client_udp.close
    server << :shutdown
    server.value
  ensure
  end

  def test_post_with_body
    skip "OpenSSL QUIC not available" unless OPENSSL_QUIC
    client_session, client_handler, client_thread, client_udp, server =
      setup_h3_pair(ByteCountServer.new)

    body = "name=test&value=123"
    client_session.request([
      [":method", "POST"],
      [":path", "/submit"],
      [":scheme", "https"],
      [":authority", "localhost"],
      ["content-type", "application/x-www-form-urlencoded"],
    ], body: body)

    event = client_handler.queue.pop
    assert_equal :headers, event[0]

    event = client_handler.queue.pop
    assert_equal :data, event[0]
    assert_equal body.bytesize, event[1].to_i

    event = client_handler.queue.pop
    assert_equal :done, event[0]

    client_session.finish
    client_thread.join(5)
    client_udp.close
    server << :shutdown
    server.value
  ensure
  end

  def test_multiple_requests
    skip "OpenSSL QUIC not available" unless OPENSSL_QUIC
    client_session, client_handler, client_thread, client_udp, server =
      setup_h3_pair(PathEchoServer.new)

    # First request
    client_session.request([
      [":method", "GET"], [":path", "/first"],
      [":scheme", "https"], [":authority", "localhost"],
    ])

    3.times { client_handler.queue.pop }

    # Second request
    client_session.request([
      [":method", "GET"], [":path", "/second"],
      [":scheme", "https"], [":authority", "localhost"],
    ])

    event = client_handler.queue.pop
    assert_equal :headers, event[0]
    event = client_handler.queue.pop
    assert_equal :data, event[0]
    assert_includes event[1], "/second"
    event = client_handler.queue.pop
    assert_equal :done, event[0]

    client_session.finish
    client_thread.join(5)
    client_udp.close
    server << :shutdown
    server.value
  ensure
  end

  def test_settings_exchange
    skip "OpenSSL QUIC not available" unless OPENSSL_QUIC
    client_session, client_handler, client_thread, client_udp, server =
      setup_h3_pair(OKServer.new)

    client_session.request([
      [":method", "GET"], [":path", "/"],
      [":scheme", "https"], [":authority", "localhost"],
    ])
    3.times { client_handler.queue.pop }

    # If we got here without error, settings were exchanged
    assert true

    client_session.finish
    client_thread.join(5)
    client_udp.close
    server << :shutdown
    server.value
  ensure
  end

  def test_static_only_headers
    skip "OpenSSL QUIC not available" unless OPENSSL_QUIC
    client_session, client_handler, client_thread, client_udp, server =
      setup_h3_pair(HeadersOnlyServer.new)

    client_session.request([
      [":method", "GET"],
      [":path", "/"],
      [":scheme", "https"],
      [":authority", "localhost"],
    ])

    event = client_handler.queue.pop
    assert_equal :headers, event[0]
    headers = event[1]
    status = headers.find { |n, _| n == ":status" }
    assert_equal "200", status[1]

    event = client_handler.queue.pop
    assert_equal :done, event[0]

    client_session.finish
    client_thread.join(5)
    client_udp.close
    server << :shutdown
    server.value
  ensure
  end
end
