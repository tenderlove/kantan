# frozen_string_literal: true

require_relative "helper"
require_relative "mock_quic"
require "kantan/h3"

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

  # ── Session (integration with MockQuic) ─────────────────────────────

  def setup_h3_pair
    client_conn, server_conn = MockQuic.pair

    client_handler = TestClientHandler.new
    server_handler = TestServerHandler.new

    server_session = Kantan::H3::Session.new(server_conn, handler: server_handler)
    client_session = Kantan::H3::Session.new(client_conn, handler: client_handler)

    server_thread = Thread.new { server_session.receive }

    [client_session, client_handler, server_session, server_handler, server_thread]
  end

  def test_simple_get
    client_session, client_handler, _, server_handler, server_thread = setup_h3_pair

    server_handler.on_request_block = ->(stream) {
      stream.respond([[":status", "200"], ["content-type", "text/plain"]], body: "OK")
    }

    Thread.new { client_session.connect }

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
    server_thread.join(5)
  end

  def test_post_with_body
    client_session, client_handler, _, server_handler, server_thread = setup_h3_pair

    received_body = nil
    server_handler.on_request_block = ->(stream) {
      received_body = stream.data_received
      stream.respond([[":status", "200"]], body: "accepted")
    }

    Thread.new { client_session.connect }

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
    assert_equal "accepted", event[1]

    event = client_handler.queue.pop
    assert_equal :done, event[0]

    assert_equal body.bytesize, received_body

    client_session.finish
    server_thread.join(5)
  end

  def test_multiple_requests
    client_session, client_handler, _, server_handler, server_thread = setup_h3_pair

    request_count = 0
    server_handler.on_request_block = ->(stream) {
      request_count += 1
      path = stream.headers.find { |n, _| n == ":path" }[1]
      stream.respond([[":status", "200"]], body: "response for #{path}")
    }

    Thread.new { client_session.connect }

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

    assert_equal 2, request_count

    client_session.finish
    server_thread.join(5)
  end

  def test_settings_exchange
    client_conn, server_conn = MockQuic.pair
    client_handler = TestClientHandler.new
    server_handler = TestServerHandler.new

    server_session = Kantan::H3::Session.new(server_conn, handler: server_handler)
    client_session = Kantan::H3::Session.new(client_conn, handler: client_handler)

    server_handler.on_request_block = ->(stream) {
      stream.respond([[":status", "200"]], body: "ok")
    }

    server_thread = Thread.new { server_session.receive }
    Thread.new { client_session.connect }

    client_session.request([
      [":method", "GET"], [":path", "/"],
      [":scheme", "https"], [":authority", "localhost"],
    ])
    3.times { client_handler.queue.pop }

    # If we got here without error, settings were exchanged
    assert true

    client_session.finish
    server_thread.join(5)
  end

  def test_static_only_headers
    client_session, client_handler, _, server_handler, server_thread = setup_h3_pair

    server_handler.on_request_block = ->(stream) {
      stream.respond([[":status", "200"], ["content-type", "text/plain"]])
    }

    Thread.new { client_session.connect }

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
    server_thread.join(5)
  end
end
