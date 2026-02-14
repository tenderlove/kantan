# frozen_string_literal: true

require 'minitest/autorun'
require 'socket'
require "htwo"

class TestClientHandler < HTWO::Handler
  attr_reader :queue

  def initialize
    @queue = Queue.new
  end

  def on_headers(stream) = @queue << [:headers, stream.headers]
  def on_data(stream, chunk) = @queue << [:data, chunk]
  def on_request(stream) = @queue << [:done, stream.id]
end

class TestServerHandler < HTWO::Handler
  attr_accessor :on_request_block

  def on_request(stream)
    @on_request_block&.call(stream)
  end
end

class TestHTTP2 < Minitest::Test
  def test_hpack_encoding_decoding
    encoder = HTWO::HPACK.new
    decoder = HTWO::HPACK.new

    headers = [[":method", "GET"], [":path", "/"]]
    encoded = encoder.encode(headers)
    decoded = decoder.decode(encoded)

    assert_equal headers, decoded
  end

  def write_frame io, type, stream_id, payload, flags: 0
    io.write [(payload.bytesize << 8) | type, flags, stream_id].pack("NCN")
    io.write payload
  end

  def read_frame io
    header = io.read(9)
    return unless header
    len_type, flags, stream_id = header.unpack("NCN")
    payload = io.read(len_type >> 8)
    [len_type & 0xFF, flags, stream_id & 0x7FFFFFFF, payload]
  end

  def test_continuation_flood
    client_io, server_io = Socket.pair(:UNIX, :STREAM, 0)
    client_io.sync = true
    server_io.sync = true

    server_handler = TestServerHandler.new
    server_session = HTWO::Session.new(server_io, handler: server_handler)
    server_thread = Thread.new { server_session.receive }

    # Handshake
    client_io.write "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    write_frame client_io, 0x04, 0, "" # SETTINGS
    write_frame client_io, 0x04, 0, "", flags: 0x01 # SETTINGS ACK

    # HEADERS without END_HEADERS (flags=0) on stream 1
    write_frame client_io, 0x01, 1, "\x82" # :method GET

    # Flood CONTINUATION frames exceeding MAX_HEADER_LIST_SIZE (65536)
    chunk = "\x00".b * 16384
    begin
      5.times { write_frame client_io, 0x09, 1, chunk }
      client_io.flush
    rescue Errno::EPIPE, Errno::ECONNRESET
      # Expected - server may close mid-flood
    end

    # Read frames until GOAWAY
    goaway_error = nil
    loop do
      type, _, _, payload = read_frame(client_io)
      break unless type
      if type == 0x07
        _, goaway_error = payload.unpack("NN")
        break
      end
    end

    assert_equal 0x0B, goaway_error, "Expected ENHANCE_YOUR_CALM"

  ensure
    client_io&.close rescue nil
    server_io&.close rescue nil
    server_thread&.join(2)
  end

  def test_simple_get
    client_io, server_io = Socket.pair(:UNIX, :STREAM, 0)
    client_io.sync = true
    server_io.sync = true

    server_handler = TestServerHandler.new
    server_handler.on_request_block = ->(stream) {
      stream.respond [[":status", "200"]], body: "Hello, world!"
    }

    client_handler = TestClientHandler.new

    server_session = HTWO::Session.new(server_io, handler: server_handler)
    client_session = HTWO::Session.new(client_io, handler: client_handler)

    server_thread = Thread.new { server_session.receive }
    client_session.connect

    client_session.request([
      [":method", "GET"],
      [":path", "/"],
      [":scheme", "https"],
      [":authority", "localhost"],
    ])

    # Collect response
    response_headers = nil
    body = "".b
    loop do
      type, value = client_handler.queue.pop
      case type
      when :headers then response_headers = value
      when :data then body << value
      when :done then break
      end
    end

    assert_equal [[":status", "200"]], response_headers
    assert_equal "Hello, world!", body

  ensure
    client_io&.close rescue nil
    server_io&.close rescue nil
    server_thread&.join(2)
  end
end
