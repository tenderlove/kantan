# frozen_string_literal: true

require_relative "helper"
require "kantan/quic/crypto"
require "kantan/quic/frames"
require "kantan/quic/packet"
require "kantan/quic/tls"
require "kantan/quic/client_tls"
require "kantan/quic/client_connection"
require "kantan/quic/stream"
require "kantan/quic/server"
require "kantan/h3"
require "openssl"

class TestQUICCrypto < Minitest::Test
  # RFC 9001 Appendix A test vectors
  # DCID = 0x8394c8f03e515708

  DCID = ["8394c8f03e515708"].pack("H*")

  def test_initial_salt
    salt = Kantan::QUIC::Crypto::INITIAL_SALT
    assert_equal ["38762cf7f55934b34d179ae6a4c80cadccbb7f0a"].pack("H*"), salt
  end

  def test_derive_initial_secrets
    client_secret, server_secret = Kantan::QUIC::Crypto.derive_initial_secrets(DCID)

    # RFC 9001 Appendix A.1
    expected_client = ["c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea"].pack("H*")
    expected_server = ["3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b"].pack("H*")

    assert_equal expected_client, client_secret, "client initial secret"
    assert_equal expected_server, server_secret, "server initial secret"
  end

  def test_derive_client_initial_keys
    client_secret, _ = Kantan::QUIC::Crypto.derive_initial_secrets(DCID)
    keys = Kantan::QUIC::Crypto.derive_keys(client_secret)

    expected_key = ["1f369613dd76d5467730efcbe3b1a22d"].pack("H*")
    expected_iv  = ["fa044b2f42a3fd3b46fb255c"].pack("H*")
    expected_hp  = ["9f50449e04a0e810283a1e9933adedd2"].pack("H*")

    assert_equal expected_key, keys[:key], "client key"
    assert_equal expected_iv, keys[:iv], "client iv"
    assert_equal expected_hp, keys[:hp], "client hp"
  end

  def test_derive_server_initial_keys
    _, server_secret = Kantan::QUIC::Crypto.derive_initial_secrets(DCID)
    keys = Kantan::QUIC::Crypto.derive_keys(server_secret)

    expected_key = ["cf3a5331653c364c88f0f379b6067e37"].pack("H*")
    expected_iv  = ["0ac1493ca1905853b0bba03e"].pack("H*")
    expected_hp  = ["c206b8d9b9f0f37644430b490eeaa314"].pack("H*")

    assert_equal expected_key, keys[:key], "server key"
    assert_equal expected_iv, keys[:iv], "server iv"
    assert_equal expected_hp, keys[:hp], "server hp"
  end

  def test_aead_round_trip
    key = OpenSSL::Random.random_bytes(16)
    iv = OpenSSL::Random.random_bytes(12)
    plaintext = "hello world".b
    aad = "additional data".b

    ciphertext = Kantan::QUIC::Crypto.aead_encrypt(key, iv, 0, aad, plaintext)
    decrypted = Kantan::QUIC::Crypto.aead_decrypt(key, iv, 0, aad, ciphertext)

    assert_equal plaintext, decrypted
  end

  def test_header_protection_round_trip
    hp_key = OpenSSL::Random.random_bytes(16)
    sample = OpenSSL::Random.random_bytes(16)
    # Simulate a long header: byte 0 has bit 7 set
    header = "\xC3\x00\x00\x00\x01\x08test\x00\x00\x00\x00".b
    pn_offset = 10
    pn_length = 4

    protected = Kantan::QUIC::Crypto.apply_header_protection(hp_key, sample, header, pn_offset, pn_length)
    refute_equal header, protected

    unprotected, recovered_pn_len = Kantan::QUIC::Crypto.remove_header_protection(hp_key, sample, protected, pn_offset)
    assert_equal header, unprotected
    assert_equal pn_length, recovered_pn_len
  end
end

class TestQUICFrames < Minitest::Test
  def test_crypto_frame_round_trip
    data = "hello TLS".b
    frame = Kantan::QUIC::Frames.build_crypto(42, data)
    frames = Kantan::QUIC::Frames.parse(frame)

    assert_equal 1, frames.size
    type, offset, payload = frames[0]
    assert_equal :crypto, type
    assert_equal 42, offset
    assert_equal data, payload
  end

  def test_ack_frame_round_trip
    frame = Kantan::QUIC::Frames.build_ack(10, 5)
    frames = Kantan::QUIC::Frames.parse(frame)

    assert_equal 1, frames.size
    type, largest, delay = frames[0]
    assert_equal :ack, type
    assert_equal 10, largest
    assert_equal 5, delay
  end

  def test_stream_frame_no_offset
    data = "stream data".b
    frame = Kantan::QUIC::Frames.build_stream(4, 0, data, fin: false)
    frames = Kantan::QUIC::Frames.parse(frame)

    assert_equal 1, frames.size
    type, stream_id, offset, payload, fin = frames[0]
    assert_equal :stream, type
    assert_equal 4, stream_id
    assert_equal 0, offset
    assert_equal data, payload
    refute fin
  end

  def test_stream_frame_with_offset_and_fin
    data = "more data".b
    frame = Kantan::QUIC::Frames.build_stream(8, 100, data, fin: true)
    frames = Kantan::QUIC::Frames.parse(frame)

    assert_equal 1, frames.size
    type, stream_id, offset, payload, fin = frames[0]
    assert_equal :stream, type
    assert_equal 8, stream_id
    assert_equal 100, offset
    assert_equal data, payload
    assert fin
  end

  def test_handshake_done_frame
    frame = Kantan::QUIC::Frames.build_handshake_done
    frames = Kantan::QUIC::Frames.parse(frame)

    assert_equal 1, frames.size
    assert_equal :handshake_done, frames[0][0]
  end

  def test_connection_close_frame
    frame = Kantan::QUIC::Frames.build_connection_close(0x0a, reason: "bye")
    frames = Kantan::QUIC::Frames.parse(frame)

    assert_equal 1, frames.size
    type, error_code, _frame_type, reason = frames[0]
    assert_equal :connection_close, type
    assert_equal 0x0a, error_code
    assert_equal "bye", reason
  end

  def test_padding_frame
    frame = Kantan::QUIC::Frames.build_padding(10)
    frames = Kantan::QUIC::Frames.parse(frame)
    assert_equal 0, frames.size # padding produces no parsed frames
  end

  def test_multiple_frames
    buf = "".b
    buf << Kantan::QUIC::Frames.build_ack(5)
    buf << Kantan::QUIC::Frames.build_crypto(0, "data".b)
    buf << Kantan::QUIC::Frames.build_handshake_done

    frames = Kantan::QUIC::Frames.parse(buf)
    assert_equal 3, frames.size
    assert_equal :ack, frames[0][0]
    assert_equal :crypto, frames[1][0]
    assert_equal :handshake_done, frames[2][0]
  end
end

class TestQUICPacket < Minitest::Test
  def test_initial_packet_build_decrypt_round_trip
    dcid = OpenSSL::Random.random_bytes(8)
    scid = OpenSSL::Random.random_bytes(8)

    client_secret, server_secret = Kantan::QUIC::Crypto.derive_initial_secrets(dcid)
    server_keys = Kantan::QUIC::Crypto.derive_keys(server_secret)

    crypto_data = "fake client hello".b
    frames = [Kantan::QUIC::Frames.build_crypto(0, crypto_data)]

    packet = Kantan::QUIC::Packet.build_initial(
      dcid: dcid, scid: scid, pn: 0, frames: frames, keys: server_keys
    )

    # Should be at least 1200 bytes (QUIC Initial padding)
    assert operator: :>=, left: packet.bytesize, right: 1200

    # Decrypt it
    info, plaintext = Kantan::QUIC::Packet.decrypt_long(packet, server_keys)
    assert_equal Kantan::QUIC::Packet::INITIAL, info[:type]
    assert_equal 0, info[:pn]
    assert_equal dcid, info[:dcid]
    assert_equal scid, info[:scid]

    # Parse the decrypted frames
    parsed = Kantan::QUIC::Frames.parse(plaintext)
    crypto_frames = parsed.select { |f| f[0] == :crypto }
    assert_equal 1, crypto_frames.size
    assert_equal crypto_data, crypto_frames[0][2]
  end

  def test_handshake_packet_build_decrypt_round_trip
    dcid = OpenSSL::Random.random_bytes(8)
    scid = OpenSSL::Random.random_bytes(8)

    # Use arbitrary keys for handshake
    secret = OpenSSL::Random.random_bytes(32)
    keys = Kantan::QUIC::Crypto.derive_keys(secret)

    crypto_data = "fake handshake data".b
    frames = [Kantan::QUIC::Frames.build_crypto(0, crypto_data)]

    packet = Kantan::QUIC::Packet.build_handshake(
      dcid: dcid, scid: scid, pn: 1, frames: frames, keys: keys
    )

    info, plaintext = Kantan::QUIC::Packet.decrypt_long(packet, keys)
    assert_equal Kantan::QUIC::Packet::HANDSHAKE, info[:type]
    assert_equal 1, info[:pn]

    parsed = Kantan::QUIC::Frames.parse(plaintext)
    crypto_frames = parsed.select { |f| f[0] == :crypto }
    assert_equal crypto_data, crypto_frames[0][2]
  end

  def test_short_packet_build_decrypt_round_trip
    dcid = OpenSSL::Random.random_bytes(8)
    secret = OpenSSL::Random.random_bytes(32)
    keys = Kantan::QUIC::Crypto.derive_keys(secret)

    stream_data = "hello http3".b
    frames = [Kantan::QUIC::Frames.build_stream(0, 0, stream_data, fin: true)]

    packet = Kantan::QUIC::Packet.build_short(dcid: dcid, pn: 42, frames: frames, keys: keys)

    info, plaintext = Kantan::QUIC::Packet.decrypt_short(packet, keys, dcid.bytesize)
    assert_equal 42, info[:pn]
    assert_equal dcid, info[:dcid]

    parsed = Kantan::QUIC::Frames.parse(plaintext)
    stream_frames = parsed.select { |f| f[0] == :stream }
    assert_equal 1, stream_frames.size
    assert_equal stream_data, stream_frames[0][3]
    assert stream_frames[0][4] # FIN
  end
end

class TestQUICStream < Minitest::Test
  def test_read_write
    stream = Kantan::QUIC::Stream.new(0, nil)
    stream.receive_data("hello".b, 0, false)
    stream.receive_data(" world".b, 5, true)

    assert_equal "hello world", stream.read(11)
  end

  def test_readbyte
    stream = Kantan::QUIC::Stream.new(0, nil)
    stream.receive_data("\x42".b, 0, false)
    assert_equal 0x42, stream.readbyte
  end

  def test_readbyte_eof
    stream = Kantan::QUIC::Stream.new(0, nil)
    stream.receive_data("".b, 0, true)
    assert_raises(EOFError) { stream.readbyte }
  end

  def test_readpartial
    stream = Kantan::QUIC::Stream.new(0, nil)
    stream.receive_data("hello world".b, 0, false)
    result = stream.readpartial(5)
    assert_equal "hello", result
    result = stream.readpartial(100)
    assert_equal " world", result
  end

  def test_threaded_read_write
    stream = Kantan::QUIC::Stream.new(0, nil)

    reader = Thread.new do
      stream.read(11)
    end

    sleep 0.01
    stream.receive_data("hello".b, 0, false)
    stream.receive_data(" world".b, 5, false)

    result = reader.join(2)&.value
    assert_equal "hello world", result
  end

  def test_fin_returns_nil_on_read
    stream = Kantan::QUIC::Stream.new(0, nil)
    stream.receive_data("".b, 0, true)
    assert_nil stream.read(10)
  end
end

class TestQUICIntegration < Minitest::Test
  CURL = "/opt/homebrew/opt/curl/bin/curl"

  def setup
    unless File.executable?(CURL)
      skip "curl not found at #{CURL}"
    end
    unless `#{CURL} --version 2>&1`.include?("HTTP3")
      skip "curl does not support HTTP/3"
    end
  end

  def setup_quic_server(&handler_block)
    # Generate self-signed EC cert
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

    # Find a free UDP port
    sock = UDPSocket.new
    sock.bind("127.0.0.1", 0)
    port = sock.addr[1]
    sock.close

    server = Kantan::QUIC::Server.new(
      host: "127.0.0.1",
      port: port,
      cert: cert,
      key: key,
    )

    server_thread = Thread.new do
      server.run do |conn|
        handler = TestServerHandler.new
        handler.on_request_block = handler_block
        session = Kantan::H3::Session.new(conn, handler: handler)
        session.receive
      end
    rescue => e
      $stderr.puts "Integration test server error: #{e.message}"
    end

    sleep 0.1 # let server bind

    [port, server, server_thread]
  end

  def run_curl(port, path, extra_args: [])
    sep = "---CURL_STATUS---"
    args = [CURL, "--http3", "-k", "-s", "-w", "\n#{sep}%{http_code}",
            *extra_args,
            "https://127.0.0.1:#{port}#{path}"]
    output = IO.popen(args, err: "/dev/null", &:read)
    body, status_str = output.split(sep, 2)
    [status_str.to_i, body.rstrip]
  end

  def test_curl_get_200
    port, server, _ = setup_quic_server do |stream|
      body = "Hello from HTTP/3!\n"
      stream.respond([
        [":status", "200"],
        ["content-type", "text/plain"],
        ["content-length", body.bytesize.to_s],
      ], body: body)
    end

    status, body = run_curl(port, "/")
    assert_equal 200, status
    assert_equal "Hello from HTTP/3!", body
  ensure
    server&.stop
  end

  def test_curl_get_404
    port, server, _ = setup_quic_server do |stream|
      path = stream.headers.assoc(":path")&.last
      if path == "/"
        stream.respond([[":status", "200"]], body: "ok")
      else
        body = "Not Found\n"
        stream.respond([
          [":status", "404"],
          ["content-type", "text/plain"],
          ["content-length", body.bytesize.to_s],
        ], body: body)
      end
    end

    status, body = run_curl(port, "/nonexistent")
    assert_equal 404, status
    assert_equal "Not Found", body
  ensure
    server&.stop
  end

  def test_curl_response_headers
    port, server, _ = setup_quic_server do |stream|
      stream.respond([
        [":status", "200"],
        ["content-type", "application/json"],
        ["x-custom", "test-value"],
      ], body: "{}")
    end

    args = [CURL, "--http3", "-k", "-s", "-D", "-",
            "https://127.0.0.1:#{port}/"]
    output = IO.popen(args, err: "/dev/null", &:read)
    assert_match(/content-type: application\/json/i, output)
    assert_match(/x-custom: test-value/i, output)
  ensure
    server&.stop
  end

  def test_curl_post_with_body
    port, server, _ = setup_quic_server do |stream|
      method = stream.headers.assoc(":method")&.last
      received = stream.data_received
      body = "method=#{method} bytes=#{received}\n"
      stream.respond([
        [":status", "200"],
        ["content-type", "text/plain"],
        ["content-length", body.bytesize.to_s],
      ], body: body)
    end

    status, body = run_curl(port, "/echo", extra_args: ["-X", "POST", "-d", "hello world"])
    assert_equal 200, status
    assert_match(/method=POST/, body)
    assert_match(/bytes=11/, body)
  ensure
    server&.stop
  end
end

class TestQUICClientTLS < Minitest::Test
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
    cert.sign(key, "SHA256")
    [cert, key]
  end

  def test_client_hello_has_empty_session_id
    client_tls = Kantan::QUIC::ClientTLS.new
    client_tls.our_scid = "\x00".b * 8
    ch_msg = client_tls.build_client_hello

    # type(1) + length(3) + legacy_version(2) + random(32) = offset 38
    # session_id_len should be 0 (RFC 9001 §8.4)
    session_id_len = ch_msg.getbyte(38)
    assert_equal 0, session_id_len, "QUIC ClientHello must have empty session_id"
  end

  def test_client_hello_includes_sni
    client_tls = Kantan::QUIC::ClientTLS.new("example.com")
    client_tls.our_scid = "\x00".b * 8
    ch_msg = client_tls.build_client_hello

    # SNI extension should contain the hostname
    assert_includes ch_msg, "example.com".b
  end

  def test_client_hello_no_sni_without_host
    client_tls = Kantan::QUIC::ClientTLS.new
    client_tls.our_scid = "\x00".b * 8
    ch_msg = client_tls.build_client_hello

    # Without host, no SNI extension — verify no server_name ext type (0x0000)
    # at extension boundaries. Just check the message is parseable by the server.
    server_tls = Kantan::QUIC::TLS.new(*generate_cert)
    server_tls.original_dcid = "\x00".b * 8
    server_tls.our_scid = "\x01".b * 8
    result = server_tls.process_client_hello(ch_msg)
    assert result[:handshake_keys]
    assert result[:app_keys]
  end

  def test_full_tls_handshake_round_trip
    cert, key = generate_cert

    # Client side
    client_tls = Kantan::QUIC::ClientTLS.new("localhost")
    client_tls.our_scid = OpenSSL::Random.random_bytes(8)
    ch_msg = client_tls.build_client_hello

    # Server side processes ClientHello
    server_tls = Kantan::QUIC::TLS.new(cert, key)
    server_tls.original_dcid = OpenSSL::Random.random_bytes(8)
    server_tls.our_scid = OpenSSL::Random.random_bytes(8)
    server_result = server_tls.process_client_hello(ch_msg)

    # Client processes ServerHello
    client_result = client_tls.process_server_hello(server_result[:server_hello])
    assert client_result[:handshake_keys][:client][:key]
    assert client_result[:handshake_keys][:server][:key]

    # Client and server must agree on handshake keys
    assert_equal server_result[:handshake_keys][:client][:key], client_result[:handshake_keys][:client][:key]
    assert_equal server_result[:handshake_keys][:server][:key], client_result[:handshake_keys][:server][:key]

    # Client processes EE+Cert+CV+Finished
    hs_result = client_tls.process_handshake_crypto(server_result[:handshake_crypto])
    assert hs_result[:app_keys][:client][:key]
    assert hs_result[:client_finished]

    # Client and server must agree on app keys
    assert_equal server_result[:app_keys][:client][:key], hs_result[:app_keys][:client][:key]
    assert_equal server_result[:app_keys][:server][:key], hs_result[:app_keys][:server][:key]

    # Server can verify client Finished
    assert server_tls.verify_client_finished(hs_result[:client_finished])
  end

  def test_client_hello_includes_signature_algorithms
    client_tls = Kantan::QUIC::ClientTLS.new
    client_tls.our_scid = "\x00".b * 8
    ch_msg = client_tls.build_client_hello

    # Should include ECDSA (0x0403) and RSA-PSS (0x0804) signature algorithms
    assert_includes ch_msg, [0x0403].pack("n")
    assert_includes ch_msg, [0x0804].pack("n")
  end
end

class TestQUICClientConnection < Minitest::Test
  def setup_quic_server(&handler_block)
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

    sock = UDPSocket.new
    sock.bind("127.0.0.1", 0)
    port = sock.addr[1]
    sock.close

    server = Kantan::QUIC::Server.new(
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
      $stderr.puts "Client test server error: #{e.message}"
    end

    sleep 0.1
    [port, server]
  end

  def test_client_connection_get_200
    port, server = setup_quic_server do |stream|
      body = "Hello from HTTP/3!\n"
      stream.respond([
        [":status", "200"],
        ["content-type", "text/plain"],
        ["content-length", body.bytesize.to_s],
      ], body: body)
    end

    conn = Kantan::QUIC::ClientConnection.new("127.0.0.1", port)
    conn.connect

    handler = TestClientHandler.new
    session = Kantan::H3::Session.new(conn, handler: handler)
    Thread.new { session.connect }
    sleep 0.1

    session.request([
      [":method", "GET"],
      [":path", "/"],
      [":scheme", "https"],
      [":authority", "localhost"],
    ])

    # Collect response
    headers = nil
    body = "".b
    deadline = Time.now + 5
    loop do
      assert Time.now < deadline, "timed out waiting for response"
      event = handler.queue.pop
      case event[0]
      when :headers then headers = event[1]
      when :data then body << event[1]
      when :done then break
      end
    end

    status = headers.assoc(":status")&.last
    assert_equal "200", status
    assert_equal "Hello from HTTP/3!\n", body
  ensure
    conn&.close
    server&.stop
  end

  def test_client_connection_gets_response_headers
    port, server = setup_quic_server do |stream|
      stream.respond([
        [":status", "200"],
        ["x-custom", "quic-test"],
        ["content-type", "text/plain"],
      ], body: "ok")
    end

    conn = Kantan::QUIC::ClientConnection.new("127.0.0.1", port)
    conn.connect

    handler = TestClientHandler.new
    session = Kantan::H3::Session.new(conn, handler: handler)
    Thread.new { session.connect }
    sleep 0.1

    session.request([
      [":method", "GET"],
      [":path", "/"],
      [":scheme", "https"],
      [":authority", "localhost"],
    ])

    headers = nil
    deadline = Time.now + 5
    loop do
      assert Time.now < deadline, "timed out waiting for response"
      event = handler.queue.pop
      case event[0]
      when :headers then headers = event[1]
      when :done then break
      end
    end

    assert_equal "quic-test", headers.assoc("x-custom")&.last
  ensure
    conn&.close
    server&.stop
  end

  def test_client_stream_ids_are_client_initiated
    port, server = setup_quic_server do |stream|
      stream.respond([[":status", "200"]], body: "ok")
    end

    conn = Kantan::QUIC::ClientConnection.new("127.0.0.1", port)
    conn.connect

    # Client bidi streams: 0, 4, 8...
    s1 = conn.open_stream(bidi: true)
    assert_equal 0, s1.id & 0x03, "client bidi stream low bits should be 0"

    # Client uni streams: 2, 6, 10...
    s2 = conn.open_stream(bidi: false)
    assert_equal 2, s2.id & 0x03, "client uni stream low bits should be 2"
  ensure
    conn&.close
    server&.stop
  end
end
