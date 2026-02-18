# frozen_string_literal: true

require_relative "helper"
require 'rack'
require 'concurrent'
require 'htwo/rack_handler'

class TestRackHandler < Minitest::Test
  def setup
    @executor = Concurrent::FixedThreadPool.new(5)
  end

  def teardown
    @executor.shutdown
    @executor.wait_for_termination(2)
  end

  def setup_pair(rack_app)
    client_io, server_io = Socket.pair(:UNIX, :STREAM, 0)
    client_io.sync = true
    server_io.sync = true

    handler = Kantan::RackHandler.new(rack_app,
      executor: @executor,
      server_name: "localhost",
      server_port: 443,
      scheme: "https")

    client_handler = TestClientHandler.new

    server_session = Kantan::Session.new(server_io, handler: handler)
    client_session = Kantan::Session.new(client_io, handler: client_handler)

    server_thread = Thread.new { server_session.receive }
    client_session.connect

    [client_session, client_handler, client_io, server_io, server_thread]
  end

  def collect_response(client_handler)
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
    [response_headers, body]
  end

  def test_simple_get
    app = ->(env) {
      [200, { "content-type" => "text/plain" }, ["Hello from Rack!"]]
    }

    client_session, client_handler, client_io, server_io, server_thread = setup_pair(app)

    client_session.request([
      [":method", "GET"],
      [":path", "/foo"],
      [":scheme", "https"],
      [":authority", "localhost"],
    ])

    headers, body = collect_response(client_handler)

    assert_equal "200", headers.assoc(":status").last
    assert_equal "text/plain", headers.assoc("content-type").last
    assert_equal "Hello from Rack!", body
  ensure
    client_io&.close rescue nil
    server_io&.close rescue nil
    server_thread&.join(2)
  end

  def test_env_is_correct
    captured_env = nil
    app = ->(env) {
      captured_env = env.dup
      [200, { "content-type" => "text/plain" }, ["ok"]]
    }

    client_session, client_handler, client_io, server_io, server_thread = setup_pair(app)

    client_session.request([
      [":method", "POST"],
      [":path", "/test?foo=bar"],
      [":scheme", "https"],
      [":authority", "example.com"],
    ])

    collect_response(client_handler)

    assert_equal "POST", captured_env["REQUEST_METHOD"]
    assert_equal "/test", captured_env["PATH_INFO"]
    assert_equal "foo=bar", captured_env["QUERY_STRING"]
    assert_equal "", captured_env["SCRIPT_NAME"]
    assert_equal "localhost", captured_env["SERVER_NAME"]
    assert_equal "443", captured_env["SERVER_PORT"]
    assert_equal "HTTP/2", captured_env["SERVER_PROTOCOL"]
    assert_equal "https", captured_env["rack.url_scheme"]
    assert_instance_of StringIO, captured_env["rack.input"]
    # :authority should map to HTTP_HOST
    assert_equal "example.com", captured_env["HTTP_HOST"]
  ensure
    client_io&.close rescue nil
    server_io&.close rescue nil
    server_thread&.join(2)
  end

  def test_post_with_body
    captured_body = nil
    app = ->(env) {
      captured_body = env["rack.input"].read
      [200, { "content-type" => "text/plain" }, ["got it"]]
    }

    client_session, client_handler, client_io, server_io, server_thread = setup_pair(app)

    client_session.request([
      [":method", "POST"],
      [":path", "/upload"],
      [":scheme", "https"],
      [":authority", "localhost"],
      ["content-type", "application/json"],
      ["content-length", "13"],
    ], body: '{"key":"val"}')

    headers, body = collect_response(client_handler)

    assert_equal "200", headers.assoc(":status").last
    assert_equal "got it", body
    assert_equal '{"key":"val"}', captured_body
  ensure
    client_io&.close rescue nil
    server_io&.close rescue nil
    server_thread&.join(2)
  end

  def test_content_type_and_length_not_prefixed_with_http
    captured_env = nil
    app = ->(env) {
      captured_env = env.dup
      [200, { "content-type" => "text/plain" }, ["ok"]]
    }

    client_session, client_handler, client_io, server_io, server_thread = setup_pair(app)

    client_session.request([
      [":method", "POST"],
      [":path", "/"],
      [":scheme", "https"],
      [":authority", "localhost"],
      ["content-type", "application/json"],
      ["content-length", "5"],
    ], body: "hello")

    collect_response(client_handler)

    assert_equal "application/json", captured_env["CONTENT_TYPE"]
    assert_equal "5", captured_env["CONTENT_LENGTH"]
    refute captured_env.key?("HTTP_CONTENT_TYPE")
    refute captured_env.key?("HTTP_CONTENT_LENGTH")
  ensure
    client_io&.close rescue nil
    server_io&.close rescue nil
    server_thread&.join(2)
  end

  def test_custom_headers_mapped_to_http_prefix
    captured_env = nil
    app = ->(env) {
      captured_env = env.dup
      [200, { "content-type" => "text/plain" }, ["ok"]]
    }

    client_session, client_handler, client_io, server_io, server_thread = setup_pair(app)

    client_session.request([
      [":method", "GET"],
      [":path", "/"],
      [":scheme", "https"],
      [":authority", "localhost"],
      ["x-request-id", "abc123"],
      ["accept", "text/html"],
    ])

    collect_response(client_handler)

    assert_equal "abc123", captured_env["HTTP_X_REQUEST_ID"]
    assert_equal "text/html", captured_env["HTTP_ACCEPT"]
  ensure
    client_io&.close rescue nil
    server_io&.close rescue nil
    server_thread&.join(2)
  end

  def test_empty_body_response
    app = ->(env) {
      [204, {}, []]
    }

    client_session, client_handler, client_io, server_io, server_thread = setup_pair(app)

    client_session.request([
      [":method", "DELETE"],
      [":path", "/resource/1"],
      [":scheme", "https"],
      [":authority", "localhost"],
    ])

    headers, body = collect_response(client_handler)

    assert_equal "204", headers.assoc(":status").last
    assert_equal "", body
  ensure
    client_io&.close rescue nil
    server_io&.close rescue nil
    server_thread&.join(2)
  end

  def test_query_string_absent
    captured_env = nil
    app = ->(env) {
      captured_env = env.dup
      [200, { "content-type" => "text/plain" }, ["ok"]]
    }

    client_session, client_handler, client_io, server_io, server_thread = setup_pair(app)

    client_session.request([
      [":method", "GET"],
      [":path", "/no-query"],
      [":scheme", "https"],
      [":authority", "localhost"],
    ])

    collect_response(client_handler)

    assert_equal "/no-query", captured_env["PATH_INFO"]
    assert_equal "", captured_env["QUERY_STRING"]
  ensure
    client_io&.close rescue nil
    server_io&.close rescue nil
    server_thread&.join(2)
  end

  def test_send_file_via_to_path
    require "tempfile"
    tmpfile = Tempfile.new("htwo_test")
    tmpfile.binmode
    tmpfile.write("file body content")
    tmpfile.flush

    app = ->(env) {
      [200, { "content-type" => "application/octet-stream" }, tmpfile]
    }

    client_session, client_handler, client_io, server_io, server_thread = setup_pair(app)

    client_session.request([
      [":method", "GET"],
      [":path", "/download"],
      [":scheme", "https"],
      [":authority", "localhost"],
    ])

    headers, body = collect_response(client_handler)

    assert_equal "200", headers.assoc(":status").last
    assert_equal "file body content", body
    assert tmpfile.closed?, "rack body should be closed"
  ensure
    tmpfile&.unlink
    client_io&.close rescue nil
    server_io&.close rescue nil
    server_thread&.join(2)
  end

  def test_rack_lint_compliance
    app = ->(env) {
      [200, { "content-type" => "text/plain" }, ["lint ok"]]
    }
    linted_app = Rack::Lint.new(app)

    client_session, client_handler, client_io, server_io, server_thread = setup_pair(linted_app)

    client_session.request([
      [":method", "GET"],
      [":path", "/"],
      [":scheme", "https"],
      [":authority", "localhost"],
    ])

    headers, body = collect_response(client_handler)

    assert_equal "200", headers.assoc(":status").last
    assert_equal "lint ok", body
  ensure
    client_io&.close rescue nil
    server_io&.close rescue nil
    server_thread&.join(2)
  end
end
