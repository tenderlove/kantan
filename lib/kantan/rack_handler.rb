require "stringio"

module Kantan
  class RackHandler < Handler
    def initialize app, executor:, server_name:, server_port:, scheme: "https"
      @app = app
      @executor = executor
      @server_name = server_name
      @server_port = server_port.to_s
      @scheme = scheme
      @bodies = {}  # stream_id => StringIO
    end

    def on_data stream, chunk
      (@bodies[stream.id] ||= StringIO.new("".b)) << chunk
    end

    def on_request stream
      body = @bodies.delete(stream.id)
      body&.rewind
      @executor.post(stream, body) { |s, b| serve(s, b) }
    end

    private

    def serve stream, body
      env = build_env(stream, body)
      status, headers, rack_body = @app.call(env)

      response_headers = [[":status", status.to_s]]
      headers.each do |key, value|
        next if key.start_with?("rack.")
        key = key.downcase
        # Rack allows header values to be Arrays
        if value.is_a?(Array)
          value.each { |v| response_headers << [key, v] }
        else
          response_headers << [key, value]
        end
      end

      if rack_body.respond_to?(:to_path)
        stream.send_headers(response_headers, has_body: true)
        stream.send_file(rack_body.to_path)
      else
        parts = []
        rack_body.each { |part| parts << part }
        response_body = parts.join unless parts.empty?

        stream.send_headers(response_headers, has_body: !!response_body)
        stream.send_body(response_body) if response_body
      end
    ensure
      rack_body.close if rack_body.respond_to?(:close)
    end

    def build_env stream, body
      input = body || StringIO.new("".b)
      authority = nil
      method = nil
      path = nil
      query = nil
      scheme = nil

      env = {
        "SCRIPT_NAME"     => "",
        "SERVER_NAME"     => @server_name,
        "SERVER_PORT"     => @server_port,
        "SERVER_PROTOCOL" => "HTTP/2",
        "rack.input"      => input,
        "rack.errors"     => $stderr,
      }

      stream.headers.each do |name, value|
        case name
        when ":method"
          method = value
        when ":path"
          path, query = value.split("?", 2)
        when ":scheme"
          scheme = value
        when ":authority"
          authority = value
        when "content-type"
          env["CONTENT_TYPE"] = value
        when "content-length"
          env["CONTENT_LENGTH"] = value
        when "host"
          env["HTTP_HOST"] = value
        else
          key = "HTTP_" + name.tr("-", "_").upcase
          # RFC 7230: multiple header values joined with comma
          existing = env[key]
          env[key] = existing ? "#{existing}, #{value}" : value
        end
      end

      env["REQUEST_METHOD"]  = method
      env["PATH_INFO"]       = path
      env["QUERY_STRING"]    = query || ""
      env["rack.url_scheme"] = scheme || @scheme

      # Use :authority as HTTP_HOST if host header wasn't set
      env["HTTP_HOST"] ||= authority if authority

      env
    end
  end
end
