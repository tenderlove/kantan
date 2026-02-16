require "stringio"

module HTWO
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
        # Rack allows header values to be Arrays
        if value.is_a?(Array)
          value.each { |v| response_headers << [key, v] }
        else
          response_headers << [key, value]
        end
      end

      # Collect response body
      response_body = nil
      if rack_body.respond_to?(:to_path)
        path = rack_body.to_path
        response_body = File.binread(path) if path
      end

      unless response_body
        parts = []
        rack_body.each { |part| parts << part }
        response_body = parts.join unless parts.empty?
      end

      stream.respond(response_headers, body: response_body)
    ensure
      rack_body.close if rack_body.respond_to?(:close)
    end

    def build_env(stream, body)
      headers = stream.headers
      method = header_value(headers, ":method")
      path_and_query = header_value(headers, ":path")
      authority = header_value(headers, ":authority")
      scheme = header_value(headers, ":scheme") || @scheme

      path, query = path_and_query.split("?", 2)

      input = body || StringIO.new("".b)

      env = {
        "REQUEST_METHOD"  => method,
        "SCRIPT_NAME"     => "",
        "PATH_INFO"       => path,
        "QUERY_STRING"    => query || "",
        "SERVER_NAME"     => @server_name,
        "SERVER_PORT"     => @server_port,
        "SERVER_PROTOCOL" => "HTTP/2",
        "rack.url_scheme" => scheme,
        "rack.input"      => input,
        "rack.errors"     => $stderr,
      }

      headers.each do |name, value|
        next if name.start_with?(":")
        case name
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

      # Use :authority as HTTP_HOST if host header wasn't set
      env["HTTP_HOST"] ||= authority if authority

      env
    end

    def header_value(headers, name)
      headers.assoc(name)&.last
    end
  end
end
