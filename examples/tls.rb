#!/usr/bin/env ruby
# frozen_string_literal: true

require 'socket'
require 'openssl'
require_relative '../lib/http2'

# Example of using HTTP/2 with TLS/SSL
# This demonstrates how to wrap sockets with SSL for secure HTTP/2

def create_self_signed_cert
  # Generate a self-signed certificate for testing
  key = OpenSSL::PKey::RSA.new(2048)

  cert = OpenSSL::X509::Certificate.new
  cert.subject = cert.issuer = OpenSSL::X509::Name.parse("/C=US/O=Test/CN=localhost")
  cert.not_before = Time.now
  cert.not_after = Time.now + 365 * 24 * 60 * 60
  cert.public_key = key.public_key
  cert.serial = 0x0
  cert.version = 2

  # Add extensions
  ef = OpenSSL::X509::ExtensionFactory.new
  ef.subject_certificate = cert
  ef.issuer_certificate = cert

  cert.extensions = [
    ef.create_extension("basicConstraints", "CA:TRUE", true),
    ef.create_extension("subjectKeyIdentifier", "hash"),
    ef.create_extension("subjectAltName", "DNS:localhost,IP:127.0.0.1")
  ]

  cert.sign(key, OpenSSL::Digest::SHA256.new)

  [cert, key]
end

def run_tls_server
  puts "Starting HTTP/2 over TLS server on port 8443..."

  # Create TCP server
  tcp_server = TCPServer.new(8443)

  # Generate self-signed certificate
  cert, key = create_self_signed_cert

  # Setup SSL context
  ssl_context = OpenSSL::SSL::SSLContext.new
  ssl_context.cert = cert
  ssl_context.key = key

  # Enable HTTP/2 via ALPN (Application-Layer Protocol Negotiation)
  ssl_context.alpn_protocols = ['h2']

  # Create SSL server
  ssl_server = OpenSSL::SSL::SSLServer.new(tcp_server, ssl_context)

  puts "Server ready. Waiting for connections..."
  puts "ALPN protocols: #{ssl_context.alpn_protocols.inspect}"

  loop do
    # Accept SSL connection
    ssl_socket = ssl_server.accept
    puts "\nNew connection from #{ssl_socket.peeraddr[2]}"
    puts "  Protocol: #{ssl_socket.alpn_protocol}"

    # Verify HTTP/2 was negotiated
    unless ssl_socket.alpn_protocol == 'h2'
      puts "  Warning: HTTP/2 not negotiated, got: #{ssl_socket.alpn_protocol}"
    end

    Thread.new do
      begin
        # Create HTTP/2 server with the SSL socket
        http2_server = HTWO::Server.new(ssl_socket)

        http2_server.on_headers do |stream, headers|
          puts "\n[Stream #{stream.id}] Headers:"
          headers.each { |name, value| puts "  #{name}: #{value}" }
        end

        http2_server.on_stream do |stream|
          method = stream.received_headers.find { |n, _| n == ":method" }&.last
          path = stream.received_headers.find { |n, _| n == ":path" }&.last

          puts "[Stream #{stream.id}] Request: #{method} #{path}"

          # Generate response
          body = "Secure HTTP/2 response!\n\nYou are connected via TLS.\n"
          body += "Time: #{Time.now}\n"

          response_headers = [
            [":status", "200"],
            ["content-type", "text/plain"],
            ["content-length", body.bytesize.to_s],
            ["server", "Pure Ruby HTTP/2 with TLS"]
          ]

          http2_server.send_headers(stream.id, response_headers)
          http2_server.send_data(stream.id, body, end_stream: true)

          puts "[Stream #{stream.id}] Response sent"
        end

        http2_server.start
      rescue => e
        puts "Error: #{e.message}"
        puts e.backtrace[0..5]
      ensure
        ssl_socket.close unless ssl_socket.closed?
      end
    end
  end
rescue Interrupt
  puts "\nShutting down server..."
ensure
  ssl_server&.close
  tcp_server&.close
end

def run_tls_client
  puts "Connecting to HTTP/2 over TLS server..."

  # Create TCP socket
  tcp_socket = TCPSocket.new('localhost', 8443)

  # Setup SSL context
  ssl_context = OpenSSL::SSL::SSLContext.new
  ssl_context.verify_mode = OpenSSL::SSL::VERIFY_NONE  # For self-signed cert
  ssl_context.alpn_protocols = ['h2']

  # Create SSL socket
  ssl_socket = OpenSSL::SSL::SSLSocket.new(tcp_socket, ssl_context)
  ssl_socket.sync_close = true
  ssl_socket.connect

  puts "Connected via TLS"
  puts "  Protocol: #{ssl_socket.alpn_protocol}"
  puts "  Cipher: #{ssl_socket.cipher[0]}"

  # Create HTTP/2 client with the SSL socket
  http2_client = HTWO::Client.new(ssl_socket)

  http2_client.on_headers do |stream, headers|
    puts "\n[Stream #{stream.id}] Response headers:"
    headers.each { |name, value| puts "  #{name}: #{value}" }
  end

  http2_client.on_data do |stream, data|
    puts "\n[Stream #{stream.id}] Response body:"
    puts data
  end

  # Start connection
  http2_client.start

  # Make request
  puts "\nSending request..."
  request_headers = [
    [":method", "GET"],
    [":path", "/secure"],
    [":scheme", "https"],
    [":authority", "localhost:8443"]
  ]

  stream = http2_client.request(request_headers)

  # Run event loop
  Thread.new { http2_client.run }

  sleep 2

  http2_client.close
  puts "\nConnection closed"
rescue => e
  puts "Error: #{e.message}"
  puts e.backtrace[0..5]
end

# Main
if __FILE__ == $0
  if ARGV[0] == 'server'
    run_tls_server
  elsif ARGV[0] == 'client'
    run_tls_client
  else
    puts "HTTP/2 over TLS Example"
    puts "=" * 60
    puts
    puts "Usage:"
    puts "  ruby #{__FILE__} server    # Run the server"
    puts "  ruby #{__FILE__} client    # Run the client"
    puts
    puts "To test:"
    puts "  1. In one terminal: ruby #{__FILE__} server"
    puts "  2. In another terminal: ruby #{__FILE__} client"
    puts
    puts "Or test with curl (if built with HTTP/2 support):"
    puts "  curl -k --http2 https://localhost:8443/secure"
    puts
  end
end
