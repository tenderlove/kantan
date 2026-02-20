# frozen_string_literal: true

require "socket"
require "kantan/quic/connection"

module Kantan
  module QUIC
    class Server
      def initialize(host:, port:, cert:, key:)
        @host = host
        @port = port
        @cert = cert
        @key = key
        @connections = {}
        @running = false
      end

      def run(&handler_block)
        @socket = UDPSocket.new
        @socket.bind(@host, @port)
        @running = true

        $stderr.puts "QUIC server listening on #{@host}:#{@port}"

        while @running
          data, addr_info = @socket.recvfrom(65535)
          data = data.b
          client_key = [addr_info[3], addr_info[1]] # [ip, port]

          conn = @connections[client_key]

          if conn
            conn.receive_datagram(data)
          else
            # New connection — must be an Initial packet
            first_byte = data.getbyte(0)
            next unless first_byte && first_byte & 0x80 != 0 # must be long header

            type = (first_byte & 0x30) >> 4
            next unless type == Packet::INITIAL

            # Extract DCID
            dcid_len = data.getbyte(5)
            dcid = data.byteslice(6, dcid_len)

            conn = Connection.new(@socket, client_key, dcid, @cert, @key)
            @connections[client_key] = conn
            conn.start_write_thread

            # Start H3 session in a new thread
            Thread.new(conn) do |c|
              handler_block.call(c)
            rescue => e
              $stderr.puts "QUIC: handler error: #{e.message}"
              $stderr.puts e.backtrace.first(5).join("\n") if $DEBUG
            ensure
              @connections.delete(client_key)
            end

            conn.receive_datagram(data)
          end
        end
      rescue IOError, Errno::EBADF
        # Socket closed
      end

      def stop
        @running = false
        @socket&.close
      end
    end
  end
end
