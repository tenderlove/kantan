# frozen_string_literal: true

require "openssl"
require "socket"

module Kantan
  module QUIC
    class OpenSSLServerStream
      attr_reader :id

      def initialize(ssl, conn)
        @ssl = ssl
        @conn = conn
        @id = ssl.stream_id

        @recv_buf = "".b
        @recv_mu = Mutex.new
        @recv_fin = false
        @on_readable = nil
      end

      def on_readable=(cb)
        @on_readable = cb
        @recv_mu.synchronize do
          @on_readable.call if @recv_buf.bytesize > 0 || @recv_fin
        end
      end

      def drain
        @recv_mu.synchronize do
          return nil if @recv_buf.empty? && !@recv_fin
          data = @recv_buf.dup
          @recv_buf.clear
          [data, @recv_fin]
        end
      end

      def write(data)
        @conn.enqueue_write(@ssl, data)
      end

      def close
        @conn.enqueue_conclude(@ssl)
      end

      def push_data(data)
        @recv_mu.synchronize { @recv_buf << data }
        @on_readable&.call
      end

      def push_fin
        @recv_mu.synchronize { @recv_fin = true }
        @on_readable&.call
      end
    end

    class OpenSSLServerConnection
      def initialize(ssl)
        @ssl = ssl
        @ssl.default_stream_mode = :none
        @accept_queue = Thread::Queue.new
        @write_queue = Thread::Queue.new
        @closed = false
        start_io_thread
      end

      def open_stream(bidi:)
        result = Thread::Queue.new
        @write_queue << [:new_stream, bidi, result]
        result.pop
      end

      def accept_stream
        @accept_queue.pop
      end

      def close
        @closed = true
        @write_queue << [:stop]
        @accept_queue << nil rescue nil
      end

      def enqueue_write(ssl, data)
        @write_queue << [:write, ssl, data]
      end

      def enqueue_conclude(ssl)
        @write_queue << [:conclude, ssl]
      end

      private

      def start_io_thread
        Thread.new { io_loop }
      end

      def io_loop
        # Phase 1: Process initial stream creation from H3 session.
        process_initial_commands

        # Phase 2: Accept client streams using blocking accept_stream.
        # Each blocking call releases the GIL and processes QUIC events.
        # After each accept, read the stream's initial data and check
        # for FIN (bidi streams). Drain writes between accepts.
        loop do
          break if @closed

          # Accept a stream (blocking, releases GIL, processes events)
          stream_ssl = @ssl.accept_stream
          break unless stream_ssl

          stream = OpenSSLServerStream.new(stream_ssl, self)

          # Read initial data
          begin
            data = stream_ssl.sysread(16384)
            stream.push_data(data)
          rescue EOFError
            stream.push_fin
          rescue IOError, OpenSSL::SSL::SSLError
            stream.push_fin
          end

          # For bidi streams, check for EOF with a second read.
          # The GIL is released during the blocking read, allowing
          # the H3 session to process the first chunk of data.
          if stream_ssl.stream_id & 0x02 == 0
            begin
              data = stream_ssl.sysread(16384)
              stream.push_data(data)
            rescue EOFError
              stream.push_fin
            rescue IOError, OpenSSL::SSL::SSLError
              stream.push_fin
            end
          end

          @accept_queue << stream
          drain_writes

          # After a bidi stream (request) arrives, switch to write mode
          # so the response can be sent without waiting for more streams.
          break if stream_ssl.stream_id & 0x02 == 0
        end

        # Phase 3: Drain writes and pump events to send the response.
        until @closed
          drain_writes
          @ssl.handle_events
          sleep 0.01
        end
      rescue IOError, OpenSSL::SSL::SSLError
        # connection closed
      ensure
        @closed = true
        @accept_queue << nil rescue nil
      end

      def process_initial_commands
        loop do
          cmd = @write_queue.pop(true) rescue nil
          unless cmd
            sleep 0.01
            cmd = @write_queue.pop(true) rescue nil
            break unless cmd
          end
          process_one_command(cmd)
          break if cmd[0] == :stop
        end
      end

      def drain_writes
        while (cmd = @write_queue.pop(true) rescue nil)
          process_one_command(cmd)
        end
      end

      def process_one_command(cmd)
        case cmd[0]
        when :new_stream
          _, bidi, result = cmd
          flags = bidi ? 0 : OpenSSL::SSL::STREAM_FLAG_UNI
          begin
            stream_ssl = @ssl.new_stream(flags)
            result << OpenSSLServerStream.new(stream_ssl, self)
          rescue OpenSSL::SSL::SSLError
            result << nil
          end
        when :write
          _, ssl, data = cmd
          begin
            ssl.syswrite(data)
          rescue IOError, OpenSSL::SSL::SSLError
            # suppress
          end
        when :conclude
          _, ssl = cmd
          begin
            ssl.stream_conclude
          rescue IOError, OpenSSL::SSL::SSLError
            # suppress
          end
        when :stop
          @closed = true
        end
      end
    end

    class OpenSSLServer
      def initialize(host:, port:, cert:, key:)
        @host = host
        @port = port
        @cert = cert
        @key = key
        @running = false
      end

      def run(&handler_block)
        ctx = OpenSSL::SSL::SSLContext.new(quic: :server)
        ctx.cert = @cert
        ctx.key = @key
        ctx.alpn_select_cb = lambda { |protocols|
          protocols.include?("h3") ? "h3" : protocols.first
        }

        @udp = UDPSocket.new
        @udp.bind(@host, @port)
        @running = true

        @listener = OpenSSL::SSL::SSLSocket.new_listener(@udp, context: ctx)
        @listener.listen

        $stderr.puts "OpenSSL QUIC server listening on #{@host}:#{@port}"

        while @running
          conn_ssl = @listener.accept_connection
          next unless conn_ssl

          conn = OpenSSLServerConnection.new(conn_ssl)
          Thread.new(conn) do |c|
            handler_block.call(c)
          rescue => e
            $stderr.puts "OpenSSL QUIC: handler error: #{e.message}"
            $stderr.puts e.backtrace.first(5).join("\n") if $DEBUG
          ensure
            c.close
          end
        end
      rescue IOError, Errno::EBADF
        # Socket closed
      end

      def stop
        @running = false
        @listener&.close rescue nil
        @udp&.close rescue nil
      end
    end
  end
end
