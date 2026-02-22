# frozen_string_literal: true

require "openssl"
require "socket"

module Kantan
  module QUIC
    class OpenSSLStream
      attr_reader :id

      def initialize ssl, delay_read: 0
        @ssl = ssl
        @id = ssl.stream_id

        @recv_buf = "".b
        @recv_mu = Mutex.new
        @recv_fin = false
        @on_readable = nil
        @reader = nil
        @delay_read = delay_read
      end

      def on_readable= cb
        @on_readable = cb
        @reader ||= Thread.new { reader_loop }
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
        @ssl.syswrite(data)
      rescue OpenSSL::SSL::SSLError
        # Suppress write errors — connection may have been closed by
        # OpenSSL's internal QUIC thread. Non-critical writes (like
        # QPACK decoder acks) can be safely dropped.
      end

      def close
        @ssl.stream_conclude
      rescue OpenSSL::SSL::SSLError
        # stream may already be concluded
      end

      private

      def reader_loop
        sleep @delay_read if @delay_read > 0

        loop do
          data = @ssl.sysread(16384)
          @recv_mu.synchronize { @recv_buf << data }
          @on_readable&.call
        end
      rescue EOFError, IOError, Errno::EPIPE, OpenSSL::SSL::SSLError
        @recv_mu.synchronize { @recv_fin = true }
        @on_readable&.call
      end
    end

    class OpenSSLConnection
      def initialize(host, port)
        @host = host
        @port = port
        @closed = false
        @accept_queue = Thread::Queue.new
        @pump_started = false
        @mu = Mutex.new
      end

      def connect
        ctx = OpenSSL::SSL::SSLContext.new(quic: :client_thread)
        ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE
        ctx.alpn_protocols = ["h3"]
        @ssl = OpenSSL::SSL::SSLSocket.open_quic(@host, @port, context: ctx)
        @ssl.default_stream_mode = :none
      end

      def open_stream(bidi:)
        flags = bidi ? 0 : OpenSSL::SSL::STREAM_FLAG_UNI
        stream_ssl = @ssl.new_stream(flags)
        delay = bidi ? 0.15 : 0
        OpenSSLStream.new(stream_ssl, delay_read: delay)
      end

      def accept_stream
        start_pump
        @accept_queue.pop
      end

      def close
        @closed = true
        @accept_queue << nil rescue nil
        puts "#" * 90
        puts caller
        puts "#" * 90
        @ssl&.close
      rescue IOError, OpenSSL::SSL::SSLError
        # already closed
      end

      private

      def start_pump
        @mu.synchronize do
          return if @pump_started
          @pump_started = true
        end

        Thread.new do
          sleep 0.3

          3.times do
            break if @closed
            stream_ssl = @ssl.accept_stream
            break unless stream_ssl
            @accept_queue << OpenSSLStream.new(stream_ssl)
          end
        rescue OpenSSL::SSL::SSLError
          # connection closed
        end
      end
    end
  end
end
