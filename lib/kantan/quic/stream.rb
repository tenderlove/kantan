# frozen_string_literal: true

module Kantan
  module QUIC
    class Stream
      attr_reader :id

      def initialize(id, connection)
        @id = id
        @connection = connection

        @recv_buf = "".b
        @recv_mu = Mutex.new
        @recv_cv = ConditionVariable.new
        @recv_fin = false

        @send_buf = "".b
        @send_mu = Mutex.new
        @send_offset = 0
        @send_fin = false
        @closed = false
      end

      # Read exactly n bytes. Blocks until n bytes available or EOF.
      def read(n)
        @recv_mu.synchronize do
          loop do
            if @recv_buf.bytesize >= n
              return @recv_buf.slice!(0, n)
            end
            if @recv_fin
              return @recv_buf.bytesize > 0 ? @recv_buf.slice!(0, @recv_buf.bytesize) : nil
            end
            @recv_cv.wait(@recv_mu)
          end
        end
      end

      # Read a single byte. Raises EOFError at EOF.
      def readbyte
        @recv_mu.synchronize do
          loop do
            if @recv_buf.bytesize > 0
              return @recv_buf.slice!(0, 1).getbyte(0)
            end
            raise EOFError, "end of stream" if @recv_fin
            @recv_cv.wait(@recv_mu)
          end
        end
      end

      # Read up to n bytes. Blocks until at least 1 byte available.
      def readpartial(n)
        @recv_mu.synchronize do
          loop do
            if @recv_buf.bytesize > 0
              len = [n, @recv_buf.bytesize].min
              return @recv_buf.slice!(0, len)
            end
            raise EOFError, "end of stream" if @recv_fin
            @recv_cv.wait(@recv_mu)
          end
        end
      end

      # Enqueue data for sending. Connection will flush.
      def write(data)
        @send_mu.synchronize do
          raise IOError, "stream closed" if @send_fin
          @send_buf << data.b
        end
        @connection&.notify_stream_data(self)
        data.bytesize
      end

      # Close the write side (sends FIN).
      def close
        return if @closed
        @closed = true
        @send_mu.synchronize { @send_fin = true }
        @connection&.notify_stream_data(self)
      end

      def close_read
        @recv_mu.synchronize do
          @recv_fin = true
          @recv_cv.broadcast
        end
      end

      # Called by connection when STREAM frame data arrives.
      def receive_data(data, offset, fin)
        @recv_mu.synchronize do
          # Simple: assume in-order delivery for now
          @recv_buf << data
          @recv_fin = true if fin
          @recv_cv.broadcast
        end
      end

      # Drain pending send data. Returns [data, offset, fin].
      def drain_send
        @send_mu.synchronize do
          data = @send_buf.dup
          offset = @send_offset
          @send_offset += data.bytesize
          @send_buf.clear
          fin = @send_fin && !@send_fin_sent
          [data, offset, fin]
        end
      end

      def send_pending?
        @send_mu.synchronize do
          @send_buf.bytesize > 0 || (@send_fin && !@send_fin_sent)
        end
      end

      def mark_fin_sent!
        @send_fin_sent = true
      end
    end
  end
end
