# frozen_string_literal: true

# In-process mock QUIC transport for testing HTTP/3 without a real QUIC stack.
# Streams use buffer+mutex (matching Kantan::QUIC::Stream API) instead of IO pipes.
module MockQuic
  class Stream
    attr_reader :id
    attr_accessor :on_readable, :peer

    def initialize id
      @id = id
      @recv_buf = "".b
      @recv_mu = Mutex.new
      @recv_cv = ConditionVariable.new
      @recv_fin = false
      @closed = false
      @peer = nil
    end

    # Called by the peer's write/close to deliver data.
    def receive_data data, fin
      @recv_mu.synchronize do
        @recv_buf << data
        @recv_fin = true if fin
        @recv_cv.broadcast
      end
      @on_readable&.call
    end

    # Non-blocking drain. Returns [data, fin] or nil if nothing available.
    def drain
      @recv_mu.synchronize do
        return nil if @recv_buf.empty? && !@recv_fin
        data = @recv_buf.dup
        @recv_buf.clear
        [data, @recv_fin]
      end
    end

    def read n
      @recv_mu.synchronize do
        loop do
          return @recv_buf.slice!(0, n) if @recv_buf.bytesize >= n
          return @recv_buf.bytesize > 0 ? @recv_buf.slice!(0, @recv_buf.bytesize) : nil if @recv_fin
          @recv_cv.wait(@recv_mu)
        end
      end
    end

    def readbyte
      @recv_mu.synchronize do
        loop do
          return @recv_buf.slice!(0, 1).getbyte(0) if @recv_buf.bytesize > 0
          raise EOFError, "end of stream" if @recv_fin
          @recv_cv.wait(@recv_mu)
        end
      end
    end

    def readpartial n
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

    def write data
      @peer&.receive_data(data.b, false)
      data.bytesize
    end

    def close
      return if @closed
      @closed = true
      @peer&.receive_data("".b, true)
    end

    def close_read
      @recv_mu.synchronize do
        @recv_fin = true
        @recv_cv.broadcast
      end
    end
  end

  class Connection
    def initialize is_server, peer = nil
      @is_server = is_server
      @peer = peer
      @accept_queue = Thread::Queue.new
      @mu = Mutex.new
      @streams = []

      # Stream ID counters (QUIC stream ID assignment)
      # Client bidi: 0, 4, 8...   Server bidi: 1, 5, 9...
      # Client uni:  2, 6, 10...  Server uni:  3, 7, 11...
      if is_server
        @next_bidi_id = 1
        @next_uni_id  = 3
      else
        @next_bidi_id = 0
        @next_uni_id  = 2
      end

      @closed = false
    end

    attr_writer :peer

    # Accept a stream opened by the peer.  Returns nil when connection is closed.
    def accept_stream
      stream = @accept_queue.pop
      stream # nil sentinel means closed
    end

    # Open a new stream.  Returns the local Stream handle.
    def open_stream(bidi:)
      @mu.synchronize do
        raise IOError, "connection closed" if @closed

        if bidi
          id = @next_bidi_id
          @next_bidi_id += 4
        else
          id = @next_uni_id
          @next_uni_id += 4
        end

        local_stream = Stream.new(id)
        peer_stream = Stream.new(id)
        local_stream.peer = peer_stream
        peer_stream.peer = local_stream

        @streams << local_stream << peer_stream

        @peer.enqueue_stream(peer_stream) if @peer

        local_stream
      end
    end

    def enqueue_stream stream
      @accept_queue << stream
    end

    def close
      streams_to_close = nil
      do_close_peer = false
      @mu.synchronize do
        return if @closed
        @closed = true
        do_close_peer = true
        streams_to_close = @streams.dup
        @accept_queue.close
      end
      streams_to_close&.each { |s| s.close_read rescue nil }
      @peer&.close if do_close_peer
    end
  end

  # Create a linked client/server connection pair.
  def self.pair
    client = Connection.new(false)
    server = Connection.new(true)
    client.peer = server
    server.peer = client
    [client, server]
  end
end
