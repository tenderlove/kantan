# frozen_string_literal: true

# In-process mock QUIC transport for testing HTTP/3 without a real QUIC stack.
# Each stream is backed by a pair of IO.pipe.  A connection has an accept queue;
# open_stream creates pipe pairs and hands one end to the peer's accept queue.
module MockQuic
  class Stream
    attr_reader :id

    def initialize(id, reader, writer)
      @id = id
      @reader = reader
      @writer = writer
      @closed = false
    end

    def read(n)
      @reader.read(n)
    end

    def readbyte
      @reader.readbyte
    end

    def readpartial(n)
      @reader.readpartial(n)
    end

    def write(data)
      @writer.write(data)
    end

    def close
      return if @closed
      @closed = true
      @writer.close rescue nil
    end

    def close_read
      @reader.close rescue nil
    end
  end

  class Connection
    def initialize(is_server, peer = nil)
      @is_server = is_server
      @peer = peer
      @accept_queue = Thread::Queue.new
      @mu = Mutex.new
      @all_ios = []  # all pipe IOs for cleanup

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

        local_r, peer_w = IO.pipe   # data flows: peer_w → local_r
        peer_r, local_w = IO.pipe   # data flows: local_w → peer_r

        local_r.binmode; peer_w.binmode
        peer_r.binmode; local_w.binmode

        @all_ios.push(local_r, peer_w, peer_r, local_w)

        local_stream = Stream.new(id, peer_r, peer_w)
        peer_stream  = Stream.new(id, local_r, local_w)

        @peer.enqueue_stream(peer_stream) if @peer

        local_stream
      end
    end

    def enqueue_stream(stream)
      @accept_queue << stream
    end

    def close
      do_close_peer = false
      @mu.synchronize do
        return if @closed
        @closed = true
        do_close_peer = true
        @accept_queue.close
        @all_ios.each { _1.close rescue nil }
      end
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
