require "htwo/errors"

module HTWO
  Stream = Struct.new(:id, :headers, :data, :session, :state, :window_size, :rst_received, :content_length, :received_end_stream, :pending_body) do
    def respond headers, body: nil
      session.send_response self, headers, body
    end

    # State predicates
    def idle?
      state == :idle
    end

    def open?
      state == :open
    end

    def closed?
      state == :closed
    end

    def half_closed_remote?
      state == :half_closed_remote
    end

    def half_closed_local?
      state == :half_closed_local
    end

    # State transitions
    def open!
      self.state = :open
    end

    def half_close_remote!
      if open?
        self.state = :half_closed_remote
      elsif half_closed_local?
        self.state = :closed
      end
    end

    def half_close_local!
      if open?
        self.state = :half_closed_local
      elsif half_closed_remote?
        self.state = :closed
      end
    end

    def close!
      self.state = :closed
    end

    def receiving_headers! end_stream, remaining
      # Second HEADERS without END_STREAM is invalid (trailers must end the stream)
      if headers && !end_stream
        raise Errors::StreamError.new("Second HEADERS without END_STREAM", id, remaining)
      end

      if closed?
        # If stream was closed with RST_STREAM, send RST_STREAM (stream error)
        # If closed with END_STREAM, send GOAWAY (connection error)
        if rst_received
          raise Errors::StreamClosed.new("HEADERS on RST closed stream", id, remaining)
        else
          raise Errors::StreamClosedError.new("HEADERS on closed stream", remaining)
        end
      elsif half_closed_remote?
        raise Errors::StreamClosed.new("HEADERS on half-closed-remote stream", id, remaining)
      end
    end
  end
end
