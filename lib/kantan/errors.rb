# frozen_string_literal: true

module Kantan
  module Errors
    class Error < StandardError; end

    class ConnectionError < Error
      attr_reader :remaining, :error_code

      def initialize msg, remaining, error_code = 0x1
        super(msg)
        @remaining = remaining
        @error_code = error_code
      end
    end

    class ProtocolError < ConnectionError
      def initialize msg, remaining
        super(msg, remaining, 0x1)
      end
    end

    class FrameSizeError < ConnectionError
      def initialize msg, remaining
        super(msg, remaining, 0x6)
      end
    end

    class FlowControlError < ConnectionError
      def initialize msg, remaining
        super(msg, remaining, 0x3)
      end
    end

    class StreamClosedError < ConnectionError
      def initialize msg, remaining
        super(msg, remaining, 0x5)
      end
    end

    class CompressionError < ConnectionError
      def initialize msg = "Compression error", remaining = 0
        super(msg, remaining, 0x9)
      end
    end

    class StreamError < Error
      attr_reader :stream_id, :error_code, :remaining

      def initialize msg, stream_id, remaining = 0, error_code = 0x1
        super(msg)
        @stream_id = stream_id
        @remaining = remaining
        @error_code = error_code
      end
    end

    class StreamClosed < StreamError
      def initialize msg, stream_id, remaining = 0
        super(msg, stream_id, remaining, 0x5)
      end
    end

    class RefusedStream < StreamError
      def initialize msg, stream_id, remaining = 0
        super(msg, stream_id, remaining, 0x7)
      end
    end
  end
end
