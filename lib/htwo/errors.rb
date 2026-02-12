# frozen_string_literal: true

module HTWO
  module Errors
    class Error < StandardError; end
    class CompressionError < Error; end

    class ProtocolError < Error
      attr_reader :len

      def initialize msg, len
        super(msg)
      end
    end
  end
end
