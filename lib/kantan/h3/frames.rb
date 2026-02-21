# frozen_string_literal: true

require "kantan/h3/varint"

module Kantan
  module H3
    module Frames
      # Frame types (RFC 9114 §7)
      DATA          = 0x00
      HEADERS       = 0x01
      CANCEL_PUSH   = 0x03
      SETTINGS      = 0x04
      PUSH_PROMISE  = 0x05
      GOAWAY        = 0x07
      MAX_PUSH_ID   = 0x0D

      # Unidirectional stream types (RFC 9114 §6.2)
      CONTROL       = 0x00
      PUSH          = 0x01
      QPACK_ENCODER = 0x02
      QPACK_DECODER = 0x03

      # Settings identifiers (RFC 9114 §7.2.4.1)
      QPACK_MAX_TABLE_CAPACITY = 0x01
      MAX_HEADER_LIST_SIZE     = 0x06
      QPACK_BLOCKED_STREAMS   = 0x07

      # Write a frame (type varint + length varint + payload) into +out+.
      def self.write(out, type, payload)
        Varint.encode(out, type)
        Varint.encode(out, payload.bytesize)
        out << payload
      end

      # Read a frame from +io+.  Returns [type, payload] or nil at EOF.
      def self.read(io)
        type = Varint.read(io)
        length = Varint.read(io)
        payload = length > 0 ? io.read(length) : "".b
        [type, payload]
      rescue EOFError
        nil
      end

      # Encode a settings hash ({id => value}) into a SETTINGS payload.
      def self.encode_settings(hash)
        out = "".b
        hash.each do |id, value|
          Varint.encode(out, id)
          Varint.encode(out, value)
        end
        out
      end

      # Non-blocking buffered frame parser. Accumulates bytes via feed,
      # returns complete frames via next_frame.
      class FrameReader
        def initialize
          @buf = "".b
        end

        def feed(data)
          @buf << data
        end

        # Returns [type, payload] or nil if incomplete.
        def next_frame
          return nil if @buf.empty?

          result = Varint.safe_decode(@buf, 0)
          return nil unless result
          type, pos = result

          result = Varint.safe_decode(@buf, pos)
          return nil unless result
          length, pos = result

          return nil if @buf.bytesize < pos + length

          payload = @buf.byteslice(pos, length)
          rest = pos + length
          @buf = rest < @buf.bytesize ? @buf.byteslice(rest, @buf.bytesize - rest) : "".b
          [type, payload]
        end

        def buffered?
          @buf.bytesize > 0
        end
      end

      # Decode a SETTINGS payload into a hash.
      def self.decode_settings(payload)
        settings = {}
        pos = 0
        while pos < payload.bytesize
          id, pos = Varint.decode(payload, pos)
          value, pos = Varint.decode(payload, pos)
          settings[id] = value
        end
        settings
      end
    end
  end
end
