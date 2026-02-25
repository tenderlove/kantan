# frozen_string_literal: true

require "openssl"
require "kantan/h3/frames"
require "kantan/h3/protocol"
require "kantan/qpack"
require "kantan/stream"

module Kantan
  module H3
    class Session
      include Protocol
      include OpenSSL::SSL

      QPACK_TABLE_CAPACITY = 4096
      QPACK_BLOCKED        = 100

      def initialize conn_ssl, io:, handler:
        @conn = conn_ssl
        @conn.default_stream_mode = :none
        @conn.incoming_stream_policy = INCOMING_STREAM_POLICY_ACCEPT
        @io = io
        @handler = handler

        @encoder = QPACK::Encoder.new(0)
        @decoder = QPACK::Decoder.new(QPACK_TABLE_CAPACITY, QPACK_BLOCKED)

        @streams = {}       # stream_id => Kantan::Stream
        @ssl_map = {}       # ssl object_id => SSL stream object
        @readers = {}       # stream_id => reader state hash
        @closed = false
        @control_stream = nil
        @encoder_stream = nil
        @decoder_stream = nil

        init
      end

      def send_headers stream_id, headers, has_body: false
        ssl = @ssl_map[stream_id] or return

        _enc_data, field_section = @encoder.encode(stream_id, headers)

        buf = "".b
        Frames.write(buf, Frames::HEADERS, field_section)
        ssl.syswrite(buf)

        stream = @streams.fetch(stream_id)
        stream.open! if stream.idle?
        unless has_body
          ssl.stream_conclude rescue nil
          stream.half_close_local!
        end
      rescue OpenSSL::SSL::SSLError, IOError
        # write failed
      end

      def send_body stream_id, body
        ssl = @ssl_map[stream_id] or return

        body = body.b if body.encoding != Encoding::BINARY
        buf = "".b
        Frames.write(buf, Frames::DATA, body)
        ssl.syswrite(buf)

        ssl.stream_conclude rescue nil
        @streams.fetch(stream_id).half_close_local!
      rescue OpenSSL::SSL::SSLError, IOError
        # write failed
      end

      private

      def open_streams
        @control_stream = @conn.new_stream(STREAM_FLAG_UNI)
        buf = "".b
        Varint.encode(buf, Frames::CONTROL)
        Frames.write(buf, Frames::SETTINGS, Frames.encode_settings({
          Frames::QPACK_MAX_TABLE_CAPACITY => 4096,
          Frames::QPACK_BLOCKED_STREAMS => 100,
        }))
        @control_stream.syswrite(buf)

        @encoder_stream = @conn.new_stream(STREAM_FLAG_UNI)
        @encoder_stream.syswrite(Frames::QPACK_ENCODER.chr)

        @decoder_stream = @conn.new_stream(STREAM_FLAG_UNI)
        @decoder_stream.syswrite(Frames::QPACK_DECODER.chr)
      end
    end
  end
end
