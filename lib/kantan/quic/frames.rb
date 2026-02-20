# frozen_string_literal: true

require "kantan/h3/varint"

module Kantan
  module QUIC
    module Frames
      PADDING            = 0x00
      PING               = 0x01
      ACK                = 0x02
      ACK_ECN            = 0x03
      RESET_STREAM       = 0x04
      STOP_SENDING       = 0x05
      CRYPTO             = 0x06
      NEW_TOKEN          = 0x07
      STREAM_BASE        = 0x08 # 0x08..0x0f
      MAX_DATA           = 0x10
      MAX_STREAM_DATA    = 0x11
      MAX_STREAMS_BIDI   = 0x12
      MAX_STREAMS_UNI    = 0x13
      DATA_BLOCKED       = 0x14
      STREAM_DATA_BLOCKED = 0x15
      STREAMS_BLOCKED_BIDI = 0x16
      STREAMS_BLOCKED_UNI  = 0x17
      NEW_CONNECTION_ID  = 0x18
      RETIRE_CONNECTION_ID = 0x19
      PATH_CHALLENGE     = 0x1a
      PATH_RESPONSE      = 0x1b
      CONNECTION_CLOSE   = 0x1c
      CONNECTION_CLOSE_APP = 0x1d
      HANDSHAKE_DONE     = 0x1e

      Varint = H3::Varint

      def self.parse(data)
        frames = []
        pos = 0
        while pos < data.bytesize
          type, pos = Varint.decode(data, pos)

          case type
          when PADDING
            # skip
          when PING
            frames << [:ping]
          when ACK
            largest, pos = Varint.decode(data, pos)
            delay, pos = Varint.decode(data, pos)
            range_count, pos = Varint.decode(data, pos)
            _first_range, pos = Varint.decode(data, pos)
            range_count.times do
              _gap, pos = Varint.decode(data, pos)
              _ack_range, pos = Varint.decode(data, pos)
            end
            frames << [:ack, largest, delay]
          when ACK_ECN
            # Same as ACK + 3 ECN counts
            largest, pos = Varint.decode(data, pos)
            delay, pos = Varint.decode(data, pos)
            range_count, pos = Varint.decode(data, pos)
            _first_range, pos = Varint.decode(data, pos)
            range_count.times do
              _gap, pos = Varint.decode(data, pos)
              _ack_range, pos = Varint.decode(data, pos)
            end
            _ect0, pos = Varint.decode(data, pos)
            _ect1, pos = Varint.decode(data, pos)
            _ecn_ce, pos = Varint.decode(data, pos)
            frames << [:ack, largest, delay]
          when RESET_STREAM
            _stream_id, pos = Varint.decode(data, pos)
            _error_code, pos = Varint.decode(data, pos)
            _final_size, pos = Varint.decode(data, pos)
          when STOP_SENDING
            _stream_id, pos = Varint.decode(data, pos)
            _error_code, pos = Varint.decode(data, pos)
          when CRYPTO
            offset, pos = Varint.decode(data, pos)
            length, pos = Varint.decode(data, pos)
            crypto_data = data.byteslice(pos, length)
            pos += length
            frames << [:crypto, offset, crypto_data]
          when NEW_TOKEN
            length, pos = Varint.decode(data, pos)
            pos += length
          when 0x08..0x0f
            fin = type & 0x01 != 0
            has_len = type & 0x02 != 0
            has_off = type & 0x04 != 0
            stream_id, pos = Varint.decode(data, pos)
            offset = 0
            if has_off
              offset, pos = Varint.decode(data, pos)
            end
            if has_len
              length, pos = Varint.decode(data, pos)
              stream_data = data.byteslice(pos, length)
              pos += length
            else
              stream_data = data.byteslice(pos, data.bytesize - pos)
              pos = data.bytesize
            end
            frames << [:stream, stream_id, offset, stream_data, fin]
          when MAX_DATA, DATA_BLOCKED
            _value, pos = Varint.decode(data, pos)
          when MAX_STREAM_DATA, STREAM_DATA_BLOCKED
            _stream_id, pos = Varint.decode(data, pos)
            _value, pos = Varint.decode(data, pos)
          when MAX_STREAMS_BIDI, MAX_STREAMS_UNI, STREAMS_BLOCKED_BIDI, STREAMS_BLOCKED_UNI
            _value, pos = Varint.decode(data, pos)
          when NEW_CONNECTION_ID
            _seq, pos = Varint.decode(data, pos)
            _retire, pos = Varint.decode(data, pos)
            cid_len = data.getbyte(pos); pos += 1
            pos += cid_len # connection ID
            pos += 16      # stateless reset token
          when RETIRE_CONNECTION_ID
            _seq, pos = Varint.decode(data, pos)
          when PATH_CHALLENGE, PATH_RESPONSE
            pos += 8 # 8-byte data
          when HANDSHAKE_DONE
            frames << [:handshake_done]
          when CONNECTION_CLOSE
            error_code, pos = Varint.decode(data, pos)
            frame_type, pos = Varint.decode(data, pos)
            reason_len, pos = Varint.decode(data, pos)
            reason = data.byteslice(pos, reason_len)
            pos += reason_len
            frames << [:connection_close, error_code, frame_type, reason]
          when CONNECTION_CLOSE_APP
            error_code, pos = Varint.decode(data, pos)
            reason_len, pos = Varint.decode(data, pos)
            reason = data.byteslice(pos, reason_len)
            pos += reason_len
            frames << [:connection_close, error_code, 0, reason]
          else
            # Unknown frame type — cannot determine length, stop parsing
            break
          end
        end
        frames
      end

      def self.build_crypto(offset, data)
        buf = "".b
        Varint.encode(buf, CRYPTO)
        Varint.encode(buf, offset)
        Varint.encode(buf, data.bytesize)
        buf << data
      end

      def self.build_ack(largest_ack, delay = 0)
        buf = "".b
        Varint.encode(buf, ACK)
        Varint.encode(buf, largest_ack)
        Varint.encode(buf, delay)
        Varint.encode(buf, 0) # range count
        Varint.encode(buf, 0) # first ack range
        buf
      end

      def self.build_stream(stream_id, offset, data, fin: false)
        flags = 0x02 # LEN always set
        flags |= 0x01 if fin
        flags |= 0x04 if offset > 0
        buf = "".b
        Varint.encode(buf, STREAM_BASE | flags)
        Varint.encode(buf, stream_id)
        Varint.encode(buf, offset) if offset > 0
        Varint.encode(buf, data.bytesize)
        buf << data
      end

      def self.build_handshake_done
        "\x1e".b
      end

      def self.build_padding(n)
        ("\x00" * n).b
      end

      def self.build_connection_close(error_code, reason: "")
        buf = "".b
        Varint.encode(buf, CONNECTION_CLOSE)
        Varint.encode(buf, error_code)
        Varint.encode(buf, 0) # frame type
        Varint.encode(buf, reason.bytesize)
        buf << reason.b
      end
    end
  end
end
