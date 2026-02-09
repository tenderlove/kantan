# frozen_string_literal: true

require "socket"
require "openssl"
require "uri"
#require "http2"

module HTWO
  module Frames
    NAMES = [
      :DATA,
      :HEADERS,
      :PRIORITY,
      :RST_STREAM,
      :SETTINGS,
      :PUSH_PROMISE,
      :PING,
      :GOAWAY,
      :WINDOW_UPDATE,
    ]

    NAMES.each_with_index { next unless _1; const_set(_1, _2) }

    class Settings
      NAMES = [
        nil,
        :HEADER_TABLE_SIZE,
        :ENABLE_PUSH,
        :MAX_CONCURRENT_STREAMS,
        :INITIAL_WINDOW_SIZE,
        :MAX_FRAME_SIZE,
        :MAX_HEADER_LIST_SIZE,
      ]

      NAMES.each_with_index { next unless _1; const_set(_1, _2) }
    end
  end

  class Session
    HEADER_BUFF = ("\0".b * 9).freeze
    private_constant :HEADER_BUFF

    CONNECTION_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".b.freeze

    attr_reader :io

    def initialize io
      @io = io

      # Table used to encode values sent to the peer
      @encoding_table = nil

      # Table used to decode values sent by the peer
      @decoding_table = nil

      @peer_settings = [
        0,
        4096, # default header table size,
        1,    # default enable_push
        -1,   # default value max concurrent streams (-1 for unlimited)
        65535, # initial window size
        16384, # initial max frame size
        -1,    # max header list size (-1 for not set)
      ]

      @window_size = 65535

      @stream_ports = [[]]

      @reader = Thread.new do
        header_buff = HEADER_BUFF.dup

        while true
          str = io.readpartial(9, header_buff)
          len_type, flags, stream_ident = str.unpack("NCN")
          len = len_type >> 8
          type = len_type & 0xFF
          stream_ident &= 0x7FFF_FFF # clear reserved bit

          case type
          when 0x4 # settings
            handle_settings io, len, flags, stream_ident
          when 0x6 # ping
            handle_ping io, len, flags, stream_ident
          when 0x7 # goaway
            handle_goaway io, len, flags, stream_ident
            io.close
            break
          when 0x8 # window update
            handle_window_update io, len, flags, stream_ident
          else
            raise "unknown type #{type}"
          end
        end

        @stream_ports.each { |port_list| port_list.each { |port| port << nil if port } }
      end
    end

    def finish port
      @reader.join
    end

    def connect port
      io.write CONNECTION_PREFACE
      send_settings io, nil
    end

    def ping port
      @stream_ports[0][Frames::PING] = port
      ts = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)
      send_ping io, [ts].pack("Q>")
    end

    private

    def send_ping io, data
      puts __method__
      io.write "\x00\x00\x08\x06\x00\x00\x00\x00\x00"
      io.write data
    end

    def send_settings io, settings
      if settings
        raise NotImplementedError
      else
        io.write "\x00\x00\x00\x04\x00\x00\x00\x00\x00"
      end
    end

    def send_settings_ack io
      io.write "\x00\x00\x00\x04\x01\x00\x00\x00\x00"
    end

    def handle_ping io, len, flags, stream_ident
      raise NotImplementedError unless stream_ident.zero?
      raise NotImplementedError unless len == 8

      if flags.zero?
        raise NotImplementedError
      else
        payload = io.read(8)
        sent_at = payload.unpack1("Q>")
        rtt_ns = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond) - sent_at
        @stream_ports[0][Frames::PING] << rtt_ns
      end
    end

    def handle_settings io, len, flags, stream_ident
      puts __method__
      read = 0

      if flags.positive?
        if len.positive?
          raise "fixme: connection error case"
        end
        puts "got ack"
        return
      end

      s = "\0".b * 6
      while read < len
        ident, value = io.readpartial(6, s).unpack("nN")
        @peer_settings[ident] = value
        read += 6
      end
      send_settings_ack io
    end

    def handle_goaway io, len, flags, stream_ident
      puts __method__
      raise NotImplementedError unless stream_ident.zero?

      buff = "\0".b * 4
      last_stream_id = io.readpartial(4, buff).unpack1("N") & 0x7FFF_FFF
      error_code = io.readpartial(4, buff).unpack1("N")
    end

    def handle_window_update io, len, flags, stream_ident
      puts __method__
      increment = io.readpartial(4).unpack1("N") & 0x7FFF_FFF
      raise NotImplementedError unless stream_ident == 0
      @window_size += increment
    end
  end

  class Connection
    def initialize io
      @s = Ractor.new(io) { |io|
        session = Session.new(io)
        while true
          cmd, port = Ractor.receive

          case cmd
          when :connect then session.connect(port)
          when :ping then session.ping(port)
          when :finish then session.finish(port); break
          else
          end
        end
      }
    end

    def connect
      @s << [:connect, Ractor.current.default_port]
    end

    def finish
      @s << [:finish, Ractor.current.default_port]
      @s.value
    end

    def ping
      @s << [:ping, Ractor.current.default_port]
      Ractor.receive
    end
  end
end

if $0 == __FILE__
  uri = URI.parse "https://localhost:8443"

  tcp = TCPSocket.new uri.host, uri.port
  tcp.sync = true

  client = HTWO::Connection.new tcp
  client.connect
  5.times do
    p PING: client.ping
    sleep 1
  end
  client.finish
end
