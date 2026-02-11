# frozen_string_literal: true

require "htwo/hpack"
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
      :CONTINUATION,
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
      ].freeze

      NAMES.each_with_index { next unless _1; const_set(_1, _2) }

      DEFAULT = [
        nil,
        nil, # default is 4096
        nil, # don't specify push promise
        100, # max concurrent streams
        65535, # initial window size
      ].freeze

      def self.encode stream_id, settings
        settings = settings.each_with_index.select { |v, _| v }
        bytesize = settings.length * 6
        type = 0x4

        [
          (bytesize << 8) | type,
          0,
          stream_id
        ].pack("NCN") + settings.map { |val, i|
          [i, val].pack("nN")
        }.join
      end

      DEFAULT_ENCODED = encode(0, DEFAULT).freeze
    end
  end

  class Handler
    def on_headers stream; end
    def on_data stream, chunk; end
    def on_request stream; end
    def on_ping rtt; end
    def on_close; end
  end

  Stream = Struct.new(:id, :headers, :data, :session) do
    def respond headers, body: nil
      session.send_response self, headers, body
    end
  end

  class Session
    HEADER_BUFF = ("\0".b * 9).freeze
    private_constant :HEADER_BUFF

    CONNECTION_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".b.freeze

    attr_reader :io

    def initialize io, handler:
      @io = io
      @handler = handler

      # Table used to encode values sent to the peer
      @encoding_table = HPACK.new

      # Table used to decode values sent by the peer
      @decoding_table = HPACK.new

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
      @next_stream_id = 1
      @streams = {}
    end

    def get path
      stream_id = @next_stream_id
      @next_stream_id += 2
      @streams[stream_id] = Stream.new(stream_id, nil, nil, self)

      headers = [
        [":method", "GET"],
        [":path", "/"],
        [":scheme", "http"],
        [":authority", "localhost:8443"],
        ["priority", "u=3"],
        ["accept", "*/*"],
        ["accept-encoding", "gzip, deflate"],
        ["user-agent", "htwo"],
      ]

      hpack = @encoding_table.encode headers

      send_headers io, stream_id, hpack
      stream_id
    end

    def finish
      send_goaway io, 0x0 # NO_ERROR
      io.flush
      io.close
      @reader.join
    end

    def connect
      start_read_thread
      io.write CONNECTION_PREFACE
      send_settings io, nil
    end

    def receive
      preface = io.read CONNECTION_PREFACE.bytesize
      if preface != CONNECTION_PREFACE
        send_goaway io, 0x1 # PROTOCOL_ERROR
        io.close
        return
      end
      send_settings io, nil
      start_read_thread
    end

    def ping
      ts = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)
      send_ping io, [ts].pack("Q>")
    end

    private

    def start_read_thread
      @reader = Thread.new { read_loop }
    end

    def read_loop
      header_buff = HEADER_BUFF.dup

      while true
        begin
          str = io.readpartial(9, header_buff)
        rescue IOError, Errno::ECONNRESET
          break
        end
        len_type, flags, stream_ident = str.unpack("NCN")
        len = len_type >> 8
        type = len_type & 0xFF
        stream_ident &= 0x7FFF_FFFF # clear reserved bit

        if len > 16384 && type != 0x4 # SETTINGS_MAX_FRAME_SIZE default
          send_goaway io, 0x6 # FRAME_SIZE_ERROR
          io.close
          break
        end

        case type
        when 0x0 # data
          handle_data io, len, flags, stream_ident
        when 0x1 # headers
          break if handle_headers(io, len, flags, stream_ident) == :close
        when 0x2 # priority
          raise NotImplementedError
        when 0x3 # RST_STREAM
          raise NotImplementedError
        when 0x4 # settings
          handle_settings io, len, flags, stream_ident
        when 0x5 # PUSH_PROMISE
          raise NotImplementedError
        when 0x6 # ping
          handle_ping io, len, flags, stream_ident
        when 0x7 # goaway
          handle_goaway io, len, flags, stream_ident
          io.close
          break
        when 0x8 # window update
          handle_window_update io, len, flags, stream_ident
        when 0x9 # CONTINUATION
          raise NotImplementedError
        else
          io.read(len) if len > 0 # skip unknown frame types (RFC 7540 4.1)
        end
      end

      @handler.on_close
    end

    def send_ping io, data
      puts __method__
      io.write "\x00\x00\x08\x06\x00\x00\x00\x00\x00"
      io.write data
    end

    def send_headers io, ident, hpack
      len = hpack.bytesize
      len_type = (len << 8) | 0x1

      flags = 0x04 | # END_HEADERS
        0x01 # END_STREAM

      io.write [len_type, flags, ident].pack("NCN")
      io.write hpack
    end

    def send_settings io, settings
      if settings
        raise NotImplementedError
      else
        io.write Frames::Settings::DEFAULT_ENCODED
      end
    end

    public

    def send_response stream, headers, body
      hpack = @encoding_table.encode headers
      len = hpack.bytesize
      len_type = (len << 8) | 0x1

      flags = 0x04 # END_HEADERS
      flags |= 0x01 unless body # END_STREAM if no body

      io.write [len_type, flags, stream.id].pack("NCN")
      io.write hpack

      if body
        body = body.b if body.encoding != Encoding::BINARY
        len = body.bytesize
        len_type = (len << 8) | 0x0
        flags = 0x01 # END_STREAM
        io.write [len_type, flags, stream.id].pack("NCN")
        io.write body
      end
    end

    private

    def send_goaway io, error
      len = 8
      len_type = (len << 8) | 0x7
      flags = 0
      ident = 0
      last_stream_id = 0
      io.write [len_type, flags, ident, last_stream_id, error].pack("NCNNN")
    end

    def send_settings_ack io
      io.write "\x00\x00\x00\x04\x01\x00\x00\x00\x00"
    end

    def handle_data io, len, flags, stream_id
      chunk = io.read(len)
      stream = @streams[stream_id]
      stream.data ||= "".b
      stream.data << chunk
      @handler.on_data stream, chunk
      @handler.on_request stream if flags[0].positive?
    end

    def handle_headers io, len, flags, stream_id
      payload = io.read(len)
      return unless payload
      begin
        headers = @decoding_table.decode payload
      rescue CompressionError
        send_goaway io, 0x9 # COMPRESSION_ERROR
        io.close
        return :close
      end
      stream = @streams[stream_id] ||= Stream.new(stream_id, nil, nil, self)
      stream.headers = headers
      @handler.on_headers stream
      @handler.on_request stream if flags[0].positive?
    end

    def handle_ping io, len, flags, stream_ident
      raise NotImplementedError unless stream_ident.zero?
      raise NotImplementedError unless len == 8

      flags &= 0x01

      payload = io.read(8)
      if flags.zero?
        # Peer PING: echo back with ACK flag
        io.write "\x00\x00\x08\x06\x01\x00\x00\x00\x00"
        io.write payload
      else
        # ACK of our PING: compute RTT
        sent_at = payload.unpack1("Q>")
        rtt_ns = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond) - sent_at
        @handler.on_ping rtt_ns
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

  class ClientHandler < Handler
    def initialize
      @ports = {}
      @ping_port = nil
    end

    attr_writer :ping_port

    def register stream_id, port
      @ports[stream_id] = port
    end

    def on_headers stream
      @ports[stream.id] << stream.headers
    end

    def on_data stream, chunk
      @ports[stream.id] << chunk.freeze
    end

    def on_request stream
      @ports[stream.id] << nil
      @ports.delete stream.id
    end

    def on_ping rtt
      @ping_port << rtt
    end

    def on_close
      @ports.each_value { |port| port << nil }
      @ports.clear
    end
  end

  class Connection
    def initialize io
      @s = Ractor.new(io) { |io|
        handler = ClientHandler.new
        session = Session.new(io, handler: handler)
        while true
          cmd, port, data = Ractor.receive

          case cmd
          when :connect then session.connect
          when :receive then session.receive
          when :ping
            handler.ping_port = port
            session.ping
          when :get
            stream_id = session.get(data)
            handler.register(stream_id, port)
          when :finish then session.finish; break
          else
          end
        end
      }
    end

    def connect
      @s << [:connect, Ractor.current.default_port]
    end

    def receive
      @s << [:receive, Ractor.current.default_port]
    end

    def finish
      @s << [:finish, Ractor.current.default_port]
      @s.value
    end

    def ping
      @s << [:ping, Ractor.current.default_port]
      Ractor.receive
    end

    def get path
      @s << [:get, Ractor.current.default_port, path]
      headers = Ractor.receive
      body = "".b
      while part = Ractor.receive
        body << part
      end
      [headers, body]
    end
  end
end

if $0 == __FILE__
  require "socket"
  require "openssl"
  require "uri"

  uri = URI.parse "https://localhost:8443"

  tcp = TCPSocket.new uri.host, uri.port
  tcp.sync = true

  client = HTWO::Connection.new tcp
  client.connect
  p PING: client.ping
  p client.get "/"
  client.finish
end
