# frozen_string_literal: true

require "http2/huffman"

module HTWO
  # HTTP/2 Frame Types
  FRAME_TYPES = {
    data: 0x0,
    headers: 0x1,
    priority: 0x2,
    rst_stream: 0x3,
    settings: 0x4,
    push_promise: 0x5,
    ping: 0x6,
    goaway: 0x7,
    window_update: 0x8,
    continuation: 0x9
  }.freeze

  # Frame type lookup
  FRAME_TYPE_NAMES = FRAME_TYPES.to_a.sort_by(&:last).map(&:first)

  # Frame Flags
  FLAGS = {
    end_stream: 0x1,
    end_headers: 0x4,
    padded: 0x8,
    priority: 0x20,
    ack: 0x1
  }.freeze

  # Error codes
  ERROR_CODES = {
    no_error: 0x0,
    protocol_error: 0x1,
    internal_error: 0x2,
    flow_control_error: 0x3,
    settings_timeout: 0x4,
    stream_closed: 0x5,
    frame_size_error: 0x6,
    refused_stream: 0x7,
    cancel: 0x8,
    compression_error: 0x9,
    connect_error: 0xa,
    enhance_your_calm: 0xb,
    inadequate_security: 0xc,
    http_1_1_required: 0xd
  }.freeze

  # Settings parameters
  SETTINGS = {
    header_table_size: 0x1,
    enable_push: 0x2,
    max_concurrent_streams: 0x3,
    initial_window_size: 0x4,
    max_frame_size: 0x5,
    max_header_list_size: 0x6
  }.freeze

  # Default settings
  DEFAULT_SETTINGS = {
    header_table_size: 4096,
    enable_push: 0,  # Disabled - we don't support server push
    max_concurrent_streams: 100,
    initial_window_size: 65535,
    max_frame_size: 16384,
    max_header_list_size: nil
  }.freeze

  # Connection preface
  CONNECTION_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".b

  class Frame
    attr_accessor :length, :type, :flags, :stream_id, :payload

    def initialize(type:, flags: 0, stream_id: 0, payload: "")
      @type = type
      @flags = flags
      @stream_id = stream_id
      @payload = payload
      @length = payload.bytesize
    end

    def flag?(flag_name)
      flag_value = FLAGS[flag_name]
      (@flags & flag_value) != 0
    end

    def set_flag(flag_name)
      @flags |= FLAGS[flag_name]
    end

    def to_binary
      # Frame format: 3 bytes length, 1 byte type, 1 byte flags, 4 bytes stream_id
      [
        @length,
        FRAME_TYPES[@type],
        @flags,
        @stream_id & 0x7FFFFFFF  # Clear reserved bit
      ].pack("N C C N")[1..-1] + @payload  # Skip first byte of length (only need 3 bytes)
    end

    def self.parse(io)
      header = io.read(9)
      return nil if header.nil? || header.bytesize < 9

      # Parse 24-bit length (3 bytes)
      length_bytes = "\x00#{header[0..2]}"  # Pad to 4 bytes for unpacking
      length = length_bytes.unpack1("N")

      type = header[3].unpack1("C")
      flags = header[4].unpack1("C")
      stream_id = header[5..8].unpack1("N") & 0x7FFFFFFF  # Clear reserved bit

      payload = length > 0 ? io.read(length) : ""
      return nil if payload.nil? || payload.bytesize < length

      frame = new(
        type: FRAME_TYPE_NAMES[type] || type,
        flags: flags,
        stream_id: stream_id,
        payload: payload
      )

      frame
    end
  end

  # HPACK - Header Compression for HTTP/2
  class HPACK
    # Static table as defined in RFC 7541
    STATIC_TABLE = [
      [":authority", ""],
      [":method", "GET"],
      [":method", "POST"],
      [":path", "/"],
      [":path", "/index.html"],
      [":scheme", "http"],
      [":scheme", "https"],
      [":status", "200"],
      [":status", "204"],
      [":status", "206"],
      [":status", "304"],
      [":status", "400"],
      [":status", "404"],
      [":status", "500"],
      ["accept-charset", ""],
      ["accept-encoding", "gzip, deflate"],
      ["accept-language", ""],
      ["accept-ranges", ""],
      ["accept", ""],
      ["access-control-allow-origin", ""],
      ["age", ""],
      ["allow", ""],
      ["authorization", ""],
      ["cache-control", ""],
      ["content-disposition", ""],
      ["content-encoding", ""],
      ["content-language", ""],
      ["content-length", ""],
      ["content-location", ""],
      ["content-range", ""],
      ["content-type", ""],
      ["cookie", ""],
      ["date", ""],
      ["etag", ""],
      ["expect", ""],
      ["expires", ""],
      ["from", ""],
      ["host", ""],
      ["if-match", ""],
      ["if-modified-since", ""],
      ["if-none-match", ""],
      ["if-range", ""],
      ["if-unmodified-since", ""],
      ["last-modified", ""],
      ["link", ""],
      ["location", ""],
      ["max-forwards", ""],
      ["proxy-authenticate", ""],
      ["proxy-authorization", ""],
      ["range", ""],
      ["referer", ""],
      ["refresh", ""],
      ["retry-after", ""],
      ["server", ""],
      ["set-cookie", ""],
      ["strict-transport-security", ""],
      ["transfer-encoding", ""],
      ["user-agent", ""],
      ["vary", ""],
      ["via", ""],
      ["www-authenticate", ""]
    ].freeze

    def initialize(table_size: 4096)
      @table_size = table_size
      @dynamic_table = []
      @dynamic_table_size = 0
    end

    def encode(headers)
      output = String.new(encoding: Encoding::BINARY)

      headers.each do |name, value|
        name = name.to_s.downcase
        value = value.to_s

        # Try to find exact match in static table
        index = STATIC_TABLE.index([name, value])
        if index
          # Indexed header field
          output << encode_integer(index + 1, 7, 0b10000000)
        else
          # Try to find name match
          name_index = STATIC_TABLE.index { |n, _| n == name }
          if name_index
            # Literal header field with incremental indexing - indexed name
            output << encode_integer(name_index + 1, 6, 0b01000000)
            output << encode_string(value)
          else
            # Literal header field with incremental indexing - new name
            output << encode_integer(0, 6, 0b01000000)
            output << encode_string(name)
            output << encode_string(value)
          end

          # Add to dynamic table
          add_to_dynamic_table(name, value)
        end
      end

      output
    end

    def decode(data)
      headers = []
      pos = 0

      while pos < data.bytesize
        byte = data[pos].unpack1("C")

        if (byte & 0b10000000) != 0
          # Indexed header field
          index, consumed = decode_integer(data, pos, 7)
          pos += consumed
          headers << lookup_table(index)
        elsif (byte & 0b01000000) != 0
          # Literal header field with incremental indexing
          index, consumed = decode_integer(data, pos, 6)
          pos += consumed

          if index == 0
            name, consumed = decode_string(data, pos)
            pos += consumed
          else
            name, _ = lookup_table(index)
          end

          value, consumed = decode_string(data, pos)
          pos += consumed

          headers << [name, value]
          add_to_dynamic_table(name, value)
        elsif (byte & 0b00100000) != 0
          # Dynamic table size update
          size, consumed = decode_integer(data, pos, 5)
          pos += consumed
          update_table_size(size)
        else
          # Literal header field without indexing or never indexed
          indexed = (byte & 0b0001_0000) != 0
          index, consumed = decode_integer(data, pos, 4)
          pos += consumed

          if index == 0
            name, consumed = decode_string(data, pos)
            pos += consumed
          else
            name, _ = lookup_table(index)
          end

          value, consumed = decode_string(data, pos)
          pos += consumed

          headers << [name, value]
        end
      end

      headers
    end

    private

    def encode_integer(value, prefix_bits, prefix)
      max_prefix = (1 << prefix_bits) - 1

      if value < max_prefix
        [prefix | value].pack("C")
      else
        output = [prefix | max_prefix].pack("C")
        value -= max_prefix

        while value >= 128
          output << [(value % 128) + 128].pack("C")
          value /= 128
        end

        output << [value].pack("C")
        output
      end
    end

    def decode_integer(data, pos, prefix_bits)
      max_prefix = (1 << prefix_bits) - 1
      byte = data[pos].unpack1("C")
      value = byte & max_prefix
      consumed = 1

      if value < max_prefix
        return [value, consumed]
      end

      # RFC 7541 Section 5.1: Variable-length integer decoding
      m = 0
      loop do
        break if pos + consumed >= data.bytesize
        byte = data[pos + consumed].unpack1("C")
        consumed += 1
        value += (byte & 0x7F) << m  # Correct formula: (byte & 0x7F) * 2^m
        m += 7
        break if (byte & 0x80) == 0
      end

      [value, consumed]
    end

    def encode_string(str, huffman: false)
      # Simple non-huffman encoding
      length = str.bytesize
      encode_integer(length, 7, 0b00000000) + str
    end

    def decode_string(data, pos)
      byte = data[pos].unpack1("C")
      huffman = (byte & 0b10000000) != 0
      length, consumed = decode_integer(data, pos, 7)
      pos += consumed

      str = data[pos, length]

      # Decode Huffman if flag is set
      str = Huffman.decode(str) if huffman

      [str, consumed + length]
    end

    def add_to_dynamic_table(name, value)
      entry_size = name.bytesize + value.bytesize + 32
      @dynamic_table.unshift([name, value])
      @dynamic_table_size += entry_size

      # Evict entries if over size limit
      while @dynamic_table_size > @table_size && !@dynamic_table.empty?
        evicted = @dynamic_table.pop
        @dynamic_table_size -= evicted[0].bytesize + evicted[1].bytesize + 32
      end
    end

    def lookup_table(index)
      if index <= STATIC_TABLE.size
        STATIC_TABLE[index - 1]
      else
        dynamic_index = index - STATIC_TABLE.size - 1
        @dynamic_table[dynamic_index]
      end
    end

    def update_table_size(size)
      @table_size = size
      # Evict entries if necessary
      while @dynamic_table_size > @table_size && !@dynamic_table.empty?
        evicted = @dynamic_table.pop
        @dynamic_table_size -= evicted[0].bytesize + evicted[1].bytesize + 32
      end
    end
  end

  class Stream
    attr_reader :id, :state, :window_size, :headers, :data
    attr_accessor :parent_id, :weight, :received_headers, :received_data

    STATES = [:idle, :reserved_local, :reserved_remote, :open,
              :half_closed_local, :half_closed_remote, :closed].freeze

    def initialize(id, window_size: 65535)
      @id = id
      @state = :idle
      @window_size = window_size
      @headers = []
      @data = String.new(encoding: Encoding::BINARY)
      @received_headers = []
      @received_data = String.new(encoding: Encoding::BINARY)
      @parent_id = nil
      @weight = 16
    end

    def send_headers!
      case @state
      when :idle
        @state = :open
      when :reserved_local
        @state = :half_closed_remote
      when :half_closed_remote, :open
        # Already open or half-closed remote, can still send headers
      else
        raise "Invalid state transition: send_headers from #{@state}"
      end
    end

    def receive_headers!
      case @state
      when :idle
        @state = :open
      when :reserved_remote
        @state = :half_closed_local
      when :half_closed_local, :open
        # Already open or half-closed local, can still receive headers
      else
        raise "Invalid state transition: receive_headers from #{@state}"
      end
    end

    def send_data!
      case @state
      when :open, :half_closed_remote
        # Valid
      else
        raise "Invalid state transition: send_data from #{@state}"
      end
    end

    def receive_data!
      case @state
      when :open, :half_closed_local
        # Valid
      else
        raise "Invalid state transition: receive_data from #{@state}"
      end
    end

    def close_local!
      case @state
      when :open
        @state = :half_closed_local
      when :half_closed_remote
        @state = :closed
      else
        @state = :closed
      end
    end

    def close_remote!
      case @state
      when :open
        @state = :half_closed_remote
      when :half_closed_local
        @state = :closed
      else
        @state = :closed
      end
    end

    def closed?
      @state == :closed
    end

    def update_window(delta)
      @window_size += delta
    end
  end

  class Connection
    attr_reader :streams, :settings, :remote_settings, :state
    attr_accessor :on_stream, :on_headers, :on_data, :on_close

    def initialize(socket, is_server: true)
      @socket = socket
      @is_server = is_server
      @state = :new

      @streams = {}
      @last_stream_id = is_server ? 0 : -1  # Server uses even, client uses odd

      @settings = DEFAULT_SETTINGS.dup
      @remote_settings = DEFAULT_SETTINGS.dup

      @window_size = DEFAULT_SETTINGS[:initial_window_size]
      @remote_window_size = DEFAULT_SETTINGS[:initial_window_size]

      @encoder = HPACK.new(table_size: @settings[:header_table_size])
      @decoder = HPACK.new(table_size: @settings[:header_table_size])

      @header_continuation = {}

      # Callbacks
      @on_stream = nil
      @on_headers = nil
      @on_data = nil
      @on_close = nil
    end

    def start
      if @is_server
        # Server must receive connection preface
        preface = @socket.read(CONNECTION_PREFACE.bytesize)
        unless preface == CONNECTION_PREFACE
          raise "Invalid connection preface"
        end

        # Send settings frame
        send_settings(@settings)
        @state = :connected
      else
        # Client must send connection preface
        @socket.write(CONNECTION_PREFACE)

        # Send settings frame
        send_settings(@settings)
        @state = :connected
      end
    end

    def run
      loop do
        frame = Frame.parse(@socket)
        break if frame.nil?

        handle_frame(frame)
      end
    rescue => e
      puts "Connection error: #{e.message}"
      puts e.backtrace
    ensure
      @on_close&.call
      @socket.close unless @socket.closed?
    end

    def send_headers(stream_id, headers, end_stream: false)
      stream = get_or_create_stream(stream_id)
      stream.send_headers!

      # Encode headers
      encoded = @encoder.encode(headers)

      # Create HEADERS frame
      flags = FLAGS[:end_headers]
      flags |= FLAGS[:end_stream] if end_stream

      frame = Frame.new(
        type: :headers,
        flags: flags,
        stream_id: stream_id,
        payload: encoded
      )

      write_frame(frame)

      stream.close_local! if end_stream
    end

    def send_data(stream_id, data, end_stream: false)
      stream = @streams[stream_id]
      raise "Stream #{stream_id} not found" unless stream

      stream.send_data!

      flags = 0
      flags |= FLAGS[:end_stream] if end_stream

      frame = Frame.new(
        type: :data,
        flags: flags,
        stream_id: stream_id,
        payload: data
      )

      write_frame(frame)

      stream.close_local! if end_stream
    end

    def new_stream
      @last_stream_id += 2
      stream_id = @last_stream_id
      get_or_create_stream(stream_id)
    end

    def close
      # Send GOAWAY frame
      frame = Frame.new(
        type: :goaway,
        stream_id: 0,
        payload: [@last_stream_id, ERROR_CODES[:no_error]].pack("N N")
      )
      write_frame(frame)

      @socket.close unless @socket.closed?
    end

    private

    def handle_frame(frame)
      case frame.type
      when :settings
        handle_settings(frame)
      when :headers
        handle_headers(frame)
      when :data
        handle_data(frame)
      when :window_update
        handle_window_update(frame)
      when :ping
        handle_ping(frame)
      when :goaway
        handle_goaway(frame)
      when :rst_stream
        handle_rst_stream(frame)
      when :priority
        handle_priority(frame)
      when :continuation
        handle_continuation(frame)
      else
        # Unknown frame type, ignore per spec
      end
    end

    def handle_settings(frame)
      if frame.flag?(:ack)
        # Settings acknowledged
        return
      end

      # Parse settings
      payload = frame.payload
      pos = 0

      while pos < payload.bytesize
        id = payload[pos, 2].unpack1("n")
        value = payload[pos + 2, 4].unpack1("N")
        pos += 6

        setting_name = SETTINGS.key(id)
        @remote_settings[setting_name] = value if setting_name

        # Update decoder table size if needed
        if id == SETTINGS[:header_table_size]
          @decoder = HPACK.new(table_size: value)
        end
      end

      # Send settings ACK
      ack_frame = Frame.new(
        type: :settings,
        flags: FLAGS[:ack],
        stream_id: 0,
        payload: ""
      )
      write_frame(ack_frame)
    end

    def handle_headers(frame)
      stream_id = frame.stream_id
      stream = get_or_create_stream(stream_id)

      # Handle continuation
      if frame.flag?(:end_headers)
        # Complete headers
        header_data = @header_continuation[stream_id].to_s + frame.payload
        @header_continuation.delete(stream_id)

        headers = @decoder.decode(header_data)
        stream.received_headers.concat(headers)

        stream.receive_headers!

        @on_headers&.call(stream, headers)

        if frame.flag?(:end_stream)
          stream.close_remote!
          @on_stream&.call(stream)
        end
      else
        # Continuation needed
        @header_continuation[stream_id] ||= String.new(encoding: Encoding::BINARY)
        @header_continuation[stream_id] << frame.payload
      end
    end

    def handle_data(frame)
      stream_id = frame.stream_id
      stream = @streams[stream_id]
      return unless stream

      stream.receive_data!
      stream.received_data << frame.payload

      @on_data&.call(stream, frame.payload)

      if frame.flag?(:end_stream)
        stream.close_remote!
        @on_stream&.call(stream)
      end

      # Send window update
      send_window_update(stream_id, frame.payload.bytesize)
      send_window_update(0, frame.payload.bytesize)
    end

    def handle_window_update(frame)
      increment = frame.payload.unpack1("N") & 0x7FFFFFFF

      if frame.stream_id == 0
        @remote_window_size += increment
      else
        stream = @streams[frame.stream_id]
        stream&.update_window(increment)
      end
    end

    def handle_ping(frame)
      if frame.flag?(:ack)
        # Ping response
        return
      end

      # Send ping ACK
      ack_frame = Frame.new(
        type: :ping,
        flags: FLAGS[:ack],
        stream_id: 0,
        payload: frame.payload
      )
      write_frame(ack_frame)
    end

    def handle_goaway(frame)
      last_stream_id = frame.payload[0, 4].unpack1("N") & 0x7FFFFFFF
      error_code = frame.payload[4, 4].unpack1("N")

      @state = :closing
      @socket.close unless @socket.closed?
    end

    def handle_rst_stream(frame)
      stream_id = frame.stream_id
      stream = @streams[stream_id]
      return unless stream

      error_code = frame.payload.unpack1("N")
      stream.instance_variable_set(:@state, :closed)
    end

    def handle_priority(frame)
      stream_id = frame.stream_id
      stream = get_or_create_stream(stream_id)

      word = frame.payload[0, 4].unpack1("N")
      exclusive = (word & 0x80000000) != 0
      parent_id = word & 0x7FFFFFFF
      weight = frame.payload[4].unpack1("C") + 1

      stream.parent_id = parent_id
      stream.weight = weight
    end

    def handle_continuation(frame)
      stream_id = frame.stream_id
      @header_continuation[stream_id] ||= String.new(encoding: Encoding::BINARY)
      @header_continuation[stream_id] << frame.payload

      if frame.flag?(:end_headers)
        # Process complete headers
        header_data = @header_continuation[stream_id]
        @header_continuation.delete(stream_id)

        stream = @streams[stream_id]
        headers = @decoder.decode(header_data)
        stream.received_headers.concat(headers)

        @on_headers&.call(stream, headers)
      end
    end

    def send_settings(settings)
      payload = String.new(encoding: Encoding::BINARY)

      settings.each do |key, value|
        next if value.nil?
        setting_id = SETTINGS[key]
        next unless setting_id

        payload << [setting_id, value].pack("n N")
      end

      frame = Frame.new(
        type: :settings,
        stream_id: 0,
        payload: payload
      )

      write_frame(frame)
    end

    def send_window_update(stream_id, increment)
      frame = Frame.new(
        type: :window_update,
        stream_id: stream_id,
        payload: [increment].pack("N")
      )
      write_frame(frame)
    end

    def get_or_create_stream(stream_id)
      @streams[stream_id] ||= Stream.new(
        stream_id,
        window_size: @settings[:initial_window_size]
      )
    end

    def write_frame(frame)
      @socket.write(frame.to_binary)
      @socket.flush
    end
  end

  class Server
    def initialize(socket)
      @connection = Connection.new(socket, is_server: true)
    end

    def on_stream(&block)
      @connection.on_stream = block
    end

    def on_headers(&block)
      @connection.on_headers = block
    end

    def on_data(&block)
      @connection.on_data = block
    end

    def on_close(&block)
      @connection.on_close = block
    end

    def start
      @connection.start
      @connection.run
    end

    def send_headers(stream_id, headers, end_stream: false)
      @connection.send_headers(stream_id, headers, end_stream: end_stream)
    end

    def send_data(stream_id, data, end_stream: false)
      @connection.send_data(stream_id, data, end_stream: end_stream)
    end

    def close
      @connection.close
    end
  end

  class Client
    def initialize(socket)
      @connection = Connection.new(socket, is_server: false)
    end

    def on_stream(&block)
      @connection.on_stream = block
    end

    def on_headers(&block)
      @connection.on_headers = block
    end

    def on_data(&block)
      @connection.on_data = block
    end

    def on_close(&block)
      @connection.on_close = block
    end

    def start
      @connection.start
    end

    def request(headers, body: nil)
      stream = @connection.new_stream

      @connection.send_headers(stream.id, headers, end_stream: body.nil?)

      if body
        @connection.send_data(stream.id, body, end_stream: true)
      end

      stream
    end

    def run
      @connection.run
    end

    def close
      @connection.close
    end
  end
end

# Example usage (commented out):
#
# # Server example:
# require 'socket'
#
# server = TCPServer.new(8080)
# client_socket = server.accept
#
# http2_server = HTWO::Server.new(client_socket)
#
# http2_server.on_headers do |stream, headers|
#   puts "Received headers on stream #{stream.id}:"
#   headers.each { |name, value| puts "  #{name}: #{value}" }
# end
#
# http2_server.on_stream do |stream|
#   # Send response
#   response_headers = [
#     [":status", "200"],
#     ["content-type", "text/plain"]
#   ]
#   http2_server.send_headers(stream.id, response_headers)
#   http2_server.send_data(stream.id, "Hello, HTTP/2!", end_stream: true)
# end
#
# http2_server.start
#
# # Client example:
# require 'socket'
#
# socket = TCPSocket.new('localhost', 8080)
#
# http2_client = HTWO::Client.new(socket)
# http2_client.start
#
# http2_client.on_headers do |stream, headers|
#   puts "Received headers:"
#   headers.each { |name, value| puts "  #{name}: #{value}" }
# end
#
# http2_client.on_data do |stream, data|
#   puts "Received data: #{data}"
# end
#
# # Make a request
# request_headers = [
#   [":method", "GET"],
#   [":path", "/"],
#   [":scheme", "https"],
#   [":authority", "localhost:8080"]
# ]
#
# http2_client.request(request_headers)
# http2_client.run
