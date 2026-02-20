# Kantan - Pure Ruby HTTP/2 and HTTP/3 (QUIC) Implementation

An HTTP/2 and HTTP/3 server and client implementation in pure Ruby.

Passes [`h2spec`](https://github.com/summerwind/h2spec) and [`hpack-test-case`](https://github.com/http2jp/hpack-test-case).

Only works with Ruby 4.1.0+

## Client

An example using HTTP/2 is here: `examples/fetch_google.rb`

An example using HTTP/3 is here: `examples/quic_fetch.rb`

## Server

Just a demo server:

```ruby
require "kantan"
require "socket"
require "logger"

class MyApp < Kantan::Handler
  def on_request stream
    stream.respond [[":status", "200"]], body: "hello"
  end
end

server = TCPServer.new "127.0.0.1", 8888
port = server.addr[1]

logger = Logger.new $stderr
logger.debug "port #{port}"

while true
  client = server.accept
  client.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1)

  logger.debug "new connection"
  Thread.new(client) do |c|
    session = Kantan::H2::Session.new(c, handler: MyApp.new)
    session.receive
  end
end
```
