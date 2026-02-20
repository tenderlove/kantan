require "kantan"
require "socket"
require "logger"

class MyApp < Kantan::Handler
  def on_request stream
    Thread.new do
      if stream.headers.assoc(":path")&.last == "/quit"
        stream.respond [[":status", "200"]], body: "hello"
        stream.goaway
        exit!
      else
        stream.respond [[":status", "200"]], body: "hello"
      end
    end
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
