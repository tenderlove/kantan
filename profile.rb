require "htwo"
require "socket"
require "logger"
require "vernier"

class MyApp < HTWO::Handler
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
  Vernier.profile(out: "time_profile.json") do
    session = HTWO::Session.new(client, handler: MyApp.new)
    session.receive
    session.join
  end
  logger.debug "done"
end
