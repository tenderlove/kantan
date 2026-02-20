require "kantan"
require "socket"
require "logger"
require "vernier"

class MyApp < Kantan::Handler
  def on_request stream
    stream.respond [[":status", "200"]], body: "hello"
  end
end

server = TCPServer.new "127.0.0.1", 8888
port = server.addr[1]

logger = Logger.new $stderr
logger.debug "port #{port}"

logger.debug "new connection"
#Vernier.profile(out: "time_profile.json") do
  4.times.map {
    client = server.accept
    client.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1)

    Thread.new {
      session = Kantan::H2::Session.new(client, handler: MyApp.new)
      session.receive
      session.join
    }
  }.each(&:join)
#end
logger.debug "done"
