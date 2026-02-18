# frozen_string_literal: true

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
  client_fd = server.sysaccept

  logger.debug "new connection"
  Ractor.new(client_fd) do |c_fd|
    c = Socket.for_fd(c_fd)
    c.autoclose = true
    c.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1)
    session = Kantan::Session.new(c, handler: MyApp.new)
    session.receive
    session.join
  end
end
