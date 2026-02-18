# frozen_string_literal: true

require 'minitest/autorun'
require 'socket'
require "kantan"

class TestClientHandler < Kantan::Handler
  attr_reader :queue

  def initialize
    @queue = Queue.new
  end

  def on_headers(stream) = @queue << [:headers, stream.headers]
  def on_data(stream, chunk) = @queue << [:data, chunk]
  def on_request(stream) = @queue << [:done, stream.id]
end

class TestServerHandler < Kantan::Handler
  attr_accessor :on_request_block

  def on_request(stream)
    @on_request_block&.call(stream)
  end
end
