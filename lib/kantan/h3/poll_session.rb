# frozen_string_literal: true

require "kantan/h3/session"

module Kantan
  module H3
    # Single-threaded H3 server session.
    # No threads — all I/O happens in #run via non-blocking SSL calls.
    # Safe for use with OSSL_QUIC_server_method and Ractors.
    class PollSession < Session
      def run
        rfds = []
        wfds = []
        until @closed
          rfds.clear
          wfds.clear

          rfds << @io if @conn.net_read_desired?
          wfds << @io if @conn.net_write_desired?

          if timeout = @conn.event_timeout
            IO.select(rfds, wfds, nil, timeout)
          else
            break
          end

          @conn.handle_events

          open_streams if !@control_stream && @conn.init_finished?
          accept_streams
          read_streams

          @conn.handle_events
        end
      rescue IOError, Errno::EBADF, OpenSSL::SSL::SSLError
        # connection closed
      ensure
        @handler.on_close
      end

      private

      def accept_streams
        while (ssl = @conn.accept_stream_nonblock(exception: false)) != :wait_readable
          sid = register_stream(ssl)
          read_stream(ssl, sid)
        end
      end

      def read_streams
        @ssl_map.each do |sid, ssl|
          read_stream(ssl, sid)
        end
      end
    end
  end
end
