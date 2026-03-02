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

        # Wait for handshake
        until @conn.init_finished?
          rfds.clear
          wfds.clear
          rfds << @io if @conn.net_read_desired?
          wfds << @io if @conn.net_write_desired?
          IO.select(rfds, wfds, nil, @conn.event_timeout)
          @conn.handle_events
        end

        open_streams

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

          accept_streams
          read_streams

          @conn.handle_events
        end
      rescue IOError, Errno::EBADF, OpenSSL::SSL::SSLError
        # connection closed
      ensure
        @handler.on_close
      end
    end
  end
end
