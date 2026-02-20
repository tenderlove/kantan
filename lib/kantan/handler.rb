# frozen_string_literal: true

module Kantan
  class Handler
    def on_headers stream; end
    def on_data stream, chunk; end
    def on_request stream; end
    def on_ping rtt; end
    def on_close; end
  end
end
