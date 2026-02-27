require "kantan"
require "kantan/rack_handler"

module Rackup
  module Handler
    class Kantan
      def self.run(app, options = {})
        host = options[:Host] || "localhost"
        port = options[:Port] || 3000

        logger = Logger.new $stderr

        # Generate a self-signed certificate
        key = OpenSSL::PKey::EC.generate("prime256v1")
        cert = OpenSSL::X509::Certificate.new
        cert.version = 2
        cert.serial = 1
        cert.subject = OpenSSL::X509::Name.parse("/CN=localhost")
        cert.issuer = cert.subject
        cert.public_key = key
        cert.not_before = Time.now
        cert.not_after = Time.now + 3600

        ef = OpenSSL::X509::ExtensionFactory.new
        ef.subject_certificate = cert
        ef.issuer_certificate = cert
        cert.add_extension(ef.create_extension("subjectAltName", "DNS:localhost,IP:127.0.0.1", false))
        cert.add_extension(ef.create_extension("basicConstraints", "CA:FALSE", true))

        cert.sign(key, "SHA256")

        executor = Concurrent::FixedThreadPool.new(5)

        handler = ::Kantan::RackHandler.new(app,
          executor: executor,
          server_name: host,
          server_port: port,
          scheme: "https")

        # QUIC context advertising h3
        udp = UDPSocket.new
        udp.bind(host, port)

        ctx = OpenSSL::SSL::SSLContext.quic(:server)
        ctx.cert = cert
        ctx.key = key
        ctx.alpn_select_cb = ->(protos) { protos.include?("h3") ? "h3" : protos.first }

        listener = OpenSSL::SSL::SSLSocket.new_listener(udp, context: ctx)
        listener.listen

        logger.info "Listening on https://#{host}:#{port}"
        logger.info "Test with: /opt/homebrew/opt/curl/bin/curl --http3 -k https://#{host}:#{port}/"

        trap("INT") { exit }

        loop do
          rfds = listener.net_read_desired? ? [udp] : []
          wfds = listener.net_write_desired? ? [udp] : []
          IO.select(rfds, wfds, nil, listener.event_timeout)
          listener.handle_events

          conn = listener.accept_connection_nonblock(exception: false)
          next if conn == :wait_readable

          logger.info "new connection (ALPN: #{conn.alpn_protocol})"
          Thread.new(conn) do |c|
            session = ::Kantan::H3::PollSession.new(c, io: udp, handler: handler)
            session.run
          rescue => e
            logger.error "#{e.class}: #{e.message}"
          end
        end
      end
    end
  end
end
Rackup::Handler.register(:kantan, Rackup::Handler::Kantan)
