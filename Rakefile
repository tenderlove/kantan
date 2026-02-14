require 'rake/testtask'

Rake::TestTask.new do |t|
  t.libs << 'test'
  t.test_files = FileList['test/test_*.rb']
  t.verbose = true
end

file "h2spec/h2spec" do |t|
  cd "h2spec" do
    sh "make"
  end
end

task :h2spec => "h2spec/h2spec" do
  require "socket"

  pid = fork {
    $LOAD_PATH << "lib"
    require_relative "test/h2spec_server"
  }

  # Wait for server to accept connections
  loop do
    TCPSocket.new("127.0.0.1", 8888).close
    break
  rescue Errno::ECONNREFUSED
    sleep 0.05
  end

  begin
    sh "../h2spec/h2spec -k -p 8888"
  ensure
    Process.kill(:TERM, pid)
    Process.wait(pid)
  end
end

task :test => :h2spec
task default: :test
