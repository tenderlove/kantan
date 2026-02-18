$: << File.expand_path("lib")

require "kantan/version"

Gem::Specification.new do |s|
  s.name        = "kantan"
  s.version     = Kantan::VERSION
  s.summary     = "HTTP/2.0 parser written in Ruby"
  s.description = "An HTTP/2.0 parser in Ruby"
  s.authors     = ["Aaron Patterson"]
  s.email       = "tenderlove@ruby-lang.org"
  s.files       = `git ls-files -z`.split("\x0")
  s.test_files  = s.files.grep(%r{^test/})
  s.homepage    = "https://github.com/tenderlove/kantan"
  s.license     = "Apache-2.0"

  s.add_development_dependency 'minitest', '~> 5'
  s.add_development_dependency 'rake', '~> 13.0'
  s.add_development_dependency 'logger', '~> 1.0'
  s.add_development_dependency 'rack', '~> 3'
  s.add_development_dependency 'concurrent-ruby', '~> 1.3'
end
