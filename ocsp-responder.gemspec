$:.push File.expand_path("../lib", __FILE__)
require "ocsp-responder/version"

spec = Gem::Specification.new do |s|
  s.name = 'ocsp-responder'
  s.version = OcspResponder::VERSION
  s.platform = Gem::Platform::RUBY
  s.has_rdoc = false
  s.summary = "A (relatively) simple OCSP responder written to work with r509"
  s.description = 'An OCSP responder. What, you want more info?'
  s.add_dependency 'r509'
  s.add_development_dependency 'rspec'
  s.add_development_dependency 'syntax'
  s.author = "Paul Kehrer"
  s.email = "paul.l.kehrer@gmail.com"
  s.homepage = "http://langui.sh"
  s.required_ruby_version = ">= 1.8.6"
  s.files = %w(README.md Rakefile) + Dir["{lib,script,spec,doc,cert_data}/**/*"]
  s.test_files= Dir.glob('test/*_spec.rb')
  s.require_path = "lib"
end

