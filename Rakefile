require 'rubygems'
require 'rspec/core/rake_task'
require "#{File.dirname(__FILE__)}/lib/r509/ocsp/responder/version"

task :default => :spec
RSpec::Core::RakeTask.new(:spec) do
    ENV['RACK_ENV'] = 'test'
end

namespace :gem do
    desc 'Build the gem'
    task :build do
        puts `yard`
        puts `gem build r509-ocsp-responder.gemspec`
    end

    desc 'Install gem'
    task :install do
        puts `gem install r509-ocsp-responder-#{R509::Ocsp::Responder::VERSION}.gem`
    end

    desc 'Uninstall gem'
    task :uninstall do
        puts `gem uninstall r509-ocsp-responder`
    end
end

desc 'Build yard documentation'
task :yard do
    puts `yard`
    `open doc/index.html`
end
