require "redis"
require "r509"
require "r509/validity/redis"
#require "r509/ocsp/stats/redis"
require "dependo"
require './lib/r509/ocsp/responder/server'

Dependo::Registry[:log] = Logger.new(STDOUT)

begin
  gem "hiredis"
  Dependo::Registry[:log].warn "Loading redis with hiredis driver"
  Dependo::Registry[:redis] = Redis.new(:driver => :hiredis)
rescue Gem::LoadError
  Dependo::Registry[:log].warn "Loading redis with standard ruby driver"
  Dependo::Registry[:redis] = Redis.new
end


R509::Ocsp::Responder::OcspConfig.load_config

R509::Ocsp::Responder::OcspConfig.print_config

# Add this line if you want to collect stats via the r509-ocsp-stats gem
# Dependo::Registry[:stats] = R509::Ocsp::Stats::Redis.new

responder = R509::Ocsp::Responder::Server
run responder

