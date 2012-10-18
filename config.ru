require "redis"
require "r509"
require "r509/validity/redis"
require "r509/ocsp/stats/default"
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

# The Default stats will do nothing, and is the same as omitting this line.
# Replace with R509::Ocsp::Stats::Redis.new to store stats to redis.
Dependo::Registry[:stats] = R509::Ocsp::Stats::Default.new

responder = R509::Ocsp::Responder::Server
run responder

