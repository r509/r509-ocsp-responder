require "redis"
require "r509"
require "r509/validity/redis"
require "r509/ocsp/stats/default"
require "dependo"
require './lib/r509/ocsp/responder/server'

Dependo::Registry[:redis] = Redis.new

R509::Ocsp::Responder::OcspConfig.load_config

Dependo::Registry[:log] = Logger.new(STDOUT)

R509::Ocsp::Responder::OcspConfig.print_config

# The Default stats will do nothing, and is the same as omitting this line.
# Replace with R509::Ocsp::Stats::Redis.new to store stats to redis.
Dependo::Registry[:stats] = R509::Ocsp::Stats::Default.new

responder = R509::Ocsp::Responder::Server
run responder

