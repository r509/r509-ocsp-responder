require "r509"
require "dependo"
require 'r509/ocsp/responder/server'

Dependo::Registry[:log] = Logger.new(STDOUT)

require "r509/validity/redis"
require 'redis'
begin
  gem "hiredis"
  Dependo::Registry[:log].warn "Loading redis with hiredis driver"
  redis = Redis.new(:driver => :hiredis)
rescue Gem::LoadError
  Dependo::Registry[:log].warn "Loading redis with standard ruby driver"
  redis = Redis.new
end
Dependo::Registry[:validity_checker] = R509::Validity::Redis::Checker.new(redis)


R509::OCSP::Responder::OCSPConfig.load_config

R509::OCSP::Responder::OCSPConfig.print_config

# Uncomment the next two lines if you want to collect stats via r509-ocsp-stats
# require "r509/ocsp/stats/redis"
# Dependo::Registry[:stats] = R509::OCSP::Stats::Redis.new

responder = R509::OCSP::Responder::Server
run responder
