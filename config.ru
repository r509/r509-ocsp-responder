require "redis"
require "r509"
require "r509/validity/redis"
require "dependo"
require './lib/r509/ocsp/responder/server'

Dependo::Registry[:redis] = Redis.new

config_data = File.read("config.yaml")

Dependo::Registry[:config_pool] = R509::Config::CaConfigPool.from_yaml("certificate_authorities", config_data)

Dependo::Registry[:copy_nonce] = YAML.load(config_data)["copy_nonce"] || false

Dependo::Registry[:cache_headers] = YAML.load(config_data)["cache_headers"] || false

Dependo::Registry[:max_cache_age] = YAML.load(config_data)["max_cache_age"]

Dependo::Registry[:ocsp_signer] = R509::Ocsp::Signer.new(
    :configs => Dependo::Registry[:config_pool].all,
    :validity_checker => R509::Validity::Redis::Checker.new(Dependo::Registry[:redis]),
    :copy_nonce => Dependo::Registry[:copy_nonce]
)

Dependo::Registry[:log] = Logger.new(STDOUT)

Dependo::Registry[:config_pool].all.each do |config|
    Dependo::Registry[:log].info "Config: "
    Dependo::Registry[:log].info "CA Cert:"+config.ca_cert.subject.to_s
    Dependo::Registry[:log].info "OCSP Cert (may be the same as above):"+config.ocsp_cert.subject.to_s
    Dependo::Registry[:log].info "OCSP Validity Hours: "+config.ocsp_validity_hours.to_s
    Dependo::Registry[:log].info "\n"
end

responder = R509::Ocsp::Responder::Server
run responder
