require "yaml"
require "redis"
require "r509"
require "r509/Validity/Redis"
require "dependo"

Dependo::Registry[:redis] = Redis.new

config_data = File.read("config.yaml")

Dependo::Registry[:config_pool] = R509::Config::CaConfigPool.from_yaml("certificate_authorities", config_data)

Dependo::Registry[:copy_nonce] = YAML.load(config_data)["copy_nonce"] || false

Dependo::Registry[:ocsp_signer] = R509::Ocsp::Signer.new(
    :configs => Dependo::Registry[:config_pool].all,
    :validity_checker => R509::Validity::Redis::Checker.new(Dependo::Registry[:redis]),
    :copy_nonce => Dependo::Registry[:copy_nonce]
)
