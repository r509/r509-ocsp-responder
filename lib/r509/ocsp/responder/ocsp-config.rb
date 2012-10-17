module R509::Ocsp::Responder
    class OcspConfig
        def self.load_config
            config_data = File.read("config.yaml")

            Dependo::Registry[:config_pool] = R509::Config::CaConfigPool.from_yaml("certificate_authorities", config_data)

            Dependo::Registry[:copy_nonce] = YAML.load(config_data)["copy_nonce"] || false

            Dependo::Registry[:cache_headers] = YAML.load(config_data)["cache_headers"] || false

            Dependo::Registry[:max_cache_age] = YAML.load(config_data)["max_cache_age"]

            Dependo::Registry[:ocsp_signer] = R509::Ocsp::Signer.new(
                :configs => Dependo::Registry[:config_pool],
                :validity_checker => R509::Validity::Redis::Checker.new(Dependo::Registry[:redis]),
                :copy_nonce => Dependo::Registry[:copy_nonce]
            )
        end

        def self.print_config
            Dependo::Registry[:log].warn "Config loaded"
            Dependo::Registry[:log].warn "Copy Nonce: "+Dependo::Registry[:copy_nonce].to_s
            Dependo::Registry[:log].warn "Cache Headers: "+Dependo::Registry[:cache_headers].to_s
            Dependo::Registry[:log].warn "Max Cache Age: "+Dependo::Registry[:max_cache_age].to_s
            Dependo::Registry[:config_pool].all.each do |config|
                Dependo::Registry[:log].warn "Config: "
                Dependo::Registry[:log].warn "CA Cert:"+config.ca_cert.subject.to_s
                Dependo::Registry[:log].warn "OCSP Cert (may be the same as above):"+config.ocsp_cert.subject.to_s
                Dependo::Registry[:log].warn "OCSP Validity Hours: "+config.ocsp_validity_hours.to_s
                Dependo::Registry[:log].warn "\n"
            end
        end
    end
end
