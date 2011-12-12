require 'rubygems' if RUBY_VERSION < "1.9"
require 'sinatra/base'
require 'r509'
require 'base64'
require 'redis'
require 'yaml'

module OcspResponder::Validity
    class ValidityChecker < R509::Validity::Checker
        def initialize(redis)
            @redis = redis
        end

        def check(serial)
            hash = @redis.hgetall("cert:#{serial}")
            if not hash.nil? and hash.has_key?("status")
                R509::Validity::Status.new(
                    :status => hash["status"].to_i,
                    :revocation_time => hash["revocation_time"].to_i || nil,
                    :revocation_reason => hash["revocation_reason"].to_i || 0
                )
            else
                R509::Validity::Status.new(:status => R509::Validity::UNKNOWN)
            end
        end
    end

    class ValidityWriter < R509::Validity::Writer
        def initialize(redis)
            @redis = redis
        end

        def issue(serial)
            @redis.hmset("cert:#{serial}", "status", 0)
        end

        def revoke(serial, reason)
            @redis.hmset("cert:#{serial}", 
                "status", 1, 
                "revocation_time", Time.now.to_i, 
                "revocation_reason", reason
            )
        end
    end
end

module OcspResponder
    class Responder < Sinatra::Base
        configure do
            mime_type :ocsp, 'application/ocsp-response'
            disable :protection #disable Rack::Protection (for speed)
            enable :logging
            #set :environment, :production

            yaml_config = YAML::load(File.read("config.yaml"))

            redis = Redis.new

            config = R509::Config.new(
                OpenSSL::X509::Certificate.new(File.read(yaml_config["ca"]["cer_filename"])),
                OpenSSL::PKey::RSA.new(File.read(yaml_config["ca"]["key_filename"])), 
                {}
            )

            OCSPSIGNER = R509::Ocsp::Signer.new(
                :configs => [config], 
                :validity_checker => OcspResponder::Validity::ValidityChecker.new(redis)
            )
        end
        error do
            "Something is amiss with our OCSP responder. You should ... wait?"
        end
        get '/favicon.ico' do
            puts "go away. no children."
            "go away. no children"
        end
        get '/*' do
            raw_request = params[:splat].join("/")
            der = Base64.decode64(raw_request)
            begin
                statuses = OCSPSIGNER.check_request(der)
                response = OCSPSIGNER.sign_response(statuses)
                content_type :ocsp
                response.to_der
            rescue StandardError => e
                puts "invalid request #{e}"
                raise e
            end

        end
        post '/' do
            if request.media_type == 'application/ocsp-request'
                der = request.env["rack.input"].read
                begin
                    statuses = OCSPSIGNER.check_request(der)
                    response = OCSPSIGNER.sign_response(statuses)
                    content_type :ocsp
                    response.to_der
                rescue StandardError => e
                    puts "invalid request #{e}"
                    raise e
                end
            end
        end
    end
end
#http://127.0.0.1/MFEwTzBNMEswSTAJBgUrDgMCGgUABBQ1mI4Ww4R5LZiQ295pj4OF%2F44yyAQUyk7dWyc1Kdn27sPlU%2B%2BkwBmWHa8CEFqb7H4xpqYH6ed2G0%2BPMG4%3D

