require 'rubygems' if RUBY_VERSION < "1.9"
require 'sinatra/base'
require 'r509'
require 'r509/Validity/Redis'
require 'base64'
require 'redis'
require 'yaml'
require 'logger'

module R509::Ocsp
    class Responder < Sinatra::Base
        configure do
            mime_type :ocsp, 'application/ocsp-response'
            disable :protection #disable Rack::Protection (for speed)
            enable :logging
            #set :environment, :production

            yaml_config = YAML::load(File.read("config.yaml"))

            redis = Redis.new

            config = R509::Config.new(
                :ca_cert =>
                    R509::Cert.new(
                        :cert => File.read(yaml_config["ca"]["cer_filename"]),
                        :key => File.read(yaml_config["ca"]["key_filename"])
                    )
            )

            OCSPSIGNER = R509::Ocsp::Signer.new(
                :configs => [config],
                :validity_checker => R509::Validity::Redis::Checker.new(redis)
            )
        end

        configure :production do
            LOG = Logger.new(STDOUT)
        end

        configure :development do
            LOG = Logger.new(STDOUT)
        end

        error do
            "Something is amiss with our OCSP responder. You should ... wait?"
        end

        get '/favicon.ico' do
            LOG.debug "go away. no children."
            "go away. no children"
        end
        get '/*' do
            LOG.info "Got a GET request"
            raw_request = params[:splat].join("/")
            der = Base64.decode64(raw_request)
            begin
                statuses = OCSPSIGNER.check_request(der)
                response = OCSPSIGNER.sign_response(statuses)
                content_type :ocsp
                response.to_der
            rescue StandardError => e
                LOG.error "invalid request #{e}"
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
                    LOG.error "invalid request #{e}"
                    raise e
                end
            end
        end
    end
end
#http://127.0.0.1/MFEwTzBNMEswSTAJBgUrDgMCGgUABBQ1mI4Ww4R5LZiQ295pj4OF%2F44yyAQUyk7dWyc1Kdn27sPlU%2B%2BkwBmWHa8CEFqb7H4xpqYH6ed2G0%2BPMG4%3D

