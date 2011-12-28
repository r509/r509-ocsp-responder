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
        #error for status checking
        class StatusError < StandardError
        end

        configure do
            mime_type :ocsp, 'application/ocsp-response'
            disable :protection #disable Rack::Protection (for speed)
            disable :logging
            set :environment, :production

            set :redis, Redis.new

            config_pool = R509::Config::CaConfigPool.from_yaml("certificate_authorities", File.read("config.yaml"))

            set :ocsp_signer, R509::Ocsp::Signer.new(
                :configs => config_pool.all,
                :validity_checker => R509::Validity::Redis::Checker.new(settings.redis)
            )
        end

        configure :production do
            set :log, Logger.new(nil)
        end

        configure :development do
            set :log, Logger.new(nil)
        end

        configure :test do
            set :log, Logger.new(nil)
        end

        helpers do
            def log
                settings.log
            end
            def ocsp_signer
                settings.ocsp_signer
            end
        end

        error do
            log.error env["sinatra.error"].inspect
            log.error env["sinatra.error"].backtrace.join("\n")
            "Something is amiss with our OCSP responder. You should ... wait?"
        end

        error OpenSSL::OCSP::OCSPError do
            "Invalid request"
        end

        error R509::Ocsp::Responder::StatusError do
            "Down"
        end

        get '/favicon.ico' do
            log.debug "go away. no children."
            "go away. no children"
        end

        get '/status/?' do
            begin
                settings.redis.ping
                "OK"
            rescue
                raise R509::Ocsp::Responder::StatusError
            end
        end

        get '/*' do
            raw_request = params[:splat].join("/")
            der = Base64.decode64(raw_request)
            handle_ocsp_request(der, "GET")
        end

        post '/' do
            if request.media_type == 'application/ocsp-request'
                der = request.env["rack.input"].read
                handle_ocsp_request(der, "POST")
            end
        end

        private

        def handle_ocsp_request(der, method="?")
            begin
                statuses = ocsp_signer.check_request(der)
                log.info "#{method} Request For Serial(s): #{statuses[:statuses].map { |status|
                    line = status[:certid].serial.to_s
                    line += "(Unknown CA)" if status[:config].nil?
                    line
                }.join(",")}"
                response = ocsp_signer.sign_response(statuses)
                content_type :ocsp
                response.to_der
            rescue StandardError => e
                log.error "invalid request #{e}"
                raise e
            end
        end

    end
end
#http://127.0.0.1/MFEwTzBNMEswSTAJBgUrDgMCGgUABBQ1mI4Ww4R5LZiQ295pj4OF%2F44yyAQUyk7dWyc1Kdn27sPlU%2B%2BkwBmWHa8CEFqb7H4xpqYH6ed2G0%2BPMG4%3D

