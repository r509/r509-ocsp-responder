require 'rubygems' if RUBY_VERSION < "1.9"
require 'sinatra/base'
require 'r509'
require 'r509/Validity/Redis'
require 'base64'
require 'dependo'
require 'logger'

module R509::Ocsp
    class Responder < Sinatra::Base
        include Dependo::Mixin

        #error for status checking
        class StatusError < StandardError
        end

        configure do
            mime_type :ocsp, 'application/ocsp-response'
            disable :protection #disable Rack::Protection (for speed)
            disable :logging
            set :environment, :production
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
                redis.ping
                "OK"
            rescue
                raise R509::Ocsp::Responder::StatusError
            end
        end

        get '/*' do
            raw_request = params[:splat].join("/")
            #remove any leading slashes (looking at you MS Crypto API)
            raw_request.sub!(/^\/+/,"")
            log.info "GET Request: "+raw_request
            der = Base64.decode64(raw_request)
            handle_ocsp_request(der, "GET")
        end

        post '/' do
            if request.media_type == 'application/ocsp-request'
                der = request.env["rack.input"].read
                log.info "POST Request: "+Base64.encode64(der).gsub!(/\n/,"")
                handle_ocsp_request(der, "POST")
            end
        end

        private

        def handle_ocsp_request(der, method)
            begin
                response = ocsp_signer.handle_request(der)

                log_response(response,method)

                content_type :ocsp
                response.to_der
            rescue StandardError => e
                log.error "unexpected error #{e}"
                raise e
            end
        end

        def log_response(response, method="?")
            if response.nil?
                log.error "Something went horribly wrong"
                return
            end

            case response.status
            when OpenSSL::OCSP::RESPONSE_STATUS_SUCCESSFUL
                serial_data = response.basic.status.map do |status|
                    friendly_status = case status[1]
                    when 0
                        "VALID"
                    when 1
                        "REVOKED"
                    when 2
                        "UNKNOWN"
                    end
                    status[0].serial.to_s+" Status: #{friendly_status}"
                end
                log.info "#{method} Request For Serial(s): #{serial_data.join(",")} UserAgent: #{env["HTTP_USER_AGENT"]}"
            when OpenSSL::OCSP::RESPONSE_STATUS_UNAUTHORIZED
                log.info "#{method} Request For Unauthorized CA. UserAgent: #{env["HTTP_USER_AGENT"]}"
            when OpenSSL::OCSP::RESPONSE_STATUS_MALFORMEDREQUEST
                log.info "#{method} Malformed Request. UserAgent: #{env["HTTP_USER_AGENT"]}"
            end
        end

    end
end
