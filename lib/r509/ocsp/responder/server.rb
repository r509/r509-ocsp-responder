require 'sinatra/base'
require 'r509'
require 'r509/ocsp/signer'
require 'base64'
require 'dependo'
require 'logger'
require 'time'
require File.dirname(__FILE__)+'/ocsp-config.rb'

# Capture USR2 calls so we can reload and print the config
# I'd rather use HUP, but daemons like thin already capture that
# so we can't use it.
Signal.trap("USR2") do
  R509::Ocsp::Responder::OcspConfig.load_config
  R509::Ocsp::Responder::OcspConfig.print_config
end


module R509::Ocsp::Responder
  #error for status checking
  class StatusError < StandardError
  end

  class Server < Sinatra::Base
    include Dependo::Mixin

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
        if Dependo::Registry[:ocsp_signer].validity_checker.is_available?
          "OK"
        else
          raise R509::Ocsp::Responder::StatusError
        end
      rescue
        raise R509::Ocsp::Responder::StatusError
      end
    end

    get '/*' do
      raw_request = params[:splat].join("/")
      #remove any leading slashes (looking at you MS Crypto API)
      raw_request.sub!(/^\/+/,"")
      log.info { "GET Request: "+raw_request }
      der = Base64.decode64(raw_request)
      request_response = handle_ocsp_request(der, "GET")
      build_headers(request_response)
      request_response[:response].to_der
    end

    post '/' do
      if request.media_type == 'application/ocsp-request'
        der = request.env["rack.input"].read
        log.info { "POST Request: "+Base64.encode64(der).gsub!(/\n/,"") }
        request_response = handle_ocsp_request(der, "POST")
        request_response[:response].to_der
      end
    end

    private

    def handle_ocsp_request(der, method)
      begin
        request_response = ocsp_signer.handle_request(der)

        log_ocsp_response(request_response[:response],method)

        content_type :ocsp
        request_response
      rescue StandardError => e
        log.error "unexpected error #{e}"
        raise e
      end
    end

    def log_ocsp_response(ocsp_response, method="?")
      if response.nil?
        log.error "Something went horribly wrong"
        return
      end

      case ocsp_response.status
      when OpenSSL::OCSP::RESPONSE_STATUS_SUCCESSFUL
        serial_data = ocsp_response.basic.status.map do |status|
          friendly_status = case status[1]
          when 0
            "VALID"
          when 1
            "REVOKED"
          when 2
            "UNKNOWN"
          end
          if ocsp_response.basic.status[0][0].respond_to?(:issuer_key_hash)
            config_used = ocsp_signer.request_checker.configs_hash[ocsp_response.basic.status[0][0].issuer_key_hash]
          else
            config_used = ocsp_signer.request_checker.configs.find do |config|
              #we need to create an OCSP::CertificateId object that has the right
              #issuer so we can pass it to #cmp_issuer. This is annoying because
              #CertificateId wants a cert and its issuer, but we don't want to
              #force users to provide an end entity cert just to make this comparison
              #work. So, we create a fake new cert and pass it in.
              ee_cert = OpenSSL::X509::Certificate.new
              ee_cert.issuer = config.ca_cert.cert.subject
              issuer_certid = OpenSSL::OCSP::CertificateId.new(ee_cert,config.ca_cert.cert)
              ocsp_response.basic.status[0][0].cmp_issuer(issuer_certid)
            end
          end
          stats.record(config_used.ca_cert.subject.to_s, status[0].serial.to_s, friendly_status) if Dependo::Registry.has_key?(:stats)
          status[0].serial.to_s+" Status: #{friendly_status}"
        end
        log.info { "#{method} Request For Serial(s): #{serial_data.join(",")} UserAgent: #{env["HTTP_USER_AGENT"]}" }
      when OpenSSL::OCSP::RESPONSE_STATUS_UNAUTHORIZED
        log.info { "#{method} Request For Unauthorized CA. UserAgent: #{env["HTTP_USER_AGENT"]}" }
      when OpenSSL::OCSP::RESPONSE_STATUS_MALFORMEDREQUEST
        log.info { "#{method} Malformed Request. UserAgent: #{env["HTTP_USER_AGENT"]}" }
      end
    end

    def build_headers(request_response)
      ocsp_response = request_response[:response]
      ocsp_request = request_response[:request]

      # cache_headers is injected via config.ru
      # we only cache if it's a RESPONSE_STATUS_SUCCESSFUL response and there's no nonce.
      if cache_headers and not ocsp_response.basic.nil? and ocsp_response.check_nonce(ocsp_request) == R509::Ocsp::Request::Nonce::BOTH_ABSENT
        calculated_max_age =  ocsp_response.basic.status[0][5] - Time.now
        #same with max_cache_age
        if not max_cache_age or ( max_cache_age > calculated_max_age )
          max_age = calculated_max_age
        else
          max_age = max_cache_age
        end

        response["Last-Modified"] = Time.now.httpdate
        response["ETag"] = OpenSSL::Digest::SHA1.new(ocsp_response.to_der).to_s
        response["Expires"] = ocsp_response.basic.status[0][5].httpdate
        response["Cache-Control"] = "max-age=#{max_age.to_i}, public, no-transform, must-revalidate"
      end
    end

  end
end
