require 'rubygems' if RUBY_VERSION < "1.9"
require 'sinatra/base'
require 'r509'
require 'base64'

class ValidityChecker < R509::Validity::Checker
    def check(serial)
        R509::Validity::Status.new(:status => R509::Validity::VALID)
    end
end

class ValidityWriter < R509::Validity::Writer
    def write(serial, status)
    end
end

@@config = R509::Config.new(OpenSSL::X509::Certificate.new(File.read("/Users/pkehrer/Code/r509/cert_data/test_ca/test_ca.cer")),OpenSSL::PKey::RSA.new(File.read("/Users/pkehrer/Code/r509/cert_data/test_ca/test_ca.key")), {})

OCSPSIGNER = R509::Ocsp::Signer.new( :configs => [@@config], :validity_checker => ValidityChecker.new )

module OcspResponder
    class Responder < Sinatra::Base
        configure do
            mime_type :ocsp, 'application/ocsp-response'
            disable :protection #disable Rack::Protection (for speed)
            enable :logging
        end
        get '/*' do
            raw_request = params[:splat].join("/")
            der = Base64.decode64(raw_request)
            begin
                statuses = OCSPSIGNER.check_request(der)
                response = OCSPSIGNER.sign_response(statuses)
                content_type :ocsp
                response.to_der
            rescue
                puts "invalid request"
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
                rescue
                    puts "invalid request"
                end
            end
        end
    end
end
#http://127.0.0.1/MFEwTzBNMEswSTAJBgUrDgMCGgUABBQ1mI4Ww4R5LZiQ295pj4OF%2F44yyAQUyk7dWyc1Kdn27sPlU%2B%2BkwBmWHa8CEFqb7H4xpqYH6ed2G0%2BPMG4%3D

