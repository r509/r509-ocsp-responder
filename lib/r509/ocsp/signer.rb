require 'openssl'
require 'r509/exceptions'
require 'r509/config'
require 'dependo'

# OCSP related classes (signing, response, request)
module R509::OCSP
  # A class for signing OCSP responses
  class Signer
    attr_reader :validity_checker,:request_checker

    # @option options [Boolean] :copy_nonce copy nonce from request to response?
    # @option options [R509::Config::CAConfigPool] :configs CAConfigPool object
    # possible OCSP issuance roots that we want to issue OCSP responses for
    def initialize(options)
      if options.has_key?(:validity_checker)
        @validity_checker = options[:validity_checker]
      else
        @validity_checker = R509::Validity::DefaultChecker.new
      end
      @request_checker = Helper::RequestChecker.new(options[:configs], @validity_checker)
      @response_signer = Helper::ResponseSigner.new(options)
    end


    # @param request [String,OpenSSL::OCSP::Request] OCSP request (string or parsed object)
    # @return [Hash]
    # * :request [OpenSSL::OCSP::Request] parsed request object
    # * :response [OpenSSL::OCSP::Response] full response object
    def handle_request(request)
      begin
        parsed_request = OpenSSL::OCSP::Request.new request
      rescue
        return {:response => @response_signer.create_response(OpenSSL::OCSP::RESPONSE_STATUS_MALFORMEDREQUEST), :request => nil}
      end

      statuses = @request_checker.check_statuses(parsed_request)
      if not @request_checker.validate_statuses(statuses)
        return {:response => @response_signer.create_response(OpenSSL::OCSP::RESPONSE_STATUS_UNAUTHORIZED), :request => nil}
      end

      basic_response = @response_signer.create_basic_response(parsed_request,statuses)

      {:response => @response_signer.create_response(
        OpenSSL::OCSP::RESPONSE_STATUS_SUCCESSFUL,
        basic_response
      ), :request => parsed_request}
    end

  end
end

#Helper module for OCSP handling
module R509::OCSP::Helper
  module Compatibility
    if RUBY_VERSION < "2.4"
       def ruby_24
         false
       end
       
       def ruby_23
         yield
       end
     else 
       def ruby_24
         yield
       end
       
       def ruby_23
         false
       end
     end
  end
  # checks requests for validity against a set of configs
  class RequestChecker
    include Dependo::Mixin
    include Compatibility
    attr_reader :configs,:configs_hash

    # @param [R509::Config::CAConfigPool] configs CAConfigPool object
    # @param [R509::Validity::Checker] validity_checker an implementation of the R509::Validity::Checker class
    def initialize(configs, validity_checker)
      unless configs.kind_of?(R509::Config::CAConfigPool)
        raise R509::R509Error, "Must pass R509::Config::CAConfigPool object"
      end
      if configs.all.empty?
        raise R509::R509Error, "Must be at least one R509::Config object"
      end
      @configs = configs.all
      test_cid = OpenSSL::OCSP::CertificateId.new(OpenSSL::X509::Certificate.new,OpenSSL::X509::Certificate.new)
      if test_cid.respond_to?(:issuer_key_hash)
        @configs_hash = {}
        @configs.each do |config|
          ee_cert = OpenSSL::X509::Certificate.new
          ruby_23 { ee_cert.issuer = config.ca_cert.cert.subject.name } ||
          ruby_24 { ee_cert.issuer = config.ca_cert.cert.subject }
          # per RFC 5019
          # Clients MUST use SHA1 as the hashing algorithm for the
          # CertID.issuerNameHash and the CertID.issuerKeyHash values.
          # so we can safely assume that our inbound hashes will be SHA1
          issuer_certid = OpenSSL::OCSP::CertificateId.new(ee_cert,config.ca_cert.cert,OpenSSL::Digest::SHA1.new)
          @configs_hash[issuer_certid.issuer_key_hash] = config
        end
      end
      @validity_checker = validity_checker
      if @validity_checker.nil?
        raise R509::R509Error, "Must supply a R509::Validity::Checker"
      end
      if not @validity_checker.respond_to?(:check)
        raise R509::R509Error, "The validity checker must have a check method"
      end
    end

    # Loads and checks a raw OCSP request
    #
    # @param request [OpenSSL::OCSP::Request] OpenSSL OCSP Request object
    # @return [Hash] hash from the check_status method
    def check_statuses(request)
      request.certid.map { |certid|
        if certid.respond_to?(:issuer_key_hash)
          validated_config = @configs_hash[certid.issuer_key_hash]
        else
          validated_config = @configs.find do |config|
            #we need to create an OCSP::CertificateId object that has the right
            #issuer so we can pass it to #cmp_issuer. This is annoying because
            #CertificateId wants a cert and its issuer, but we don't want to
            #force users to provide an end entity cert just to make this comparison
            #work. So, we create a fake new cert and pass it in.
            ee_cert = OpenSSL::X509::Certificate.new
            ee_cert.issuer = config.ca_cert.cert.subject
            issuer_certid = OpenSSL::OCSP::CertificateId.new(ee_cert,config.ca_cert.cert)
            certid.cmp_issuer(issuer_certid)
          end
        end

        log.info "#{validated_config.ca_cert.subject.to_s} found for issuer" if validated_config
        check_status(certid, validated_config)
      }
    end

    # Determines whether the statuses constitute a request that is compliant.
    # No config means we don't know the CA, different configs means there are
    # requests from two different CAs in there. Both are invalid.
    #
    # @param statuses [Array<Hash>] array of hashes from check_statuses
    # @return [Boolean]
    def validate_statuses(statuses)
      validity = true
      config = nil

      statuses.each do |status|
        if status[:config].nil?
          validity = false
        end
        if config.nil?
          config = status[:config]
        end
        if config != status[:config]
          validity = false
        end
      end

      validity
    end

    private

    # Checks the status of a certificate with the corresponding CA
    # @param certid [OpenSSL::OCSP::CertificateId] The certId object from check_statuses
    # @param validated_config [R509::Config]
    def check_status(certid, validated_config)
      if(validated_config == nil) then
        return {
          :certid => certid,
          :config => nil
        }
      else
        validity_status = @validity_checker.check(validated_config.ca_cert.subject.to_s,certid.serial)
        return {
          :certid => certid,
          :status => validity_status.ocsp_status,
          :revocation_reason => validity_status.revocation_reason,
          :revocation_time => validity_status.revocation_time,
          :config => validated_config
        }
      end
    end
  end

  #signs OCSP responses
  class ResponseSigner
    include Compatibility
    # @option options [Boolean] :copy_nonce
    def initialize(options)
      if options.has_key?(:copy_nonce)
        @copy_nonce = options[:copy_nonce]
      else
        @copy_nonce = false
      end
    end

    # It is UNWISE to call this method directly because it assumes that the request is
    # validated. You probably want to take a look at R509::OCSP::Signer#handle_request
    #
    # @param request [OpenSSL::OCSP::Request]
    # @param statuses [Hash] hash from R509::OCSP::Helper::RequestChecker#check_statuses
    # @return [OpenSSL::OCSP::BasicResponse]
    def create_basic_response(request,statuses)
      basic_response = OpenSSL::OCSP::BasicResponse.new

      basic_response.copy_nonce(request) if @copy_nonce

      statuses.each do |status|
        #revocation time is retarded and is relative to now, so
        #let's figure out what that is.
        if status[:status] == OpenSSL::OCSP::V_CERTSTATUS_REVOKED
          revocation_time = status[:revocation_time].to_i - Time.now.to_i
        end
        basic_response.add_status(status[:certid],
                    status[:status],
                    status[:revocation_reason],
                    revocation_time,
                    -1*status[:config].ocsp_start_skew_seconds,
                    status[:config].ocsp_validity_hours*3600,
                    [] #array of OpenSSL::X509::Extensions
                    )
      end

      #this method assumes the request data is validated by validate_request so all configs will be the same and
      #we can choose to use the first one safely
      config = statuses[0][:config]

      #confusing, but R509::Cert contains R509::PrivateKey under #key. PrivateKey#key gives the OpenSSL object
      #turns out BasicResponse#sign can take up to 4 params
      #cert, key, array of OpenSSL::X509::Certificates, flags (not sure what the enumeration of those are)
      ruby_24 do
        signature_algorithm = "SHA256"
        basic_response.sign(config.ocsp_cert.cert, config.ocsp_cert.key.key, config.ocsp_chain, 0, signature_algorithm)
      end || 
      ruby_23 do
        basic_response.sign(config.ocsp_cert.cert,config.ocsp_cert.key.key,config.ocsp_chain) 
      end
    end

    # Builds final response.
    #
    # @param response_status [OpenSSL::OCSP::RESPONSE_STATUS_*] the primary response status
    # @param basic_response [OpenSSL::OCSP::BasicResponse] an optional basic response object
    # generated by create_basic_response
    # @return [OpenSSL::OCSP::OCSPResponse]
    def create_response(response_status,basic_response=nil)

      # first arg is the response status code, comes from this list
      # these can also be enumerated via OpenSSL::OCSP::RESPONSE_STATUS_*
      #OCSPResponseStatus ::= ENUMERATED {
      #  successful        (0),    --Response has valid confirmations
      #  malformedRequest    (1),    --Illegal confirmation request
      #  internalError       (2),    --Internal error in issuer
      #  tryLater        (3),    --Try again later
      #           --(4) is not used
      #  sigRequired       (5),    --Must sign the request
      #  unauthorized      (6)     --Request unauthorized
      #}
      #
      R509::OCSP::Response.new(
        OpenSSL::OCSP::Response.create(
          response_status, basic_response
        )
      )
    end
  end
end
