require File.dirname(__FILE__) + '/spec_helper'
require 'time'


describe R509::Ocsp::Responder do
    before :each do
        # clear the dependo before each test
        Dependo::Registry.clear
        Dependo::Registry[:log] = Logger.new(nil)

        # we always want to mock with a new redis
        @redis = double("redis")
        Dependo::Registry[:redis] = @redis

        # default value for :copy_nonce is false (can override on a per-test basis)
        Dependo::Registry[:copy_nonce] = false

        # default value for :cache_headers is false (can override on a per-test basis)
        Dependo::Registry[:cache_headers] = false

        # read the config.yaml
        Dependo::Registry[:config_pool] = R509::Config::CaConfigPool.from_yaml("certificate_authorities", File.read("config.yaml"))
    end
    def app
        # this is executed after the code in each test, so if we change something in the dependo registry, it'll show up here (we will set :copy_nonce in some tests)
        Dependo::Registry[:ocsp_signer] = R509::Ocsp::Signer.new(
            :configs => Dependo::Registry[:config_pool].all,
            :validity_checker => R509::Validity::Redis::Checker.new(Dependo::Registry[:redis]),
            :copy_nonce => Dependo::Registry[:copy_nonce]
        )
        @app ||= R509::Ocsp::Responder
    end

    before :all do
        @test_ca_cert = OpenSSL::X509::Certificate.new(File.read(Pathname.new(__FILE__).dirname + "fixtures/test_ca.cer"))
        @second_ca_cert = OpenSSL::X509::Certificate.new(File.read(Pathname.new(__FILE__).dirname + "fixtures/second_ca.cer"))
    end

    it "should return unauthorized on a GET which does not match any configured CA" do
        class R509::Validity::Redis::Checker
            def check(issuer, serial)
                raise StandardError.new("Shouldn't ever call the Checker here, since the request isn't from the configured CA")
            end
        end
        get '/MFEwTzBNMEswSTAJBgUrDgMCGgUABBQ1mI4Ww4R5LZiQ295pj4OF%2F44yyAQUyk7dWyc1Kdn27sPlU%2B%2BkwBmWHa8CEFqb7H4xpqYH6ed2G0%2BPMG4%3D'
        ocsp_response = R509::Ocsp::Response.parse(last_response.body)
        ocsp_response.status.should == OpenSSL::OCSP::RESPONSE_STATUS_UNAUTHORIZED
        last_response.content_type.should == "application/ocsp-response"
        last_response.should be_ok
    end
    it "should return a valid (UNKNOWN) response on a GET request from the test_ca CA" do
        class R509::Validity::Redis::Checker
            def check(issuer, serial)
                R509::Validity::Status.new(:status => R509::Validity::UNKNOWN)
            end
        end
        get '/MFYwVDBSMFAwTjAJBgUrDgMCGgUABBQ4ykaMB0SN9IGWx21tTHBRnmCnvQQUeXW7hDrLLN56Cb4xG0O8HCpNU1gCFQC4IG5U4zC4RYb4VQ%2B2f0zCoFCvNg%3D%3D'
        ocsp_response = R509::Ocsp::Response.parse(last_response.body)
        ocsp_response.status.should == OpenSSL::OCSP::RESPONSE_STATUS_SUCCESSFUL
        ocsp_response.basic.status[0][1].should == OpenSSL::OCSP::V_CERTSTATUS_UNKNOWN
        ocsp_response.basic.status[0][0].serial.should == 1051177536915098490149656742929223623669143613238
        ocsp_response.verify(@test_ca_cert).should == true
        last_response.content_type.should == "application/ocsp-response"
        last_response.should be_ok
    end
    it "should return a valid (REVOKED) response on a GET request from the test_ca CA" do
        class R509::Validity::Redis::Checker
            def check(issuer, serial)
                R509::Validity::Status.new(:status => R509::Validity::REVOKED, :revocation_time => 123, :revocation_reason => 1)
            end
        end
        get '/MFYwVDBSMFAwTjAJBgUrDgMCGgUABBQ4ykaMB0SN9IGWx21tTHBRnmCnvQQUeXW7hDrLLN56Cb4xG0O8HCpNU1gCFQC4IG5U4zC4RYb4VQ%2B2f0zCoFCvNg%3D%3D'
        ocsp_response = R509::Ocsp::Response.parse(last_response.body)
        ocsp_response.status.should == OpenSSL::OCSP::RESPONSE_STATUS_SUCCESSFUL
        ocsp_response.basic.status[0][1].should == OpenSSL::OCSP::V_CERTSTATUS_REVOKED
        ocsp_response.basic.status[0][0].serial.should == 1051177536915098490149656742929223623669143613238
        ocsp_response.verify(@test_ca_cert).should == true
        last_response.content_type.should == "application/ocsp-response"
        last_response.should be_ok
    end
    it "should return a valid (VALID) response on a GET request from the test_ca CA" do
        class R509::Validity::Redis::Checker
            def check(issuer, serial)
                R509::Validity::Status.new(:status => R509::Validity::VALID, :revocation_time => nil, :revocation_reason => 0)
            end
        end
        get '/MFYwVDBSMFAwTjAJBgUrDgMCGgUABBQ4ykaMB0SN9IGWx21tTHBRnmCnvQQUeXW7hDrLLN56Cb4xG0O8HCpNU1gCFQC4IG5U4zC4RYb4VQ%2B2f0zCoFCvNg%3D%3D'
        ocsp_response = R509::Ocsp::Response.parse(last_response.body)
        ocsp_response.status.should == OpenSSL::OCSP::RESPONSE_STATUS_SUCCESSFUL
        ocsp_response.basic.status[0][1].should == OpenSSL::OCSP::V_CERTSTATUS_GOOD
        ocsp_response.basic.status[0][0].serial.should == 1051177536915098490149656742929223623669143613238
        ocsp_response.verify(@test_ca_cert).should == true
        last_response.content_type.should == "application/ocsp-response"
        last_response.should be_ok
    end
    it "should return a valid (VALID) response on a GET request with extra leading slashes from the test_ca CA" do
        class R509::Validity::Redis::Checker
            def check(issuer, serial)
                R509::Validity::Status.new(:status => R509::Validity::VALID, :revocation_time => nil, :revocation_reason => 0)
            end
        end
        get '/%2F%2FMFYwVDBSMFAwTjAJBgUrDgMCGgUABBQ4ykaMB0SN9IGWx21tTHBRnmCnvQQUeXW7hDrLLN56Cb4xG0O8HCpNU1gCFQC4IG5U4zC4RYb4VQ%2B2f0zCoFCvNg%3D%3D'
        ocsp_response = R509::Ocsp::Response.parse(last_response.body)
        ocsp_response.status.should == OpenSSL::OCSP::RESPONSE_STATUS_SUCCESSFUL
        ocsp_response.basic.status[0][1].should == OpenSSL::OCSP::V_CERTSTATUS_GOOD
        ocsp_response.basic.status[0][0].serial.should == 1051177536915098490149656742929223623669143613238
        ocsp_response.verify(@test_ca_cert).should == true
        last_response.content_type.should == "application/ocsp-response"
        last_response.should be_ok
    end
    it "should return a valid (VALID) response on a GET request from a second configured CA (second_ca)" do
        class R509::Validity::Redis::Checker
            def check(issuer, serial)
                R509::Validity::Status.new(:status => R509::Validity::VALID, :revocation_time => nil, :revocation_reason => 0)
            end
        end
        get '/MFYwVDBSMFAwTjAJBgUrDgMCGgUABBT1kOLWHXbHiKP3sVPVxVziq%2FMqIwQUP8ezIf8yhMLgHnccSKJLQdhDaVkCFQCHf1HsjUAACwcp3qQL4IxclfXSww%3D%3D'
        ocsp_response = R509::Ocsp::Response.parse(last_response.body)
        ocsp_response.status.should == OpenSSL::OCSP::RESPONSE_STATUS_SUCCESSFUL
        ocsp_response.basic.status[0][1].should == OpenSSL::OCSP::V_CERTSTATUS_GOOD
        ocsp_response.basic.status[0][0].serial.should == 773553085290984246110251380739025914079776985795
        ocsp_response.verify(@test_ca_cert).should == false
        ocsp_response.verify(@second_ca_cert).should == true
        last_response.content_type.should == "application/ocsp-response"
        last_response.should be_ok
    end
    it "should return unauthorized on a POST which does not match any configured CA" do
        class R509::Validity::Redis::Checker
            def check(issuer, serial)
                raise StandardError.new("Shouldn't ever call the Checker here, since the request isn't from the configured CA")
            end
        end
        der = Base64.decode64(URI.decode("MFEwTzBNMEswSTAJBgUrDgMCGgUABBQ1mI4Ww4R5LZiQ295pj4OF%2F44yyAQUyk7dWyc1Kdn27sPlU%2B%2BkwBmWHa8CEFqb7H4xpqYH6ed2G0%2BPMG4%3D"))
        post '/', der, "CONTENT_TYPE" => "application/ocsp-request"
        ocsp_response = R509::Ocsp::Response.parse(last_response.body)
        ocsp_response.status.should == OpenSSL::OCSP::RESPONSE_STATUS_UNAUTHORIZED
        last_response.content_type.should == "application/ocsp-response"
        last_response.should be_ok
    end
    it "should return a valid (UNKNOWN) response on a POST request from the test_ca CA" do
        class R509::Validity::Redis::Checker
            def check(issuer, serial)
                R509::Validity::Status.new(:status => R509::Validity::UNKNOWN)
            end
        end
        der = Base64.decode64(URI.decode("MFYwVDBSMFAwTjAJBgUrDgMCGgUABBQ4ykaMB0SN9IGWx21tTHBRnmCnvQQUeXW7hDrLLN56Cb4xG0O8HCpNU1gCFQC4IG5U4zC4RYb4VQ%2B2f0zCoFCvNg%3D%3D"))
        post '/', der, "CONTENT_TYPE" => "application/ocsp-request"
        ocsp_response = R509::Ocsp::Response.parse(last_response.body)
        ocsp_response.status.should == OpenSSL::OCSP::RESPONSE_STATUS_SUCCESSFUL
        ocsp_response.basic.status[0][1].should == OpenSSL::OCSP::V_CERTSTATUS_UNKNOWN
        ocsp_response.basic.status[0][0].serial.should == 1051177536915098490149656742929223623669143613238
        ocsp_response.verify(@test_ca_cert).should == true
        last_response.content_type.should == "application/ocsp-response"
        last_response.should be_ok
    end
    it "should return a valid (REVOKED) response on a POST request from the test_ca CA" do
        class R509::Validity::Redis::Checker
            def check(issuer, serial)
                R509::Validity::Status.new(:status => R509::Validity::REVOKED, :revocation_time => 123, :revocation_reason => 1)
            end
        end
        der = Base64.decode64(URI.decode("MFYwVDBSMFAwTjAJBgUrDgMCGgUABBQ4ykaMB0SN9IGWx21tTHBRnmCnvQQUeXW7hDrLLN56Cb4xG0O8HCpNU1gCFQC4IG5U4zC4RYb4VQ%2B2f0zCoFCvNg%3D%3D"))
        post '/', der, "CONTENT_TYPE" => "application/ocsp-request"
        ocsp_response = R509::Ocsp::Response.parse(last_response.body)
        ocsp_response.status.should == OpenSSL::OCSP::RESPONSE_STATUS_SUCCESSFUL
        ocsp_response.basic.status[0][1].should == OpenSSL::OCSP::V_CERTSTATUS_REVOKED
        ocsp_response.basic.status[0][0].serial.should == 1051177536915098490149656742929223623669143613238
        ocsp_response.verify(@test_ca_cert).should == true
        last_response.content_type.should == "application/ocsp-response"
        last_response.should be_ok
    end
    it "should return a valid (VALID) response on a POST request from the test_ca CA" do
        class R509::Validity::Redis::Checker
            def check(issuer, serial)
                R509::Validity::Status.new(:status => R509::Validity::VALID, :revocation_time => nil, :revocation_reason => 0)
            end
        end
        der = Base64.decode64(URI.decode("MFYwVDBSMFAwTjAJBgUrDgMCGgUABBQ4ykaMB0SN9IGWx21tTHBRnmCnvQQUeXW7hDrLLN56Cb4xG0O8HCpNU1gCFQC4IG5U4zC4RYb4VQ%2B2f0zCoFCvNg%3D%3D"))
        post '/', der, "CONTENT_TYPE" => "application/ocsp-request"
        ocsp_response = R509::Ocsp::Response.parse(last_response.body)
        ocsp_response.status.should == OpenSSL::OCSP::RESPONSE_STATUS_SUCCESSFUL
        ocsp_response.basic.status[0][1].should == OpenSSL::OCSP::V_CERTSTATUS_GOOD
        ocsp_response.basic.status[0][0].serial.should == 1051177536915098490149656742929223623669143613238
        ocsp_response.verify(@test_ca_cert).should == true
        last_response.content_type.should == "application/ocsp-response"
        last_response.should be_ok
    end
    it "should return a valid (VALID) response on a POST request from a second configured CA (second_ca)" do
        class R509::Validity::Redis::Checker
            def check(issuer, serial)
                R509::Validity::Status.new(:status => R509::Validity::VALID, :revocation_time => nil, :revocation_reason => 0)
            end
        end
        der = Base64.decode64(URI.decode("MFYwVDBSMFAwTjAJBgUrDgMCGgUABBT1kOLWHXbHiKP3sVPVxVziq%2FMqIwQUP8ezIf8yhMLgHnccSKJLQdhDaVkCFQCHf1HsjUAACwcp3qQL4IxclfXSww%3D%3D"))
        post '/', der, "CONTENT_TYPE" => "application/ocsp-request"
        ocsp_response = R509::Ocsp::Response.parse(last_response.body)
        ocsp_response.status.should == OpenSSL::OCSP::RESPONSE_STATUS_SUCCESSFUL
        ocsp_response.basic.status[0][1].should == OpenSSL::OCSP::V_CERTSTATUS_GOOD
        ocsp_response.basic.status[0][0].serial.should == 773553085290984246110251380739025914079776985795
        ocsp_response.verify(@test_ca_cert).should == false
        ocsp_response.verify(@second_ca_cert).should == true
        last_response.content_type.should == "application/ocsp-response"
        last_response.should be_ok
    end
    it "should return 200 OK when querying status and redis is available" do
        @redis.should_receive(:ping).and_return("PONG")
        get '/status'
        last_response.should be_ok
    end
    it "should return 500 DOWN when querying status with redis unavailable" do
        @redis.should_receive(:ping).and_raise(StandardError)
        get '/status'
        last_response.should_not be_ok
        last_response.body.should == "Down"
    end
    it "a malformed request should return a proper OCSP response (GET)" do
        get '/Msdfsfsdf'
        ocsp_response = R509::Ocsp::Response.parse(last_response.body)
        ocsp_response.status.should == OpenSSL::OCSP::RESPONSE_STATUS_MALFORMEDREQUEST
        last_response.content_type.should == "application/ocsp-response"
        last_response.should be_ok
    end
    it "a malformed request should return a proper OCSP response (POST)" do
        post '/', 'Mdskfsdf', "CONTENT_TYPE" => "application/ocsp-request"
        ocsp_response = R509::Ocsp::Response.parse(last_response.body)
        ocsp_response.status.should == OpenSSL::OCSP::RESPONSE_STATUS_MALFORMEDREQUEST
        last_response.content_type.should == "application/ocsp-response"
        last_response.should be_ok
    end
    it "copies nonce when copy_nonce is true" do
        class R509::Validity::Redis::Checker
            def check(issuer, serial)
                R509::Validity::Status.new(:status => R509::Validity::VALID, :revocation_time => nil, :revocation_reason => 0)
            end
        end

        # set to true for this test (this works because the app doesn't get set up until after this code)
        Dependo::Registry[:copy_nonce] = true

        get '/MHsweTBSMFAwTjAJBgUrDgMCGgUABBQ4ykaMB0SN9IGWx21tTHBRnmCnvQQUeXW7hDrLLN56Cb4xG0O8HCpNU1gCFQCY2eXAtMNzVS33fF0PHrUSjklF%2BaIjMCEwHwYJKwYBBQUHMAECBBIEEDTJniOQonxCRmmHAHCVstw%3D'
        request = OpenSSL::OCSP::Request.new(Base64.decode64("MHsweTBSMFAwTjAJBgUrDgMCGgUABBQ4ykaMB0SN9IGWx21tTHBRnmCnvQQUeXW7hDrLLN56Cb4xG0O8HCpNU1gCFQCY2eXAtMNzVS33fF0PHrUSjklF+aIjMCEwHwYJKwYBBQUHMAECBBIEEDTJniOQonxCRmmHAHCVstw="))
        ocsp_response = R509::Ocsp::Response.parse(last_response.body)
        request.check_nonce(ocsp_response.basic).should == R509::Ocsp::Request::Nonce::PRESENT_AND_EQUAL

    end
    it "doesn't copy nonce when copy_nonce is false" do
        class R509::Validity::Redis::Checker
            def check(issuer, serial)
                R509::Validity::Status.new(:status => R509::Validity::VALID, :revocation_time => nil, :revocation_reason => 0)
            end
        end

        # set to false for this test (this works because the app doesn't get set up until after this code)
        Dependo::Registry[:copy_nonce] = false

        get '/MHsweTBSMFAwTjAJBgUrDgMCGgUABBQ4ykaMB0SN9IGWx21tTHBRnmCnvQQUeXW7hDrLLN56Cb4xG0O8HCpNU1gCFQCY2eXAtMNzVS33fF0PHrUSjklF%2BaIjMCEwHwYJKwYBBQUHMAECBBIEEDTJniOQonxCRmmHAHCVstw%3D'
        request = OpenSSL::OCSP::Request.new(Base64.decode64("MHsweTBSMFAwTjAJBgUrDgMCGgUABBQ4ykaMB0SN9IGWx21tTHBRnmCnvQQUeXW7hDrLLN56Cb4xG0O8HCpNU1gCFQCY2eXAtMNzVS33fF0PHrUSjklF+aIjMCEwHwYJKwYBBQUHMAECBBIEEDTJniOQonxCRmmHAHCVstw="))
        ocsp_response = R509::Ocsp::Response.parse(last_response.body)
        request.check_nonce(ocsp_response.basic).should == R509::Ocsp::Request::Nonce::REQUEST_ONLY
    end
    it "returns caching headers for GET when http_cache_headers is true" do
        Dependo::Registry[:cache_headers] = true

        class R509::Validity::Redis::Checker
            def check(issuer, serial)
                R509::Validity::Status.new(:status => R509::Validity::VALID, :revocation_time => nil, :revocation_reason => 0)
            end
        end

        get '/MFYwVDBSMFAwTjAJBgUrDgMCGgUABBT1kOLWHXbHiKP3sVPVxVziq%2FMqIwQUP8ezIf8yhMLgHnccSKJLQdhDaVkCFQCHf1HsjUAACwcp3qQL4IxclfXSww%3D%3D'
        ocsp_response = R509::Ocsp::Response.parse(last_response.body)
        max_age = (ocsp_response.basic.status[0][5] - ocsp_response.basic.status[0][4]) - 3600
        last_response.headers.size.should == 6
        last_response.headers["Last-Modified"].should == ocsp_response.basic.status[0][4].httpdate
        last_response.headers["ETag"] = OpenSSL::Digest::SHA1.new(ocsp_response.to_der)
        last_response.headers["Expires"].should == ocsp_response.basic.status[0][5].httpdate
        last_response.headers["Cache-Control"].should == "max-age=#{max_age.to_i}, public, no-transform, must-revalidate"
    end
    it "returns no caching headers for GET when http_cache_headers is false" do
        Dependo::Registry[:cache_headers] = false

        class R509::Validity::Redis::Checker
            def check(issuer, serial)
                R509::Validity::Status.new(:status => R509::Validity::VALID, :revocation_time => nil, :revocation_reason => 0)
            end
        end

        get '/MFYwVDBSMFAwTjAJBgUrDgMCGgUABBT1kOLWHXbHiKP3sVPVxVziq%2FMqIwQUP8ezIf8yhMLgHnccSKJLQdhDaVkCFQCHf1HsjUAACwcp3qQL4IxclfXSww%3D%3D'
        last_response.content_type.should == "application/ocsp-response"
        last_response.headers.size.should == 2
        last_response.should be_ok
    end
    it "returns no caching headers for POST when http_cache_headers is true" do
        Dependo::Registry[:cache_headers] = true

        class R509::Validity::Redis::Checker
            def check(issuer, serial)
                R509::Validity::Status.new(:status => R509::Validity::VALID, :revocation_time => nil, :revocation_reason => 0)
            end
        end
        der = Base64.decode64(URI.decode("MFYwVDBSMFAwTjAJBgUrDgMCGgUABBQ4ykaMB0SN9IGWx21tTHBRnmCnvQQUeXW7hDrLLN56Cb4xG0O8HCpNU1gCFQC4IG5U4zC4RYb4VQ%2B2f0zCoFCvNg%3D%3D"))
        post '/', der, "CONTENT_TYPE" => "application/ocsp-request"
        ocsp_response = R509::Ocsp::Response.parse(last_response.body)
        last_response.content_type.should == "application/ocsp-response"
        last_response.headers.size.should == 2
        last_response.should be_ok
    end
    it "returns no caching headers for POST when http_cache_headers is false" do
        Dependo::Registry[:cache_headers] = false

        class R509::Validity::Redis::Checker
            def check(issuer, serial)
                R509::Validity::Status.new(:status => R509::Validity::VALID, :revocation_time => nil, :revocation_reason => 0)
            end
        end
        der = Base64.decode64(URI.decode("MFYwVDBSMFAwTjAJBgUrDgMCGgUABBQ4ykaMB0SN9IGWx21tTHBRnmCnvQQUeXW7hDrLLN56Cb4xG0O8HCpNU1gCFQC4IG5U4zC4RYb4VQ%2B2f0zCoFCvNg%3D%3D"))
        post '/', der, "CONTENT_TYPE" => "application/ocsp-request"
        ocsp_response = R509::Ocsp::Response.parse(last_response.body)
        last_response.content_type.should == "application/ocsp-response"
        last_response.headers.size.should == 2
        last_response.should be_ok
    end
end
