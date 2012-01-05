require File.dirname(__FILE__) + '/spec_helper'


describe R509::Ocsp::Responder do
    before :each do
        @redis = double("redis")
    end
    def app
        @app ||= R509::Ocsp::Responder
        @app.send(:set, :redis, @redis)
        #@app.send(:set, :log, Logger.new(STDOUT))
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
end
