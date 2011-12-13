require File.dirname(__FILE__) + '/spec_helper'


describe R509::Ocsp::Responder do
    def app
        @app ||= R509::Ocsp::Responder
    end

    it "should return unauthorized on a GET unrelated to the configured CA" do
        class R509::Validity::Redis::Checker
            def check(serial)
                raise StandardError.new("Shouldn't ever call the Checker here, since the request isn't from the configured CA")
            end
        end
        get '/MFEwTzBNMEswSTAJBgUrDgMCGgUABBQ1mI4Ww4R5LZiQ295pj4OF%2F44yyAQUyk7dWyc1Kdn27sPlU%2B%2BkwBmWHa8CEFqb7H4xpqYH6ed2G0%2BPMG4%3D'
        last_response.content_type.should == "application/ocsp-response"
        last_response.should be_ok
        ocsp_response = R509::Ocsp::Response.parse(last_response.body)
        ocsp_response.status.should == OpenSSL::OCSP::RESPONSE_STATUS_UNAUTHORIZED
    end
    it "should return a valid (UNKNOWN) response on a GET request from the configured CA" do
        class R509::Validity::Redis::Checker
            def check(serial)
                R509::Validity::Status.new(:status => R509::Validity::UNKNOWN)
            end
        end
        get '/MFYwVDBSMFAwTjAJBgUrDgMCGgUABBQ4ykaMB0SN9IGWx21tTHBRnmCnvQQUeXW7hDrLLN56Cb4xG0O8HCpNU1gCFQC4IG5U4zC4RYb4VQ%2B2f0zCoFCvNg%3D%3D'
        last_response.content_type.should == "application/ocsp-response"
        last_response.should be_ok
        ocsp_response = R509::Ocsp::Response.parse(last_response.body)
        ocsp_response.status.should == OpenSSL::OCSP::RESPONSE_STATUS_SUCCESSFUL
        ocsp_response.basic.status[0][1].should == OpenSSL::OCSP::V_CERTSTATUS_UNKNOWN
        ocsp_response.basic.status[0][0].serial.should == 1051177536915098490149656742929223623669143613238
    end
    it "should return a valid (REVOKED) response on a GET request from the configured CA" do
        class R509::Validity::Redis::Checker
            def check(serial)
                R509::Validity::Status.new(:status => R509::Validity::REVOKED, :revocation_time => 123, :revocation_reason => 1)
            end
        end
        get '/MFYwVDBSMFAwTjAJBgUrDgMCGgUABBQ4ykaMB0SN9IGWx21tTHBRnmCnvQQUeXW7hDrLLN56Cb4xG0O8HCpNU1gCFQC4IG5U4zC4RYb4VQ%2B2f0zCoFCvNg%3D%3D'
        last_response.content_type.should == "application/ocsp-response"
        last_response.should be_ok
        ocsp_response = R509::Ocsp::Response.parse(last_response.body)
        ocsp_response.status.should == OpenSSL::OCSP::RESPONSE_STATUS_SUCCESSFUL
        ocsp_response.basic.status[0][1].should == OpenSSL::OCSP::V_CERTSTATUS_REVOKED
        ocsp_response.basic.status[0][0].serial.should == 1051177536915098490149656742929223623669143613238
    end
    it "should return a valid (VALID) response on a GET request from the configured CA" do
        class R509::Validity::Redis::Checker
            def check(serial)
                R509::Validity::Status.new(:status => R509::Validity::VALID, :revocation_time => nil, :revocation_reason => 0)
            end
        end
        get '/MFYwVDBSMFAwTjAJBgUrDgMCGgUABBQ4ykaMB0SN9IGWx21tTHBRnmCnvQQUeXW7hDrLLN56Cb4xG0O8HCpNU1gCFQC4IG5U4zC4RYb4VQ%2B2f0zCoFCvNg%3D%3D'
        last_response.content_type.should == "application/ocsp-response"
        last_response.should be_ok
        ocsp_response = R509::Ocsp::Response.parse(last_response.body)
        ocsp_response.status.should == OpenSSL::OCSP::RESPONSE_STATUS_SUCCESSFUL
        ocsp_response.basic.status[0][1].should == OpenSSL::OCSP::V_CERTSTATUS_GOOD
        ocsp_response.basic.status[0][0].serial.should == 1051177536915098490149656742929223623669143613238
    end
end
