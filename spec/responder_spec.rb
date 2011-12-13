require File.dirname(__FILE__) + '/spec_helper'


describe R509::Ocsp::Responder do
    def app
        @app ||= R509::Ocsp::Responder
    end

    it "should return unauthorized on a GET unrelated to the configured CA" do
        get '/MFEwTzBNMEswSTAJBgUrDgMCGgUABBQ1mI4Ww4R5LZiQ295pj4OF%2F44yyAQUyk7dWyc1Kdn27sPlU%2B%2BkwBmWHa8CEFqb7H4xpqYH6ed2G0%2BPMG4%3D'
        last_response.content_type.should == "application/ocsp-response"
        last_response.should be_ok
        ocsp_response = R509::Ocsp::Response.parse(last_response.body)
        ocsp_response.status.should == OpenSSL::OCSP::RESPONSE_STATUS_UNAUTHORIZED
    end
    it "should return a valid response on a GET request from the configured CA" do
        get '/MFYwVDBSMFAwTjAJBgUrDgMCGgUABBQ4ykaMB0SN9IGWx21tTHBRnmCnvQQUeXW7hDrLLN56Cb4xG0O8HCpNU1gCFQC4IG5U4zC4RYb4VQ%2B2f0zCoFCvNg%3D%3D'
        last_response.content_type.should == "application/ocsp-response"
        last_response.should be_ok
        ocsp_response = R509::Ocsp::Response.parse(last_response.body)
        ocsp_response.status.should == OpenSSL::OCSP::RESPONSE_STATUS_SUCCESSFUL
        ocsp_response.basic.status[0][1].should == 2
        ocsp_response.basic.status[0][0].serial.should == 1051177536915098490149656742929223623669143613238
    end
end
