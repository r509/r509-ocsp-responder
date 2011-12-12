require File.dirname(__FILE__) + '/spec_helper'


describe OcspResponder::Responder do
    def app
        @app ||= OcspResponder::Responder
    end

    it "should respond to /" do
        get '/MFEwTzBNMEswSTAJBgUrDgMCGgUABBQ1mI4Ww4R5LZiQ295pj4OF%2F44yyAQUyk7dWyc1Kdn27sPlU%2B%2BkwBmWHa8CEFqb7H4xpqYH6ed2G0%2BPMG4%3D'
        last_response.content_type.should == "application/ocsp-response"
        last_response.should be_ok
        ocsp_response = R509::Ocsp::Response.parse(last_response.body)
        ocsp_response.status.should == OpenSSL::OCSP::RESPONSE_STATUS_UNAUTHORIZED
    end
end
