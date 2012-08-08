require 'spec_helper'
require 'r509/ocsp'
require 'openssl'

describe R509::Ocsp::Signer do
    before :all do
        @cert = TestFixtures::CERT
        @stca_cert = TestFixtures::STCA_CERT
        @stca_ocsp_request = TestFixtures::STCA_OCSP_REQUEST
        @ocsp_test_cert = TestFixtures::OCSP_TEST_CERT
        @test_ca_config = TestFixtures.test_ca_config
        @test_ca_subroot_config = TestFixtures.test_ca_subroot_config
        @second_ca_config = TestFixtures.second_ca_config
        @ocsp_delegate_config = R509::Config::CaConfig.from_yaml("ocsp_delegate_ca", File.read("#{File.dirname(__FILE__)}/fixtures/config_test_various.yaml"), {:ca_root_path => "#{File.dirname(__FILE__)}/fixtures"})
        @ocsp_subroot_delegate_config = R509::Config::CaConfig.from_yaml("ocsp_subroot_delegate_ca", File.read("#{File.dirname(__FILE__)}/fixtures/config_test_various.yaml"), {:ca_root_path => "#{File.dirname(__FILE__)}/fixtures"})
        @ocsp_chain_config = R509::Config::CaConfig.from_yaml("ocsp_chain_ca", File.read("#{File.dirname(__FILE__)}/fixtures/config_test_various.yaml"), {:ca_root_path => "#{File.dirname(__FILE__)}/fixtures"})
        Dependo::Registry.clear
        Dependo::Registry[:log] = Logger.new(nil)

    end
    it "rejects ocsp requests from an unknown CA" do
        ocsp_handler = R509::Ocsp::Signer.new( :configs => [@test_ca_config] )
        request_response = ocsp_handler.handle_request(@stca_ocsp_request)
        request_response[:response].status.should == OpenSSL::OCSP::RESPONSE_STATUS_UNAUTHORIZED
    end
    it "rejects malformed OCSP requests" do
        ocsp_handler = R509::Ocsp::Signer.new( :configs => [@test_ca_config] )
        request_response = ocsp_handler.handle_request("notreallyanocsprequest")
        request_response[:response].status.should == OpenSSL::OCSP::RESPONSE_STATUS_MALFORMEDREQUEST
    end
    it "responds successfully with an OCSP delegate" do
        ocsp_handler = R509::Ocsp::Signer.new( :configs => [@ocsp_delegate_config] )
        csr = R509::Csr.new( :subject => [['CN','ocsptest.r509.local']], :bit_strength => 1024 )
        ca = R509::CertificateAuthority::Signer.new(@test_ca_config)
        cert = ca.sign(:csr => csr, :profile_name => 'server')
        ocsp_request = OpenSSL::OCSP::Request.new
        certid = OpenSSL::OCSP::CertificateId.new(cert.cert,@test_ca_config.ca_cert.cert)
        ocsp_request.add_certid(certid)
        request_response = ocsp_handler.handle_request(ocsp_request)
        request_response[:response].status.should == OpenSSL::OCSP::RESPONSE_STATUS_SUCCESSFUL
        request_response[:response].verify(@ocsp_delegate_config.ca_cert.cert).should == true
        #TODO Better way to check whether we're adding the certs when signing the basic_response than response size...
        request_response[:response].to_der.size.should == 1678
    end
    it "responds successfully for a subroot (signing via subroot)" do
        ocsp_handler = R509::Ocsp::Signer.new( :configs => [@test_ca_subroot_config] )
        csr = R509::Csr.new( :subject => [['CN','ocsptest.r509.local']], :bit_strength => 1024 )
        ca = R509::CertificateAuthority::Signer.new(@test_ca_subroot_config)
        cert = ca.sign(:csr => csr, :profile_name => 'server')
        ocsp_request = OpenSSL::OCSP::Request.new
        certid = OpenSSL::OCSP::CertificateId.new(cert.cert,@test_ca_subroot_config.ca_cert.cert)
        ocsp_request.add_certid(certid)
        request_response = ocsp_handler.handle_request(ocsp_request)
        request_response[:response].status.should == OpenSSL::OCSP::RESPONSE_STATUS_SUCCESSFUL
        request_response[:response].verify([@test_ca_subroot_config.ca_cert.cert,@test_ca_config.ca_cert.cert]).should == true
    end
    it "responds successfully for a subroot (signing via delegate)" do
        ocsp_handler = R509::Ocsp::Signer.new( :configs => [@ocsp_subroot_delegate_config] )
        csr = R509::Csr.new( :subject => [['CN','ocsptest.r509.local']], :bit_strength => 1024 )
        ca = R509::CertificateAuthority::Signer.new(@test_ca_subroot_config)
        cert = ca.sign(:csr => csr, :profile_name => 'server')
        ocsp_request = OpenSSL::OCSP::Request.new
        certid = OpenSSL::OCSP::CertificateId.new(cert.cert,@test_ca_subroot_config.ca_cert.cert)
        ocsp_request.add_certid(certid)
        request_response = ocsp_handler.handle_request(ocsp_request)
        request_response[:response].status.should == OpenSSL::OCSP::RESPONSE_STATUS_SUCCESSFUL
        request_response[:response].verify([@test_ca_subroot_config.ca_cert.cert,@test_ca_config.ca_cert.cert]).should == true
    end
    it "responds successfully with an OCSP chain" do
        ocsp_handler = R509::Ocsp::Signer.new( :configs => [@ocsp_chain_config] )
        csr = R509::Csr.new( :subject => [['CN','ocsptest.r509.local']], :bit_strength => 1024 )
        ca = R509::CertificateAuthority::Signer.new(@test_ca_config)
        cert = ca.sign(:csr => csr, :profile_name => 'server')
        ocsp_request = OpenSSL::OCSP::Request.new
        certid = OpenSSL::OCSP::CertificateId.new(cert.cert,@test_ca_config.ca_cert.cert)
        ocsp_request.add_certid(certid)
        request_response = ocsp_handler.handle_request(ocsp_request)
        request_response[:response].status.should == OpenSSL::OCSP::RESPONSE_STATUS_SUCCESSFUL
        request_response[:response].verify(@ocsp_chain_config.ca_cert.cert).should == true
        #TODO Better way to check whether we're adding the certs when signing the basic_response than response size...
        request_response[:response].to_der.size.should == 3725
    end
    it "responds successfully from the test_ca" do
        csr = R509::Csr.new( :subject => [['CN','ocsptest.r509.local']], :bit_strength => 1024 )
        ca = R509::CertificateAuthority::Signer.new(@test_ca_config)
        cert = ca.sign(:csr => csr, :profile_name => 'server')
        ocsp_request = OpenSSL::OCSP::Request.new
        certid = OpenSSL::OCSP::CertificateId.new(cert.cert,@test_ca_config.ca_cert.cert)
        ocsp_request.add_certid(certid)
        ocsp_handler = R509::Ocsp::Signer.new({ :configs => [@test_ca_config] })
        request_response = ocsp_handler.handle_request(ocsp_request)
        request_response[:response].status.should == OpenSSL::OCSP::RESPONSE_STATUS_SUCCESSFUL
        request_response[:request].should_not be_nil
    end
    it "rejects request with 2 certs from different known CAs" do
        ca = R509::CertificateAuthority::Signer.new(@test_ca_config)

        csr = R509::Csr.new( :subject => [['CN','ocsptest.r509.local']], :bit_strength => 1024 )
        cert = ca.sign(:csr => csr, :profile_name => 'server')

        ca2 = R509::CertificateAuthority::Signer.new(@second_ca_config)

        csr2 = R509::Csr.new( :subject => [['CN','ocsptest2.r509.local']], :bit_strength => 1024 )
        cert2 = ca2.sign(:csr => csr2, :profile_name => 'server')

        ocsp_request = OpenSSL::OCSP::Request.new
        certid = OpenSSL::OCSP::CertificateId.new(cert.cert,@test_ca_config.ca_cert.cert)
        ocsp_request.add_certid(certid)
        certid2 = OpenSSL::OCSP::CertificateId.new(cert2.cert,@second_ca_config.ca_cert.cert)
        ocsp_request.add_certid(certid2)

        ocsp_handler = R509::Ocsp::Signer.new({ :configs => [@test_ca_config,@second_ca_config] })
        request_response = ocsp_handler.handle_request(ocsp_request)
        request_response[:response].status.should == OpenSSL::OCSP::RESPONSE_STATUS_UNAUTHORIZED
        request_response[:request].should be_nil
    end
    it "rejects request with 1 cert from known CA and 1 cert from unknown CA" do
        ca = R509::CertificateAuthority::Signer.new(@test_ca_config)

        csr = R509::Csr.new( :subject => [['CN','ocsptest.r509.local']], :bit_strength => 1024 )
        cert = ca.sign(:csr => csr, :profile_name => 'server')

        ocsp_request = OpenSSL::OCSP::Request.new
        certid = OpenSSL::OCSP::CertificateId.new(cert.cert,@test_ca_config.ca_cert.cert)
        ocsp_request.add_certid(certid)
        certid2 = OpenSSL::OCSP::CertificateId.new(OpenSSL::X509::Certificate.new(@cert),OpenSSL::X509::Certificate.new(@stca_cert))
        ocsp_request.add_certid(certid2)

        ocsp_handler = R509::Ocsp::Signer.new({ :configs => [@test_ca_config] })
        request_response = ocsp_handler.handle_request(ocsp_request)
        request_response[:response].status.should == OpenSSL::OCSP::RESPONSE_STATUS_UNAUTHORIZED
    end
    it "responds successfully with 2 certs from 1 known CA" do
        ca = R509::CertificateAuthority::Signer.new(@test_ca_config)

        csr = R509::Csr.new( :subject => [['CN','ocsptest.r509.local']], :bit_strength => 1024 )
        cert = ca.sign(:csr => csr, :profile_name => 'server')

        csr2 = R509::Csr.new( :subject => [['CN','ocsptest.r509.local']], :bit_strength => 1024 )
        cert2 = ca.sign(:csr => csr2, :profile_name => 'server')

        ocsp_request = OpenSSL::OCSP::Request.new
        certid = OpenSSL::OCSP::CertificateId.new(cert.cert,@test_ca_config.ca_cert.cert)
        ocsp_request.add_certid(certid)
        certid2 = OpenSSL::OCSP::CertificateId.new(cert2.cert,@test_ca_config.ca_cert.cert)
        ocsp_request.add_certid(certid2)

        ocsp_handler = R509::Ocsp::Signer.new({ :configs => [@test_ca_config] })
        request_response = ocsp_handler.handle_request(ocsp_request)
        request_response[:response].status.should == OpenSSL::OCSP::RESPONSE_STATUS_SUCCESSFUL
    end
    it "signs an OCSP response properly" do
        cert = OpenSSL::X509::Certificate.new(@ocsp_test_cert)
        ocsp_request = OpenSSL::OCSP::Request.new
        certid = OpenSSL::OCSP::CertificateId.new(cert,@test_ca_config.ca_cert.cert)
        ocsp_request.add_certid(certid)
        ocsp_handler = R509::Ocsp::Signer.new({ :configs => [@test_ca_config] })
        request_response = ocsp_handler.handle_request(ocsp_request)
        request_response[:response].verify(@test_ca_config.ca_cert.cert).should == true
        request_response[:response].verify(@second_ca_config.ca_cert.cert).should == false
        request_response[:response].basic.status[0][1].should == OpenSSL::OCSP::V_CERTSTATUS_GOOD
    end
    it "passes in a specific validity checker" do
        class R509::Validity::BogusTestChecker < R509::Validity::Checker
            def check(issuer_fingerprint, serial)
                R509::Validity::Status.new(:status => R509::Validity::REVOKED, :revocation_time => Time.now.to_i)
            end
        end
        cert = OpenSSL::X509::Certificate.new(@ocsp_test_cert)
        ocsp_request = OpenSSL::OCSP::Request.new
        certid = OpenSSL::OCSP::CertificateId.new(cert,@test_ca_config.ca_cert.cert)
        ocsp_request.add_certid(certid)
        ocsp_handler = R509::Ocsp::Signer.new({ :configs => [@test_ca_config], :validity_checker => R509::Validity::BogusTestChecker.new })
        request_response = ocsp_handler.handle_request(ocsp_request)
        request_response[:response].verify(@test_ca_config.ca_cert.cert).should == true
        request_response[:response].basic.status[0][1].should == OpenSSL::OCSP::V_CERTSTATUS_REVOKED
    end
    it "encodes the proper revocation time in the response" do
        time = Time.now.to_i-3600
        class R509::Validity::BogusTestChecker < R509::Validity::Checker
            def initialize(time)
                @time = time
            end
            def check(issuer_fingerprint, serial)
                R509::Validity::Status.new(:status => R509::Validity::REVOKED, :revocation_time => @time)
            end
        end
        cert = OpenSSL::X509::Certificate.new(@ocsp_test_cert)
        ocsp_request = OpenSSL::OCSP::Request.new
        certid = OpenSSL::OCSP::CertificateId.new(cert,@test_ca_config.ca_cert.cert)
        ocsp_request.add_certid(certid)
        ocsp_handler = R509::Ocsp::Signer.new({ :configs => [@test_ca_config], :validity_checker => R509::Validity::BogusTestChecker.new(time) })
        request_response = ocsp_handler.handle_request(ocsp_request)
        request_response[:response].basic.status[0][3].to_i.should == time
    end
    it "copies nonce from request to response if copy_nonce is true" do
        cert = OpenSSL::X509::Certificate.new(@ocsp_test_cert)
        ocsp_request = OpenSSL::OCSP::Request.new
        certid = OpenSSL::OCSP::CertificateId.new(cert,@test_ca_config.ca_cert.cert)
        ocsp_request.add_certid(certid)
        ocsp_request.add_nonce
        ocsp_handler = R509::Ocsp::Signer.new({ :copy_nonce => true, :configs => [@test_ca_config] })
        request_response = ocsp_handler.handle_request(ocsp_request)
        request_response[:response].check_nonce(ocsp_request).should == R509::Ocsp::Request::Nonce::PRESENT_AND_EQUAL
    end
    it "doesn't copy nonce if request doesn't have one and copy_nonce is true" do
        cert = OpenSSL::X509::Certificate.new(@ocsp_test_cert)
        ocsp_request = OpenSSL::OCSP::Request.new
        certid = OpenSSL::OCSP::CertificateId.new(cert,@test_ca_config.ca_cert.cert)
        ocsp_request.add_certid(certid)
        ocsp_handler = R509::Ocsp::Signer.new( :copy_nonce => true, :configs => [@test_ca_config] )
        request_response = ocsp_handler.handle_request(ocsp_request)
        request_response[:response].check_nonce(ocsp_request).should == R509::Ocsp::Request::Nonce::BOTH_ABSENT
    end
    it "doesn't copy nonce if request doesn't have one and copy_nonce is false" do
        cert = OpenSSL::X509::Certificate.new(@ocsp_test_cert)
        ocsp_request = OpenSSL::OCSP::Request.new
        certid = OpenSSL::OCSP::CertificateId.new(cert,@test_ca_config.ca_cert.cert)
        ocsp_request.add_certid(certid)
        ocsp_handler = R509::Ocsp::Signer.new( :copy_nonce => false, :configs => [@test_ca_config] )
        request_response = ocsp_handler.handle_request(ocsp_request)
        request_response[:response].check_nonce(ocsp_request).should == R509::Ocsp::Request::Nonce::BOTH_ABSENT
    end
    it "nonce in request only if copy_nonce is false" do
        cert = OpenSSL::X509::Certificate.new(@ocsp_test_cert)
        ocsp_request = OpenSSL::OCSP::Request.new
        certid = OpenSSL::OCSP::CertificateId.new(cert,@test_ca_config.ca_cert.cert)
        ocsp_request.add_certid(certid)
        ocsp_request.add_nonce
        ocsp_handler = R509::Ocsp::Signer.new( :copy_nonce => false, :configs => [@test_ca_config] )
        request_response = ocsp_handler.handle_request(ocsp_request)
        request_response[:response].check_nonce(ocsp_request).should == R509::Ocsp::Request::Nonce::REQUEST_ONLY
    end
    it "encodes thisUpdate/nextUpdate time properly" do
        cert = OpenSSL::X509::Certificate.new(@ocsp_test_cert)
        ocsp_request = OpenSSL::OCSP::Request.new
        certid = OpenSSL::OCSP::CertificateId.new(cert,@test_ca_config.ca_cert.cert)
        ocsp_request.add_certid(certid)
        now = Time.now
        ocsp_handler = R509::Ocsp::Signer.new( :configs => [@test_ca_config] )
        request_response = ocsp_handler.handle_request(ocsp_request)
        request_response[:response].basic.status[0][4].to_i.should == now.to_i - @test_ca_config.ocsp_start_skew_seconds
        request_response[:response].basic.status[0][5].to_i.should == now.to_i + @test_ca_config.ocsp_validity_hours*3600
    end
end

describe R509::Ocsp::Helper::RequestChecker do
    before :all do
        @cert = TestFixtures::CERT
        @test_ca_config = TestFixtures.test_ca_config
        @second_ca_config = TestFixtures.second_ca_config
    end
    it "fails if you don't give it an array of configs" do
        expect { R509::Ocsp::Helper::RequestChecker.new({}, nil) }.to raise_error(R509::R509Error)
    end
    it "fails if you give it an empty array of configs" do
        expect { R509::Ocsp::Helper::RequestChecker.new([], nil) }.to raise_error(R509::R509Error)
    end
    it "fails if you give it a valid config but nil validity checker" do
        expect { R509::Ocsp::Helper::RequestChecker.new([@test_ca_config], nil) }.to raise_error(R509::R509Error)
    end
    it "fails if you give it a valid config but the validity checker doesn't respond to a check method" do
        class FakeChecker
        end
        fake_checker = FakeChecker.new
        expect { R509::Ocsp::Helper::RequestChecker.new([@test_ca_config], fake_checker) }.to raise_error(R509::R509Error)
    end
end

describe R509::Ocsp::Helper::ResponseSigner do
    before :all do
        @cert = TestFixtures::CERT
        @test_ca_config = TestFixtures.test_ca_config
        @second_ca_config = TestFixtures.second_ca_config
    end
    it "fails if you don't give it an array of configs" do
        expect { R509::Ocsp::Helper::ResponseSigner.new({}) }.to raise_error(R509::R509Error)
    end
    it "fails if you give it an empty array of configs" do
        expect { R509::Ocsp::Helper::ResponseSigner.new({:configs=>[]}) }.to raise_error(R509::R509Error)
    end
end
