require './lib/r509/Ocsp/Responder'
responder = R509::Ocsp::Responder
responder.send(:set, :log, Logger.new(STDOUT))
run responder
