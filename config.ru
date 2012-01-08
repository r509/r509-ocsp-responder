require './environment'
require './lib/r509/ocsp/responder'

Dependo::Registry[:log] = Logger.new(STDOUT)

responder = R509::Ocsp::Responder
run responder
