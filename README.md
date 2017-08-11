# r509-ocsp-responder [![Build Status](https://secure.travis-ci.org/r509/r509-ocsp-responder.png)](http://travis-ci.org/r509/r509-ocsp-responder) [![Coverage Status](https://coveralls.io/repos/r509/r509-ocsp-responder/badge.png)](https://coveralls.io/r/r509/r509-ocsp-responder)

r509-ocsp-responder is an OCSP responder written using [r509](https://github.com/r509/r509) and Sinatra to conform to RFC [2560](http://www.ietf.org/rfc/rfc2560.txt) and [5019](http://www.ietf.org/rfc/rfc5019.txt). It supports Ruby 2.3+.

## Requirements

r509-ocsp-responder depends on [r509](https://github.com/r509/r509), [redis](http://redis.io), [r509-validity-redis](https://github.com/sirsean/r509-validity-redis) (or another library that implements R509::Validity such as [r509-validity-crl](https://github.com/r509/r509-validity-crl)), [sinatra](http://sinatrarb.com), and [dependo](https://github.com/sirsean/dependo). These must be installed as gems.

## Basic Usage

### Build/Install

If you have cloned the repo you can build the gem with ```rake gem:build``` and install with ```rake gem:install``` . Alternately you can use a prebuilt gem by typing ```gem install r509-ocsp-responder``` .

### Set Up config.ru

Save the below into a config.ru file

```ruby
require "r509"
require "dependo"
require 'r509/ocsp/responder/server'

Dependo::Registry[:log] = Logger.new(STDOUT)

require "r509/validity/redis"
require 'redis'
begin
  gem "hiredis"
  Dependo::Registry[:log].warn "Loading redis with hiredis driver"
  redis = Redis.new(:driver => :hiredis)
rescue Gem::LoadError
  Dependo::Registry[:log].warn "Loading redis with standard ruby driver"
  redis = Redis.new
end
Dependo::Registry[:validity_checker] = R509::Validity::Redis::Checker.new(redis)


R509::OCSP::Responder::OCSPConfig.load_config

R509::OCSP::Responder::OCSPConfig.print_config

responder = R509::OCSP::Responder::Server
run responder
```


### Configure config.yaml

The config.yaml contains certificate authority nodes as well as options like copy_nonce (documented below). Each CA node has an arbitrary name like test_ca and contains a ca_cert and (optional) ocsp_cert node. If you want to sign OCSP responses directly from your root you'll set your config up like this:

```yaml
---
copy_nonce: true
cache_headers: true
max_cache_age: 60
certificate_authorities:
  second_ca:
    ca_cert:
      cert: spec/fixtures/second_ca.cer
      key: spec/fixtures/second_ca.key
```

If you want to use an OCSP delegate

```yaml
---
copy_nonce: true
cache_headers: true
max_cache_age: 60
certificate_authorities:
  test_ca:
    ca_cert:
      cert: spec/fixtures/test_ca.cer
    ocsp_cert:
      cert: spec/fixtures/test_ca_ocsp.cer
      key: spec/fixtures/test_ca_ocsp.key
```

Finally, if you're responding for multiple roots you specify them like so:

```yaml
---
copy_nonce: true
cache_headers: true
max_cache_age: 60
certificate_authorities:
  test_ca:
    ca_cert:
      cert: spec/fixtures/test_ca.cer
    ocsp_cert:
      cert: spec/fixtures/test_ca_ocsp.cer
      key: spec/fixtures/test_ca_ocsp.key
  second_ca:
    ca_cert:
      cert: spec/fixtures/second_ca.cer
      key: spec/fixtures/second_ca.key
```

### Configure Thin & nginx
The example below is an example yaml config for thin. You will want to have as many servers as you have cores.

```yaml
chdir: /var/www/r509-ocsp-responder
rackup: /var/www/r509-ocsp-responder/config.ru
socket: /var/run/r509-ocsp-responder.sock
pid: /var/run/r509-ocsp-responder.pid
servers: 2
daemonize: true
log: /var/log/r509-ocsp-responder.log
```

Since this config is just using sockets let's set up nginx as a reverse proxy for the thin instances. We can also use this as a caching layer if we choose to enable cache_headers.

```
proxy_cache_path  /var/www/cache levels=1:2 keys_zone=ocsp:8m max_size=16m inactive=64m;
proxy_temp_path /var/www/cache/tmp;

upstream thin_ocsp_responder{
  server unix:/var/run/r509-ocsp-responder.0.sock fail_timeout=0;
  server unix:/var/run/r509-ocsp-responder.1.sock fail_timeout=0;
}
server {
  listen     80;
  server_name  ocsp.r509.org;

  location / {
    proxy_pass http://thin_ocsp_responder;
    proxy_cache ocsp;
    proxy_cache_use_stale updating;
  }
}
```

Within the location block you may also choose to add these directives:

```
proxy_cache_methods GET POST;
proxy_cache_valid  200 302  1m;
```

If present, these lines will cause 200 and 302 responses to POST and GET to be cached for 1 minute. This allows you to cache POST requests (Note: Per the HTTP RFC POST requests should not be cached) in addition to the GET requests normally supported by the ruby layer. __NOTE:__ The proxy\_cache\_valid values are lower priority than caching headers sent by the thin instances so if you do not keep the value here in sync with the max\_cache\_age config (or turn off cache\_headers entirely and solely control it through nginx) you will have mismatched cache times. Additionally, this will cache nonced responses, which wastes RAM since they will not be re-used.

If you would like to track the cache utilization you can also modify the nginx logging to track cache hits. There are a variety of ways this can be accomplisehd, but one of the simplest is simply to alter your log_format line to add ```$upstream_cache_status```.

## Options
This OCSP responder supports several optional flags (in addition to supporting an arbitrary number of responder certificates).

* __copy\_nonce__ - (true/false) Sets whether to copy the nonce from request to response (if present)

* __cache\_headers__ - (true/false) Sets whether to set HTTP headers for caching GET responses. Coupled with a reverse proxy you can cache responses for a finite period and vastly speed up the response time of your server (at the cost of response freshness). Nonced requests will not be cached. The performance benefit of caching can vary drastically depending on the mix of clients connecting to the OCSP responder.

* __max\_cache\_age__ - (integer) Sets the maximum age in __seconds__ a response can be cached. At this time r509-ocsp-responder does not support cache invalidation so it is recommended to set this to a low value to reduce the time you may serve stale responses in the event of a revocation.

## Signals
You can send a kill -USR2 signal to any running r509-ocsp-responder process to cause it to reload and print its config to the logs (provided your app server isn't trapping USR2 first).

## Support
You can file bugs on GitHub or join the #r509 channel on irc.freenode.net to ask questions.

## Running Tests
You'll need rspec, rake, and rack-test to run the tests. With these gems in place run ```rake spec```
