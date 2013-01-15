#r509-ocsp-responder [![Build Status](https://secure.travis-ci.org/reaperhulk/r509-ocsp-responder.png)](http://travis-ci.org/reaperhulk/r509-ocsp-responder)
r509-ocsp-responder is an OCSP responder written using [r509](https://github.com/reaperhulk/r509) and Sinatra to conform to RFC [2560](http://www.ietf.org/rfc/rfc2560.txt) and [5019](http://www.ietf.org/rfc/rfc5019.txt).

##Requirements

r509-ocsp-responder depends on [r509](https://github.com/reaperhulk/r509), [redis](http://redis.io), [r509-validity-redis](https://github.com/sirsean/r509-validity-redis) (or another library that implements R509::Validity), [sinatra](http://sinatrarb.com), [r509-ocsp-stats](https://github.com/sirsean/r509-ocsp-stats), and [dependo](https://github.com/sirsean/dependo). These must be installed as gems.

##Basic Usage

1. Build the gem. If you have cloned the repo you can build the gem with ```rake gem:build```. You will need
2. Install the gem. ```rake gem:install```
3. Set up your config.ru and config.yaml. At this time you'll need to copy the config.ru from the gem install to another dir with your config.yaml. You should also copy (and modify) the config.yaml.example file from the gem. You'll need to alter the config.ru's require line from ```require './lib/r509/ocsp/responder/server'``` to ```require 'r509/ocsp/responder/server'``` if you have it installed as a gem.

Once you've done that you can set up your rack server. The example below is an example yaml config for thin. You will want to have as many servers as you have cores.

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

##Options
This OCSP responder supports several optional flags (in addition to supporting an arbitrary number of responder certificates).

* __copy\_nonce__ - (true/false) Sets whether to copy the nonce from request to response (if present)

* __cache\_headers__ - (true/false) Sets whether to set HTTP headers for caching GET responses. Coupled with a reverse proxy you can cache responses for a finite period and vastly speed up the response time of your server (at the cost of response freshness). Nonced requests will not be cached. The performance benefit of caching can vary drastically depending on the mix of clients connecting to the OCSP responder.

* __max\_cache\_age__ - (integer) Sets the maximum age in __seconds__ a response can be cached. At this time r509-ocsp-responder does not support cache invalidation so it is recommended to set this to a low value to reduce the time you may serve stale responses in the event of a revocation.

See the config.yaml.example for an example configuration.

##Signals
You can send a kill -USR2 signal to any running r509-ocsp-responder process to cause it to reload and print its config to the logs (provided your app server isn't trapping USR2 first).

##Running Tests
You'll need rspec, rake, and rack-test to run the tests. With these gems in place run ```rake spec```

##Future Ideas
* Devise a mechanism for doing automated OCSP delegate certificate renewal
