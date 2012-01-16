#r509-ocsp-responder
r509-ocsp-responder is an OCSP responder written using [r509](https://github.com/reaperhulk/r509) and Sinatra to conform to RFC 2560 and 5019.

##Requirements

r509-ocsp-responder depends on r509, redis, r509-validity-redis, sinatra, and dependo.

##Basic Usage

Install the gem and set up your config.ru and config.yaml. At this time you'll need to copy the config.ru from the gem install to another dir with your config.yaml. You should also ccopy (and modify) the config.yaml.example file from the gem.

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
    listen       80;
    server_name  ocsp.r509.org;

    location / {
        proxy_pass http://thin_ocsp_responder;
        proxy_cache ocsp;
        proxy_cache_use_stale updating;
    }
}
```

##Options
This OCSP responder supports several optional flags (in addition to supporting an arbitrary number of responder certificates).

* copy\_nonce - (true/false) Sets whether to copy the nonce from request to response (if present)

* cache\_headers - (true/false) Sets whether to set HTTP headers for caching GET responses. Coupled with a reverse proxy you can cache responses for a finite period and vastly speed up the response time of your server (at the cost of response freshness)

* max\_cache\_age - (integer) Sets the maximum age in __seconds__ a response can be cached. At this time r509-ocsp-responder does not support cache invalidation so it is recommended to set this to a low value to reduce the time you may serve stale responses in the event of a revocation.

See the config.yaml.example for an example configuration. (Note: at this time the example config does not use ocsp_cert and ca_cert together)

##Running Tests
You'll need rspec, rake, and rack-test to run the tests. With these gems in place run ```rake spec```
