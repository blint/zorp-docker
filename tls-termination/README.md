# Supported tags and respective `Dockerfile` links

* 6.0.8 ([Dockerfile](https://github.com/Balasys/zorp-docker/blob/6.0.8/tls-termination/Dockerfile))
* 6.0.9 ([Dockerfile](https://github.com/Balasys/zorp-docker/blob/6.0.9/tls-termination/Dockerfile))
* 6.0.10 ([Dockerfile](https://github.com/Balasys/zorp-docker/blob/6.0.10/tls-termination/Dockerfile))
* latest ([Dockerfile](https://github.com/Balasys/zorp-docker/blob/master/tls-termination/Dockerfile))

# What is Zorp GPL?

Zorp GPL is a new generation proxy firewall suite. It uses application level proxies, it is modular and component based,
it uses a script language to describe policy decisions, it makes it possible to monitor encrypted traffic, it lets you
override client actions.

For more information about Zorp GPL, read the [tutorial](http://zorp-gpl-tutorial.readthedocs.io/). If you are
interested follow Zorp GPL [GitHub site](https://balasys.github.io/zorp).

# How to use this image

## Start a `zorpgpl` server instance

Starting a Zorp GPL [TLS termination proxy](https://en.wikipedia.org/wiki/TLS_termination_proxy) instance is simple:

    $ docker run \
      --name tls-terminator-zorpgpl \
      --volume certs:/etc/zorp/certs \
      --publish 443:443 --publish 80:80 \
      --env "ZORP_TLS_TERMINATION_SERVICE_ENABLED=https" \
      --link www \
      balasys/zorpgpl-tls-termination

* `balasys/zorpgpl-tls-termination` is the name you want to assign to your container,
* `certs` is the location of the public key chain (`fullchain.pem`) and private key (`privkey.pem`) files used to encrypt the
  connections with
* `www` is the name of the container to pass plain HTTP connections to

This image exposes the standard service ports (443 in case of HTTPS) and also connects to the standard service port 80
in case of HTTP) so container linking makes the non-encrypted service instances available from proxy container. Start
your proxy container like this in order to link it to the HTTP service container:


### Start with Let's Encrypt certificate

If you have Let's Encrypt certficate by default the necessary files are installed to `/etc/letsencrypt/archive/your.host.name` 
and linked from `/etc/letsencrypt/live/your.host.name` so either of them should be shared with the container.

    $ docker run \
      --name tls-terminator-zorpgpl \
      --volume certs:/etc/zorp/certs \
      --volume /etc/letsencrypt/live/your.host.name:/etc/zorp/certs \
      --volume /etc/letsencrypt/archive/your.host.name:/etc/archive/your.host.name \
      --publish 443:443 --publish 80:80 \
      --env "ZORP_TLS_TERMINATION_SERVICE_ENABLED=https" \
      --link www \
      balasys/zorpgpl-tls-termination

## Environment Variables

### `ZORP_TLS_TERMINATION_SERVICE_ENABLED`

This variable is mandatory and specifies the space separated list of services that will be enabled for TLS termination. Now the only possible value is https.
