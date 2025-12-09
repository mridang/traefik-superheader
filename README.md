# Superheader - OWASP Headers for Traefik

**Superheader** is a plugin for Traefik that adds the necessary headers
to responses to help secure web applications.

The headers set are adhere to the recommendations of the OWASP Secure Headers
Project https://owasp.org/www-project-secure-headers/

##### Why ?

While there is third-party middleware for almost all frameworks e.g. Helmet for
Express (Node) and Spring Security for Spring (Java), using this
middleware make it simple to secure all your web applications.

## Usage

For a plugin to be active for a given Traefik instance, it must be declared in
the static configuration.

```yaml
experimental:
  plugins:
    superheader:
      moduleName: "github.com/mridang/traefik-superheader"
      version: "v1.0.0"
```

##### Example 1: Traefik Configuration Using YAML

```yaml
http:
  routers:
    my-router:
      rule: "Host(`example.com`)"
      entryPoints:
        - web
      middlewares:
        - my-middleware  # Apply the middleware to the router

middlewares:
  superheader:
    plugin:
      superheader:
        x-frame-options: DENY
        x-dns-prefetch-control: off
        x-content-type-options: nosniff
        strict-transport-security: max-age=31536000; includeSubDomains
        referrer-policy: no-referrer
        x-xss-protection: 1; mode=block
        cross-origin-opener-policy: same-origin
        cross-origin-embedder-policy: require-corp
        cross-origin-resource-policy: same-origin
        origin-agent-cluster: ?1
        x-permitted-cross-domain-policies: master-only
        remove-powered-by: on
```

##### Example 2: Traefik Configuration Using CLI Args

This example shows you how to load and configure the plugin using the command-line
arguments.

```shell
traefik \
  --entryPoints.web.address=:80 \
  --providers.file.filename=traefik.yml \
  --experimental.plugins.superheader.moduleName=github.com/mridang/traefik-superheader \
  --experimental.plugins.superheader.version=v0.1.0 \
  --http.middlewares.superheader.plugin.superheader.x-frame-options=DENY \
  --http.middlewares.superheader.plugin.superheader.x-dns-prefetch-control=off \
  --http.middlewares.superheader.plugin.superheader.x-content-type-options=nosniff \
  --http.middlewares.superheader.plugin.superheader.strict-transport-security="max-age=31536000; includeSubDomains" \
  --http.middlewares.superheader.plugin.superheader.referrer-policy=no-referrer \
  --http.middlewares.superheader.plugin.superheader.x-xss-protection="1; mode=block" \
  --http.middlewares.superheader.plugin.superheader.cross-origin-opener-policy=same-origin \
  --http.middlewares.superheader.plugin.superheader.cross-origin-embedder-policy=require-corp \
  --http.middlewares.superheader.plugin.superheader.cross-origin-resource-policy=same-origin \
  --http.middlewares.superheader.plugin.superheader.origin-agent-cluster="?1" \
  --http.middlewares.superheader.plugin.superheader.x-permitted-cross-domain-policies=master-only \
  --http.middlewares.superheader.plugin.superheader.remove-powered-by=on
```

##### Example 3: Usage in Docker Compose

```yaml
services:
  traefik:
    image: traefik:3.3.3
    ports:
      - "7080:80"
    command:
      - --api.dashboard=false
      - --api.insecure=false
      - --log.level=DEBUG
      - --experimental.plugins.superheader.moduleName=github.com/mridang/traefik-superheader
      - --providers.docker=true
      - --entrypoints.web.address=:80
    volumes:
      - '/var/run/docker.sock:/var/run/docker.sock'
    labels:
      - traefik.enable=true
      - traefik.http.services.traefik.loadbalancer.server.port=8080

  # A sample service that uses the middleware with the defaults
  foo:
    image: traefik/whoami
    labels:
      - traefik.enable=true
      - traefik.http.routers.foo.rule=PathPrefix(`/foo`)
      - traefik.http.routers.foo.middlewares=securefoo
      - traefik.http.middlewares.securefoo.plugin.superheader=true
      - traefik.http.routers.foo.entrypoints=web

  # A sample service that uses the middleware with custom options
  bar:
    image: traefik/whoami
    labels:
      - traefik.enable=true
      - traefik.http.routers.bar.rule=PathPrefix(`/bar`)
      - traefik.http.routers.bar.middlewares=securebar
      - traefik.http.middlewares.securebar.plugin.superheader.x-frame-options="DENY"
      - traefik.http.routers.bar.entrypoints=web

  # A sample service that does not use the middleware at all
  baz:
    image: traefik/whoami
    labels:
      - traefik.enable=true
      - traefik.http.routers.baz.rule=PathPrefix(`/baz`)
      - traefik.http.routers.baz.entrypoints=web
```

Once the middleware has been installed, you can test the security of your web
application using the test suite on MDN https://observatory.mozilla.org/

### Options

The middleware exposes a few options to allow customising the behaviour. To make
it harder to misconfigure the plugin all the keys and values are lowercased. All
the values are case-insensitive.

#### Configuring the X-Frame-Options Header

This header can be configured by the "x-frame-options" header to control whether
a browser should be allowed to render a page in a `<frame>`, `<iframe>`,
`<embed>`, or `<object>`.

The valid values are as follows:

- `deny`: Prevents any domain from framing the content. (Default)
- `sameorigin`: Allows the same domain to frame the content.

For more information,
visit: [MDN: X-Frame-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options)

#### Configuring the X-DNS-Prefetch-Control Header

This header can be configured by the "x-dns-prefetch-control" header to control DNS
prefetching.

The valid values are as follows:

- `on`: Enables DNS prefetching. (Default)
- `off`: Disables the setting of the header

For more information,
visit: [MDN: X-DNS-Prefetch-Control](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-DNS-Prefetch-Control)

#### Configuring the X-Content-Type-Options Header

This header can be configured by the "x-content-type-options" header to tell
the browser to not sniff the MIME type of the content.

The valid values are as follows:

- `on`: Prevents browsers from attempting to infer the MIME type. (Default)
- `off`: Disables the setting of the header

For more information,
visit: [MDN: X-Content-Type-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options)

#### Configuring the Strict-Transport-Security Header

This header can be configured by the "strict-transport-security" header to
enforce secure (HTTPS) connections to the server.

The valid values are as follows:

- `on`: Enforces HTTPS for the specified duration and includes all subdomains. (Default)
- `off`: Disables the setting of the header

For more information,
visit: [MDN: Strict-Transport-Security](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security)

#### Configuring the Referrer-Policy Header

This header can be configured by the "referrer-policy" header to control how
much referrer information should be included with requests.

The valid values are as follows:

- `on` | `no-referrer`: No referrer information is sent. (Default)
- `no-referrer-when-downgrade`: Referrer is sent for same-origin requests,
  but not for cross-origin requests to HTTP.
- `origin`: Only the origin is sent as the referrer.
- `origin-when-cross-origin`: Sends the full URL as referrer for same-origin
  requests and only the origin for cross-origin.
- `same-origin`: Sends the full URL as referrer only for same-origin requests.
- `strict-origin`: Only the origin is sent as referrer for same-origin
  requests.
- `strict-origin-when-cross-origin`: Sends the origin as referrer for
  same-origin requests, and the origin for cross-origin requests.
- `unsafe-url`: Always sends the full URL as referrer.
- `off`: Disables the setting of the header

For more information,
visit: [MDN: Referrer-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy)

#### Configuring the X-XSS-Protection Header

This header can be configured by the "x-xss-protection" header to enable or
disable cross-site scripting (XSS) filters built into most modern browsers.

The valid values are as follows:

- `on`: Enables the XSS filter. (Default)
- `block`: Enables the XSS filter and blocks the page if an attack
  is detected.
- `off`: Disables the XSS filter.

For more information,
visit: [MDN: X-XSS-Protection](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection)

#### Configuring the Cross-Origin-Opener-Policy Header

This header can be configured by the "cross-origin-opener-policy" header to
control the interaction between the browsing context (window or tab) and other
contexts (e.g., windows or tabs from other origins).

The valid values are as follows:

- `on` | `same-origin`: Only allows interactions with the same-origin windows.
- `unsafe-none`: Allows all interactions with other contexts.
- `same-origin-allow-popups`: Allows same-origin windows to interact with
  the opener, but blocks cross-origin ones.
- `noopener-allow-popups`: Allows interaction with popups, but blocks other
  contexts.
- `off`: Disables the setting of the header

For more information,
visit: [MDN: Cross-Origin-Opener-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy)

#### Configuring the Cross-Origin-Embedder-Policy Header

This header can be configured by the "cross-origin-embedder-policy" header
to control the resources that can be embedded by a document.

The valid values are as follows:

- `on` | `require-corp`: Requires cross-origin resources to be explicitly marked
  as permissive. (Default)
- `unsafe-none`: Allows all cross-origin resources to be embedded.
- `credentialless`: Requires cross-origin resources to allow for credentials
  to be omitted.
- `off`: Disables the setting of the header

For more information,
visit: [MDN: Cross-Origin-Embedder-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy)

#### Configuring the Cross-Origin-Resource-Policy Header

This header can be configured by the "cross-origin-resource-policy" header
to control the cross-origin requests that a resource can make.

The valid values are as follows:

- `on` | `same-origin`: Only allows requests from the same origin. (Default)
- `same-site`: Allows requests from the same site.
- `cross-origin`: Allows all cross-origin requests.
- `off`: Disables the setting of the header

For more information,
visit: [MDN: Cross-Origin-Resource-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy)

#### Configuring the Origin-Agent-Cluster Header

This header can be configured by the "origin-agent-cluster" header to allow
for isolating resources by user agent.

The valid values are as follows:

- `on`: Enables origin agent clustering.
- `off`: Disables the setting of the header

For more information,
visit: [MDN: Origin-Agent-Cluster](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Origin-Agent-Cluster)

#### Configuring the X-Permitted-Cross-Domain-Policies Header

This header can be configured by the "x-permitted-cross-domain-policies"
header to control the permissible cross-domain policies.

The valid values are as follows:

- `none`: No cross-domain policies are allowed.
- `master-only`: Only the master policy is allowed.
- `by-content-type`: Policies can be defined by content type.
- `by-ftp-filename`: Policies can be defined by FTP filename.
- `all`: All cross-domain policies are allowed.
- `none-this-response`: No policies are allowed for the current response.
- `off`: Disables the setting of the header

For more information,
visit: [MDN: X-Permitted-Cross-Domain-Policies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Permitted-Cross-Domain-Policies)

#### Configuring the removal of headers

The OWASP guidelines recommend the removal of certain headers to prevent
information disclosure. This feature can be toggled.

The valid values are as follows:

- `on`: Removes the sensitive headers.
- `off`: Disabled the removal of headers

For more information,
visit: [OWASP: Remove Headers](https://owasp.org/www-project-secure-headers/ci/headers_remove.json)

## Caveats

None.

## Contributing

Contributions are welcome! If you find a bug or have suggestions for improvement,
please open an issue or submit a pull request.

## License

Apache License 2.0 © 2024 Mridang Agarwalla
