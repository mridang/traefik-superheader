This repository includes an example plugin, `demo`, for you to use as a reference for developing your own plugins.

[![Build Status](https://github.com/traefik/plugindemo/workflows/Main/badge.svg?branch=master)](https://github.com/traefik/plugindemo/actions)

The existing plugins can be browsed into the [Plugin Catalog](https://plugins.traefik.io).

# Developing a Traefik plugin

[Traefik](https://traefik.io) plugins are developed using the [Go language](https://golang.org).

A [Traefik](https://traefik.io) middleware plugin is just a [Go package](https://golang.org/ref/spec#Packages) that provides an `http.Handler` to perform specific processing of requests and responses.

Rather than being pre-compiled and linked, however, plugins are executed on the fly by [Yaegi](https://github.com/traefik/yaegi), an embedded Go interpreter.

## Usage

For a plugin to be active for a given Traefik instance, it must be declared in the static configuration.

Plugins are parsed and loaded exclusively during startup, which allows Traefik to check the integrity of the code and catch errors early on.
If an error occurs during loading, the plugin is disabled.

For security reasons, it is not possible to start a new plugin or modify an existing one while Traefik is running.

Once loaded, middleware plugins behave exactly like statically compiled middlewares.
Their instantiation and behavior are driven by the dynamic configuration.

Plugin dependencies must be [vendored](https://golang.org/ref/mod#vendoring) for each plugin.
Vendored packages should be included in the plugin's GitHub repository. ([Go modules](https://blog.golang.org/using-go-modules) are not supported.)

### Configuration

All values are case insensitive.

For each plugin, the Traefik static configuration must define the module name (as is usual for Go packages).

### Example 1: Traefik Configuration Using YAML

```yaml
# Static configuration

providers:
  file:
    filename: traefik.yml

http:
  routers:
    my-router:
      rule: host(`demo.localhost`)
      service: service-foo
      entryPoints:
        - web
      middlewares:
        - superheaders

  services:
    service-foo:
      loadBalancer:
        servers:
          - url: http://127.0.0.1:5000

  middlewares:
    superheaders:
      plugin:
        superheaders:
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
          remove-server-info: on
```

### Example 2: Traefik Configuration Using CLI Args

```bash
traefik \
  --entryPoints.web.address=:80 \
  --providers.file.filename=traefik.yml \
  --experimental.plugins.superheaders.moduleName=github.com/yourusername/traefik-superheaders \
  --experimental.plugins.superheaders.version=v0.1.0 \
  --http.middlewares.superheaders.plugin.superheaders.x-frame-options=DENY \
  --http.middlewares.superheaders.plugin.superheaders.x-dns-prefetch-control=off \
  --http.middlewares.superheaders.plugin.superheaders.x-content-type-options=nosniff \
  --http.middlewares.superheaders.plugin.superheaders.strict-transport-security="max-age=31536000; includeSubDomains" \
  --http.middlewares.superheaders.plugin.superheaders.referrer-policy=no-referrer \
  --http.middlewares.superheaders.plugin.superheaders.x-xss-protection="1; mode=block" \
  --http.middlewares.superheaders.plugin.superheaders.cross-origin-opener-policy=same-origin \
  --http.middlewares.superheaders.plugin.superheaders.cross-origin-embedder-policy=require-corp \
  --http.middlewares.superheaders.plugin.superheaders.cross-origin-resource-policy=same-origin \
  --http.middlewares.superheaders.plugin.superheaders.origin-agent-cluster="?1" \
  --http.middlewares.superheaders.plugin.superheaders.x-permitted-cross-domain-policies=master-only \
  --http.middlewares.superheaders.plugin.superheaders.remove-powered-by=on \
  --http.middlewares.superheaders.plugin.superheaders.remove-server-info=on
```


#### Configuring the X-Frame-Options Header
This header can be configured by the "x-frame-options" header to control whether
a browser should be allowed to render a page in a `<frame>`, `<iframe>`,
`<embed>`, or `<object>`. The valid values with the explanations are as follows:
- `deny`: Prevents any domain from framing the content.
- `sameorigin`: Allows the same domain to frame the content.

For more information, visit: [MDN: X-Frame-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options)

#### Configuring the X-DNS-Prefetch-Control Header
This header can be configured by the "x-dns-prefetch-control" header to control DNS
prefetching. The valid values with the explanations are as follows:
- `off`: Disables DNS prefetching.
- `on`: Enables DNS prefetching.

For more information, visit: [MDN: X-DNS-Prefetch-Control](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-DNS-Prefetch-Control)

#### Configuring the X-Content-Type-Options Header
This header can be configured by the "x-content-type-options" header to tell
the browser to not sniff the MIME type of the content. The valid value is:
- `nosniff`: Prevents browsers from attempting to infer the MIME type.

For more information, visit: [MDN: X-Content-Type-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options)

#### Configuring the Strict-Transport-Security Header
This header can be configured by the "strict-transport-security" header to
enforce secure (HTTPS) connections to the server. The valid value with the
explanation is:
- `max-age=<seconds>; includeSubDomains`: Enforces HTTPS for the specified
  duration and includes all subdomains.

For more information, visit: [MDN: Strict-Transport-Security](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security)

#### Configuring the Referrer-Policy Header
This header can be configured by the "referrer-policy" header to control how
much referrer information should be included with requests. The valid values
with the explanations are as follows:
- `no-referrer`: No referrer information is sent.
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

For more information, visit: [MDN: Referrer-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy)

#### Configuring the X-XSS-Protection Header
This header can be configured by the "x-xss-protection" header to enable or
disable cross-site scripting (XSS) filters built into most modern browsers.
The valid values with the explanations are as follows:
- `1`: Enables the XSS filter.
- `1; mode=block`: Enables the XSS filter and blocks the page if an attack
  is detected.
- `0`: Disables the XSS filter.

For more information, visit: [MDN: X-XSS-Protection](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection)

#### Configuring the Cross-Origin-Opener-Policy Header
This header can be configured by the "cross-origin-opener-policy" header to
control the interaction between the browsing context (window or tab) and other
contexts (e.g., windows or tabs from other origins). The valid values with
the explanations are as follows:
- `unsafe-none`: Allows all interactions with other contexts.
- `same-origin-allow-popups`: Allows same-origin windows to interact with
  the opener, but blocks cross-origin ones.
- `same-origin`: Only allows interactions with the same-origin windows.
- `noopener-allow-popups`: Allows interaction with popups, but blocks other
  contexts.

For more information, visit: [MDN: Cross-Origin-Opener-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy)

#### Configuring the Cross-Origin-Embedder-Policy Header
This header can be configured by the "cross-origin-embedder-policy" header
to control the resources that can be embedded by a document. The valid values
with the explanations are as follows:
- `unsafe-none`: Allows all cross-origin resources to be embedded.
- `require-corp`: Requires cross-origin resources to be explicitly marked
  as permissive.
- `credentialless`: Requires cross-origin resources to allow for credentials
  to be omitted.

For more information, visit: [MDN: Cross-Origin-Embedder-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy)

#### Configuring the Cross-Origin-Resource-Policy Header
This header can be configured by the "cross-origin-resource-policy" header
to control the cross-origin requests that a resource can make. The valid values
with the explanations are as follows:
- `same-origin`: Only allows requests from the same origin.
- `same-site`: Allows requests from the same site.
- `cross-origin`: Allows all cross-origin requests.

For more information, visit: [MDN: Cross-Origin-Resource-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy)

#### Configuring the Origin-Agent-Cluster Header
This header can be configured by the "origin-agent-cluster" header to allow
for isolating resources by user agent. The valid value with the explanation is:
- `?1`: Enables origin agent clustering.

For more information, visit: [MDN: Origin-Agent-Cluster](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Origin-Agent-Cluster)

#### Configuring the X-Permitted-Cross-Domain-Policies Header
This header can be configured by the "x-permitted-cross-domain-policies"
header to control the permissible cross-domain policies. The valid values
with the explanations are as follows:
- `none`: No cross-domain policies are allowed.
- `master-only`: Only the master policy is allowed.
- `by-content-type`: Policies can be defined by content type.
- `by-ftp-filename`: Policies can be defined by FTP filename.
- `all`: All cross-domain policies are allowed.
- `none-this-response`: No policies are allowed for the current response.

For more information, visit: [MDN: X-Permitted-Cross-Domain-Policies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Permitted-Cross-Domain-Policies)

#### Configuring the Remove-Powered-By Header
This header can be configured by the "remove-powered-by" setting to remove
the `X-Powered-By` header. The valid value is:
- `on`: Removes the `X-Powered-By` header.

For more information, visit: [MDN: X-Powered-By](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Powered-By)

#### Configuring the Remove-Server-Info Header
This header can be configured by the "remove-server-info" setting to remove
the `server` header. The valid value is:
- `on`: Removes the `server` header.

For more information, visit: [MDN: Server](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Server)

### Local Mode

Traefik also offers a developer mode that can be used for temporary testing of plugins not hosted on GitHub.
To use a plugin in local mode, the Traefik static configuration must define the module name (as is usual for Go packages) and a path to a [Go workspace](https://golang.org/doc/gopath_code.html#Workspaces), which can be the local GOPATH or any directory.

The plugins must be placed in `./plugins-local` directory,
which should be in the working directory of the process running the Traefik binary.
The source code of the plugin should be organized as follows:

```
./plugins-local/
    └── src
        └── github.com
            └── traefik
                └── plugindemo
                    ├── demo.go
                    ├── demo_test.go
                    ├── go.mod
                    ├── LICENSE
                    ├── Makefile
                    └── readme.md
```

```yaml
# Static configuration

experimental:
  localPlugins:
    example:
      moduleName: github.com/traefik/plugindemo
```

(In the above example, the `plugindemo` plugin will be loaded from the path `./plugins-local/src/github.com/traefik/plugindemo`.)

```yaml
# Dynamic configuration

http:
  routers:
    my-router:
      rule: host(`demo.localhost`)
      service: service-foo
      entryPoints:
        - web
      middlewares:
        - my-plugin

  services:
   service-foo:
      loadBalancer:
        servers:
          - url: http://127.0.0.1:5000

  middlewares:
    my-plugin:
      plugin:
        example:
          headers:
            Foo: Bar
```

## Defining a Plugin

A plugin package must define the following exported Go objects:

- A type `type Config struct { ... }`. The struct fields are arbitrary.
- A function `func CreateConfig() *Config`.
- A function `func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error)`.

```go
// Package example a example plugin.
package example

import (
	"context"
	"net/http"
)

// Config the plugin configuration.
type Config struct {
	// ...
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		// ...
	}
}

// Example a plugin.
type Example struct {
	next     http.Handler
	name     string
	// ...
}

// New created a new plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	// ...
	return &Example{
		// ...
	}, nil
}

func (e *Example) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// ...
	e.next.ServeHTTP(rw, req)
}
```

## Logs

Currently, the only way to send logs to Traefik is to use `os.Stdout.WriteString("...")` or `os.Stderr.WriteString("...")`.

In the future, we will try to provide something better and based on levels.

## Plugins Catalog

Traefik plugins are stored and hosted as public GitHub repositories.

Every 30 minutes, the Plugins Catalog online service polls Github to find plugins and add them to its catalog.

### Prerequisites

To be recognized by Plugins Catalog, your repository must meet the following criteria:

- The `traefik-plugin` topic must be set.
- The `.traefik.yml` manifest must exist, and be filled with valid contents.

If your repository fails to meet either of these prerequisites, Plugins Catalog will not see it.

### Manifest

A manifest is also mandatory, and it should be named `.traefik.yml` and stored at the root of your project.

This YAML file provides Plugins Catalog with information about your plugin, such as a description, a full name, and so on.

Here is an example of a typical `.traefik.yml`file:

```yaml
# The name of your plugin as displayed in the Plugins Catalog web UI.
displayName: Name of your plugin

# For now, `middleware` is the only type available.
type: middleware

# The import path of your plugin.
import: github.com/username/my-plugin

# A brief description of what your plugin is doing.
summary: Description of what my plugin is doing

# Medias associated to the plugin (optional)
iconPath: foo/icon.png
bannerPath: foo/banner.png

# Configuration data for your plugin.
# This is mandatory,
# and Plugins Catalog will try to execute the plugin with the data you provide as part of its startup validity tests.
testData:
  Headers:
    Foo: Bar
```

Properties include:

- `displayName` (required): The name of your plugin as displayed in the Plugins Catalog web UI.
- `type` (required): For now, `middleware` is the only type available.
- `import` (required): The import path of your plugin.
- `summary` (required): A brief description of what your plugin is doing.
- `testData` (required): Configuration data for your plugin. This is mandatory, and Plugins Catalog will try to execute the plugin with the data you provide as part of its startup validity tests.
- `iconPath` (optional): A local path in the repository to the icon of the project.
- `bannerPath` (optional): A local path in the repository to the image that will be used when you will share your plugin page in social medias.

There should also be a `go.mod` file at the root of your project. Plugins Catalog will use this file to validate the name of the project.

### Tags and Dependencies

Plugins Catalog gets your sources from a Go module proxy, so your plugins need to be versioned with a git tag.

Last but not least, if your plugin middleware has Go package dependencies, you need to vendor them and add them to your GitHub repository.

If something goes wrong with the integration of your plugin, Plugins Catalog will create an issue inside your Github repository and will stop trying to add your repo until you close the issue.

## Troubleshooting

If Plugins Catalog fails to recognize your plugin, you will need to make one or more changes to your GitHub repository.

In order for your plugin to be successfully imported by Plugins Catalog, consult this checklist:

- The `traefik-plugin` topic must be set on your repository.
- There must be a `.traefik.yml` file at the root of your project describing your plugin, and it must have a valid `testData` property for testing purposes.
- There must be a valid `go.mod` file at the root of your project.
- Your plugin must be versioned with a git tag.
- If you have package dependencies, they must be vendored and added to your GitHub repository.
