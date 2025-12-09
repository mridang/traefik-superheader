package internal

import (
	"strings"

	"github.com/http-wasm/http-wasm-guest-tinygo/handler"
	"github.com/http-wasm/http-wasm-guest-tinygo/handler/api"
)

func LogMessage(headerKey string, headerValue string) {
	handler.Host.Log(api.LogLevelWarn,
		"Warning: Incorrect configuration for header '"+headerKey+
			"'. '"+headerValue+
			"' is not a valid value. See https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/"+headerKey)
}

//nolint:cyclop,funlen,goconst // The function body requires complex validation, so cyclop is suppressed here.
func AddSecureHeaders(config *Config, resp api.Response) {
	h := resp.Headers()

	xf := strings.ToLower(config.XFrameOptions)
	xd := strings.ToLower(config.XDnsPrefetchControl)
	xc := strings.ToLower(config.XContentTypeOptions)
	st := strings.ToLower(config.StrictTransportSecurity)
	rp := strings.ToLower(config.ReferrerPolicy)
	xs := strings.ToLower(config.XXssProtection)
	coop := strings.ToLower(config.CrossOriginOpenerPolicy)
	coep := strings.ToLower(config.CrossOriginEmbedderPolicy)
	corp := strings.ToLower(config.CrossOriginResourcePolicy)
	oac := strings.ToLower(config.OriginAgentCluster)
	xpcdp := strings.ToLower(config.XPermittedCrossDomainPolicies)

	// X-Frame-Options
	switch xf {
	case Enabled:
		h.Set(XFrameOptions, "deny")
	case "deny", "sameorigin":
		h.Set(XFrameOptions, xf)
	case Disabled:
		// skip
	default:
		LogMessage(XFrameOptions, config.XFrameOptions)
	}

	// X-DNS-Prefetch-Control
	switch xd {
	case Enabled, Disabled:
		h.Set(XDnsPrefetchControl, xd)
	default:
		LogMessage(XDnsPrefetchControl, config.XDnsPrefetchControl)
	}

	// X-Content-Type-Options
	switch xc {
	case Enabled:
		h.Set(XContentTypeOptions, "nosniff")
	case Disabled:
		// skip
	default:
		LogMessage(XContentTypeOptions, config.XContentTypeOptions)
	}

	// Strict-Transport-Security
	switch st {
	case Enabled:
		h.Set(StrictTransportSecurity, "max-age=31536000; includesubdomains")
	case Disabled:
		// skip
	default:
		LogMessage(StrictTransportSecurity, config.StrictTransportSecurity)
	}

	// Referrer-Policy
	switch rp {
	case Enabled:
		h.Set(ReferrerPolicy, "no-referrer")
	case
		"no-referrer", "no-referrer-when-downgrade", "origin",
		"origin-when-cross-origin", "same-origin",
		"strict-origin", "strict-origin-when-cross-origin",
		"unsafe-url":
		h.Set(ReferrerPolicy, rp)
	case Disabled:
		// skip
	default:
		LogMessage(ReferrerPolicy, config.ReferrerPolicy)
	}

	// X-XSS-Protection
	switch xs {
	case Enabled:
		h.Set(XXssProtection, "1")
	case "block":
		h.Set(XXssProtection, "1; mode=block")
	case Disabled:
		// skip
	default:
		LogMessage(XXssProtection, config.XXssProtection)
	}

	// COOP
	switch coop {
	case Enabled:
		h.Set(CrossOriginOpenerPolicy, "same-origin")
	case "unsafe-none", "same-origin-allow-popups", "same-origin", "noopener-allow-popups":
		h.Set(CrossOriginOpenerPolicy, coop)
	case Disabled:
	default:
		LogMessage(CrossOriginOpenerPolicy, config.CrossOriginOpenerPolicy)
	}

	// COEP
	switch coep {
	case Enabled:
		h.Set(CrossOriginEmbedderPolicy, "require-corp")
	case "unsafe-none", "require-corp", "credentialless":
		h.Set(CrossOriginEmbedderPolicy, coep)
	case Disabled:
	default:
		LogMessage(CrossOriginEmbedderPolicy, config.CrossOriginEmbedderPolicy)
	}

	// CORP
	switch corp {
	case Enabled:
		h.Set(CrossOriginResourcePolicy, "same-origin")
	case "same-origin", "same-site", "cross-origin":
		h.Set(CrossOriginResourcePolicy, corp)
	case Disabled:
	default:
		LogMessage(CrossOriginResourcePolicy, config.CrossOriginResourcePolicy)
	}

	// Origin-Agent-Cluster
	switch oac {
	case Enabled:
		h.Set(OriginAgentCluster, "?1")
	case Disabled:
	default:
		LogMessage(OriginAgentCluster, config.OriginAgentCluster)
	}

	// X-Permitted-Cross-Domain-Policies
	switch xpcdp {
	case Enabled:
		h.Set(XPermittedCrossDomainPolicies, "none")
	case "none", "master-only", "by-content-type", "by-ftp-filename", "all", "none-this-response":
		h.Set(XPermittedCrossDomainPolicies, xpcdp)
	case Disabled:
	default:
		LogMessage(XPermittedCrossDomainPolicies, config.XPermittedCrossDomainPolicies)
	}
}
