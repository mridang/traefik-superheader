package superheader

import (
	"log"
	"net/http"
)

func LogMessage(headerKey string, headerValue string) {
	//nolint:lll // linter rule suppression
	log.Printf("Warning: Incorrect configuration for header '%s'. '%s' is not a valid value. See https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/%s", headerKey, headerValue, headerKey)
}

//nolint:cyclop,funlen // Suppressing cyclomatic complexity warning
func AddSecureHeaders(config *Config, rw http.ResponseWriter) {
	switch config.XFrameOptions {
	case
		"DENY",
		"SAMEORIGIN":
		rw.Header().Set(XFrameOptions, config.XFrameOptions)
	default:
		LogMessage(XFrameOptions, config.XFrameOptions)
	}

	// X-DNS-Prefetch-Control
	switch config.XDnsPrefetchControl {
	case
		Enabled,
		Disabled:
		rw.Header().Set(XDnsPrefetchControl, config.XDnsPrefetchControl)
	default:
		LogMessage(XDnsPrefetchControl, config.XDnsPrefetchControl)
	}

	// X-Content-Type-Options
	switch config.XContentTypeOptions {
	case
		Enabled:
		rw.Header().Set(XContentTypeOptions, "nosniff")
	case
		Disabled:
		// Skip setting the header
	default:
		LogMessage(XContentTypeOptions, config.XContentTypeOptions)
	}

	// Strict-Transport-Security
	switch config.StrictTransportSecurity {
	case
		Enabled:
		rw.Header().Set(StrictTransportSecurity, "max-age=31536000; includeSubDomains")
	case
		Disabled:
		// Skip setting the header
	default:
		LogMessage(StrictTransportSecurity, config.StrictTransportSecurity)
	}

	// Referrer-Policy
	switch config.ReferrerPolicy {
	case
		"no-referrer",
		"no-referrer-when-downgrade",
		"origin",
		"origin-when-cross-origin",
		"same-origin", //nolint:goconst // linter rule suppression
		"strict-origin",
		"strict-origin-when-cross-origin",
		"unsafe-url":
		rw.Header().Set(ReferrerPolicy, config.ReferrerPolicy)
	case
		Disabled:
		// Skip setting the header
	default:
		LogMessage(ReferrerPolicy, config.ReferrerPolicy)
	}

	// X-XSS-Protection
	switch config.XXssProtection {
	case
		Enabled:
		rw.Header().Set(XXssProtection, "1")
	case
		"block":
		rw.Header().Set(XXssProtection, "1; mode=block")
	case
		Disabled:
		rw.Header().Set(XXssProtection, "0")
	default:
		LogMessage(XXssProtection, config.XXssProtection)
	}

	// Cross-Origin-Opener-Policy
	switch config.CrossOriginOpenerPolicy {
	case
		"unsafe-none",
		"same-origin-allow-popups",
		"same-origin",
		"noopener-allow-popups":
		rw.Header().Set(CrossOriginOpenerPolicy, config.CrossOriginOpenerPolicy)
	case
		Disabled:
		// Skip setting the header
	default:
		LogMessage(CrossOriginOpenerPolicy, config.CrossOriginOpenerPolicy)
	}

	// Cross-Origin-Embedder-Policy
	switch config.CrossOriginEmbedderPolicy {
	case
		"unsafe-none",
		"require-corp",
		"credentialless":
		rw.Header().Set(CrossOriginEmbedderPolicy, config.CrossOriginEmbedderPolicy)
	case
		Disabled:
		// Skip setting the header
	default:
		LogMessage(CrossOriginEmbedderPolicy, config.CrossOriginEmbedderPolicy)
	}

	switch config.CrossOriginResourcePolicy {
	case
		"same-origin",
		"same-site",
		"cross-origin":
		rw.Header().Set(CrossOriginResourcePolicy, config.CrossOriginResourcePolicy)
	case
		Disabled:
		// Skip setting the header
	default:
		LogMessage(CrossOriginResourcePolicy, config.CrossOriginResourcePolicy)
	}

	switch config.OriginAgentCluster {
	case
		Enabled:
		rw.Header().Set(OriginAgentCluster, "?1")
	case
		Disabled:
		// Skip setting the header
	default:
		LogMessage(OriginAgentCluster, config.OriginAgentCluster)
	}

	switch config.XPermittedCrossDomainPolicies {
	case
		"none",
		"master-only",
		"by-content-type",
		"by-ftp-filename",
		"all",
		"none-this-response":
		rw.Header().Set(XPermittedCrossDomainPolicies, config.XPermittedCrossDomainPolicies)
	case
		Disabled:
		// Skip setting the header
	default:
		LogMessage(XPermittedCrossDomainPolicies, config.XPermittedCrossDomainPolicies)
	}
}
