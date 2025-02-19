package superheader

import (
	"log"
	"net/http"
)

func LogMessage(headerKey string, headerValue string) {
	log.Printf("Warning: Incorrect configuration for header '%s'. '%s' is not a valid value. See https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/%s", headerKey, headerValue, headerKey)
}

func AddSecureHeaders(config *Config, rw http.ResponseWriter) {
	switch config.XFrameOptions {
	case
		"DENY",
		"SAMEORIGIN":
		rw.Header().Set("X-Frame-Options", config.XFrameOptions)
	default:
		LogMessage("X-Frame-Options", config.XFrameOptions)
	}

	// X-DNS-Prefetch-Control
	switch config.XDnsPrefetchControl {
	case
		"on",
		"off":
		rw.Header().Set("X-DNS-Prefetch-Control", config.XDnsPrefetchControl)
	default:
		LogMessage("X-DNS-Prefetch-Control", config.XDnsPrefetchControl)
	}

	// X-Content-Type-Options
	switch config.XContentTypeOptions {
	case
		"on":
		rw.Header().Set("X-Content-Type-Options", "nosniff")
	case
		"off":
		// Skip setting the header
	default:
		LogMessage("X-Content-Type-Options", config.XContentTypeOptions)
	}

	// Strict-Transport-Security
	switch config.StrictTransportSecurity {
	case
		"on":
		rw.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	case
		"off":
		// Skip setting the header
	default:
		LogMessage("Strict-Transport-Security", config.StrictTransportSecurity)
	}

	// Referrer-Policy
	switch config.ReferrerPolicy {
	case
		"no-referrer",
		"no-referrer-when-downgrade",
		"origin",
		"origin-when-cross-origin",
		"same-origin",
		"strict-origin",
		"strict-origin-when-cross-origin",
		"unsafe-url":
		rw.Header().Set("Referrer-Policy", config.ReferrerPolicy)
	case "off":
		// Skip setting the header
	default:
		LogMessage("Referrer-Policy", config.ReferrerPolicy)
	}

	// X-XSS-Protection
	switch config.XXssProtection {
	case
		"on":
		rw.Header().Set("X-XSS-Protection", "1")
	case
		"block":
		rw.Header().Set("X-XSS-Protection", "1; mode=block")
	case
		"off":
		rw.Header().Set("X-XSS-Protection", "0")
	default:
		LogMessage("X-XSS-Protection", config.XXssProtection)
	}

	// Cross-Origin-Opener-Policy
	switch config.CrossOriginOpenerPolicy {
	case
		"unsafe-none",
		"same-origin-allow-popups",
		"same-origin",
		"noopener-allow-popups":
		rw.Header().Set("Cross-Origin-Opener-Policy", config.CrossOriginOpenerPolicy)
	case "off":
		// Skip setting the header
	default:
		LogMessage("Cross-Origin-Opener-Policy", config.CrossOriginOpenerPolicy)
	}

	// Cross-Origin-Embedder-Policy
	switch config.CrossOriginEmbedderPolicy {
	case
		"unsafe-none",
		"require-corp",
		"credentialless":
		rw.Header().Set("Cross-Origin-Embedder-Policy", config.CrossOriginEmbedderPolicy)
	case "off":
		// Skip setting the header
	default:
		LogMessage("Cross-Origin-Embedder-Policy", config.CrossOriginEmbedderPolicy)
	}

	switch config.CrossOriginResourcePolicy {
	case
		"same-origin",
		"same-site",
		"cross-origin":
		rw.Header().Set("Cross-Origin-Resource-Policy", config.CrossOriginResourcePolicy)
	case "off":
		// Skip setting the header
	default:
		LogMessage("Cross-Origin-Resource-Policy", config.CrossOriginResourcePolicy)
	}

	switch config.OriginAgentCluster {
	case
		"on":
		rw.Header().Set("Origin-Agent-Cluster", "?1")
	case "off":
		// Skip setting the header
	default:
		LogMessage("Origin-Agent-Cluster", config.OriginAgentCluster)
	}

	switch config.XPermittedCrossDomainPolicies {
	case
		"none",
		"master-only",
		"by-content-type",
		"by-ftp-filename",
		"all",
		"none-this-response":
		rw.Header().Set("X-Permitted-Cross-Domain-Policies", config.XPermittedCrossDomainPolicies)
	case "off":
		// Skip setting the header
	default:
		LogMessage("X-Permitted-Cross-Domain-Policies", config.XPermittedCrossDomainPolicies)
	}
}
