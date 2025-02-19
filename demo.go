package superheader

import (
	"context"
	"log"
	"net/http"
)

type Config struct {
	XFrameOptions                 string `json:"x-frame-options,omitempty"`
	XDNSPrefetchControl           string `json:"x-dns-prefetch-control,omitempty"`
	XContentTypeOptions           string `json:"x-content-type-options,omitempty"`
	StrictTransportSecurity       string `json:"strict-transport-security,omitempty"`
	ReferrerPolicy                string `json:"referrer-policy,omitempty"`
	XXSSProtection                string `json:"x-xss-protection,omitempty"`
	CrossOriginOpenerPolicy       string `json:"cross-origin-opener-policy,omitempty"`
	CrossOriginEmbedderPolicy     string `json:"cross-origin-embedder-policy,omitempty"`
	CrossOriginResourcePolicy     string `json:"cross-origin-resource-policy,omitempty"`
	OriginAgentCluster            string `json:"origin-agent-cluster,omitempty"`
	XPermittedCrossDomainPolicies string `json:"x-permitted-cross-domain-policies,omitempty"`
	RemovePoweredBy               string `json:"remove-powered-by,omitempty"`
}

func CreateConfig() *Config {
	return &Config{
		//CSP
		CrossOriginOpenerPolicy:   "unsafe-none",
		CrossOriginResourcePolicy: "same-origin",
		OriginAgentCluster:        "on",
		ReferrerPolicy:            "off",
		StrictTransportSecurity:   "off",
		XContentTypeOptions:       "on",
		XDNSPrefetchControl:       "on",
		//XDownload
		XFrameOptions: "SAMEORIGIN",
		//XPermCross
		XXSSProtection: "on",

		XPermittedCrossDomainPolicies: "none",
		CrossOriginEmbedderPolicy:     "unsafe-none",
		RemovePoweredBy:               "on",
	}
}

type Demo struct {
	next    http.Handler
	headers map[string]string
	name    string
	config  *Config
}

// New created a new Demo plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	return &Demo{
		next:   next,
		name:   name,
		config: config,
	}, nil
}

func (sh *Demo) LogMessage(headerKey string, headerValue string) {
	log.Printf("Warning: Incorrect configuration for header '%s'. '%s' is not a valid value. See https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/%s", headerKey, headerValue, headerKey)
}

func (sh *Demo) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	switch sh.config.XFrameOptions {
	case
		"DENY",
		"SAMEORIGIN":
		rw.Header().Set("X-Frame-Options", sh.config.XFrameOptions)
	default:
		sh.LogMessage("X-Frame-Options", sh.config.XFrameOptions)
	}

	// X-DNS-Prefetch-Control
	switch sh.config.XDNSPrefetchControl {
	case
		"on",
		"off":
		rw.Header().Set("X-DNS-Prefetch-Control", sh.config.XDNSPrefetchControl)
	default:
		sh.LogMessage("X-DNS-Prefetch-Control", sh.config.XDNSPrefetchControl)
	}

	// X-Content-Type-Options
	switch sh.config.XContentTypeOptions {
	case
		"on":
		rw.Header().Set("X-Content-Type-Options", "nosniff")
	case
		"off":
		// Skip setting the header
	default:
		sh.LogMessage("X-Content-Type-Options", sh.config.XDNSPrefetchControl)
	}

	// Strict-Transport-Security
	switch sh.config.StrictTransportSecurity {
	case
		"on":
		rw.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	case
		"off":
		// Skip setting the header
	default:
		sh.LogMessage("Strict-Transport-Security", sh.config.XDNSPrefetchControl)
	}

	// Referrer-Policy
	switch sh.config.ReferrerPolicy {
	case
		"no-referrer",
		"no-referrer-when-downgrade",
		"origin",
		"origin-when-cross-origin",
		"same-origin",
		"strict-origin",
		"strict-origin-when-cross-origin",
		"unsafe-url":
		rw.Header().Set("Referrer-Policy", sh.config.ReferrerPolicy)
	case "off":
		// Skip setting the header
	default:
		sh.LogMessage("Referrer-Policy", sh.config.XDNSPrefetchControl)
	}

	// X-XSS-Protection
	switch sh.config.XXSSProtection {
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
		sh.LogMessage("X-XSS-Protection", sh.config.XDNSPrefetchControl)
	}

	// Cross-Origin-Opener-Policy
	switch sh.config.CrossOriginOpenerPolicy {
	case
		"unsafe-none",
		"same-origin-allow-popups",
		"same-origin",
		"noopener-allow-popups":
		rw.Header().Set("Cross-Origin-Opener-Policy", sh.config.CrossOriginOpenerPolicy)
	case "off":
		// Skip setting the header
	default:
		sh.LogMessage("Cross-Origin-Opener-Policy", sh.config.XDNSPrefetchControl)
	}

	// Cross-Origin-Embedder-Policy
	switch sh.config.CrossOriginEmbedderPolicy {
	case
		"unsafe-none",
		"require-corp",
		"credentialless":
		rw.Header().Set("Cross-Origin-Embedder-Policy", sh.config.CrossOriginEmbedderPolicy)
	case "off":
		// Skip setting the header
	default:
		sh.LogMessage("Cross-Origin-Embedder-Policy", sh.config.CrossOriginEmbedderPolicy)
	}

	switch sh.config.CrossOriginResourcePolicy {
	case
		"same-origin",
		"same-site",
		"cross-origin":
		rw.Header().Set("Cross-Origin-Resource-Policy", sh.config.CrossOriginResourcePolicy)
	case "off":
		// Skip setting the header
	default:
		sh.LogMessage("Cross-Origin-Resource-Policy", sh.config.CrossOriginResourcePolicy)
	}

	switch sh.config.OriginAgentCluster {
	case
		"on":
		rw.Header().Set("Origin-Agent-Cluster", "?1")
	case "off":
		// Skip setting the header
	default:
		sh.LogMessage("Origin-Agent-Cluster", sh.config.OriginAgentCluster)
	}

	switch sh.config.XPermittedCrossDomainPolicies {
	case
		"none",
		"master-only",
		"by-content-type",
		"by-ftp-filename",
		"all",
		"none-this-response":
		rw.Header().Set("X-Permitted-Cross-Domain-Policies", sh.config.XPermittedCrossDomainPolicies)
	case "off":
		// Skip setting the header
	default:
		sh.LogMessage("X-Permitted-Cross-Domain-Policies", sh.config.XPermittedCrossDomainPolicies)
	}

	sh.next.ServeHTTP(rw, req)

	switch sh.config.RemovePoweredBy {
	case "on":
		stripHeaders(rw, req)
	}
}
