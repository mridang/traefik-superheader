package superheader

import (
	"context"
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
func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	return &Demo{
		next:   next,
		name:   name,
		config: config,
	}, nil
}

func (sh *Demo) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	sh.next.ServeHTTP(rw, req)

	AddSecureHeaders(sh.config, rw, req)

	switch sh.config.RemovePoweredBy {
	case "on":
		stripHeaders(rw, req)
	}
}
