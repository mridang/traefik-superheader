package superheader

type Config struct {
	XFrameOptions                 string `json:"x-frame-options,omitempty"`
	XDnsPrefetchControl           string `json:"x-dns-prefetch-control,omitempty"`
	XContentTypeOptions           string `json:"x-content-type-options,omitempty"`
	StrictTransportSecurity       string `json:"strict-transport-security,omitempty"`
	ReferrerPolicy                string `json:"referrer-policy,omitempty"`
	XXssProtection                string `json:"x-xss-protection,omitempty"`
	CrossOriginOpenerPolicy       string `json:"cross-origin-opener-policy,omitempty"`
	CrossOriginEmbedderPolicy     string `json:"cross-origin-embedder-policy,omitempty"`
	CrossOriginResourcePolicy     string `json:"cross-origin-resource-policy,omitempty"`
	OriginAgentCluster            string `json:"origin-agent-cluster,omitempty"`
	XPermittedCrossDomainPolicies string `json:"x-permitted-cross-domain-policies,omitempty"`
	RemovePoweredBy               string `json:"remove-powered-by,omitempty"`
}

func CreateConfig() *Config {
	return &Config{
		CrossOriginOpenerPolicy:       "unsafe-none",
		CrossOriginResourcePolicy:     "same-origin",
		OriginAgentCluster:            "on",
		ReferrerPolicy:                "off",
		StrictTransportSecurity:       "off",
		XContentTypeOptions:           "on",
		XDnsPrefetchControl:           "on",
		XFrameOptions:                 "SAMEORIGIN",
		XXssProtection:                "on",
		XPermittedCrossDomainPolicies: "none",
		CrossOriginEmbedderPolicy:     "unsafe-none",
		RemovePoweredBy:               "on",
	}
}
