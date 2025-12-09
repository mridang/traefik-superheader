package internal

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

// SetDefaults ensures the default "on" values are applied if fields are empty.
// This replaces the old CreateConfig() function.
func (c *Config) SetDefaults() {
	if c.XFrameOptions == "" {
		c.XFrameOptions = "on"
	}
	if c.XDnsPrefetchControl == "" {
		c.XDnsPrefetchControl = "on"
	}
	if c.XContentTypeOptions == "" {
		c.XContentTypeOptions = "on"
	}
	if c.StrictTransportSecurity == "" {
		c.StrictTransportSecurity = "on"
	}
	if c.ReferrerPolicy == "" {
		c.ReferrerPolicy = "on"
	}
	if c.XXssProtection == "" {
		c.XXssProtection = "on"
	}
	if c.CrossOriginOpenerPolicy == "" {
		c.CrossOriginOpenerPolicy = "on"
	}
	if c.CrossOriginEmbedderPolicy == "" {
		c.CrossOriginEmbedderPolicy = "on"
	}
	if c.CrossOriginResourcePolicy == "" {
		c.CrossOriginResourcePolicy = "on"
	}
	if c.OriginAgentCluster == "" {
		c.OriginAgentCluster = "on"
	}
	if c.XPermittedCrossDomainPolicies == "" {
		c.XPermittedCrossDomainPolicies = "on"
	}
	if c.RemovePoweredBy == "" {
		c.RemovePoweredBy = "on"
	}
}
