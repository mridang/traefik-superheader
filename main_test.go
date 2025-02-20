package superheader_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mridang/superheader/internal"

	"github.com/mridang/superheader"
	"github.com/stretchr/testify/assert"
)

// createHandler creates the handler with the given configuration.
func createHandler(config *internal.Config) (http.Handler, error) {
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "Go")
		w.Header().Set("X-Powered-By", "Go")
		w.WriteHeader(http.StatusOK)
	})

	return superheader.New(context.Background(), mockHandler, config, "test")
}

// assertResponseHeader checks if the response header satisfies the provided matcher condition.
func assertResponseHeader(t *testing.T, headerKey string, headerVal interface{}, configFn func(*internal.Config)) {
	config := internal.CreateConfig()
	configFn(config)

	handler, err := createHandler(config)
	if err != nil {
		t.Fatalf("Failed to create handler: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "https://example.com", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	actualHeader := rec.Header().Get(headerKey)

	switch v := headerVal.(type) {
	case string:
		assert.Equal(t, v, actualHeader, "Header value does not match")
	case nil:
		assert.Empty(t, actualHeader, "Header should be removed")
	default:
		t.Errorf("Unsupported expected value type: %T", v)
	}
}

func TestXFrameOptions(t *testing.T) {
	// Test "DENY"
	assertResponseHeader(t, "X-Frame-Options", "DENY",
		func(config *internal.Config) {
			config.XFrameOptions = "DENY"
		})

	// Test "SAMEORIGIN"
	assertResponseHeader(t, "X-Frame-Options", "SAMEORIGIN",
		func(config *internal.Config) {
			config.XFrameOptions = "SAMEORIGIN"
		})

	// Test invalid value (header should not be set)
	assertResponseHeader(t, "X-Frame-Options", nil,
		func(config *internal.Config) {
			config.XFrameOptions = "invalid"
		})
}

func TestXDNSPrefetchControl(t *testing.T) {
	// Test "on"
	assertResponseHeader(t, "X-DNS-Prefetch-Control", "on",
		func(config *internal.Config) {
			config.XDnsPrefetchControl = "on"
		})

	// Test "off"
	assertResponseHeader(t, "X-DNS-Prefetch-Control", "off",
		func(config *internal.Config) {
			config.XDnsPrefetchControl = "off"
		})

	// Test invalid value (header should not be set)
	assertResponseHeader(t, "X-DNS-Prefetch-Control", nil,
		func(config *internal.Config) {
			config.XDnsPrefetchControl = "invalid"
		})
}

func TestXContentTypeOptions(t *testing.T) {
	// Test "on"
	assertResponseHeader(t, "X-Content-Type-Options", "nosniff",
		func(config *internal.Config) {
			config.XContentTypeOptions = "on"
		})

	// Test "off" (header should not be set)
	assertResponseHeader(t, "X-Content-Type-Options", nil,
		func(config *internal.Config) {
			config.XContentTypeOptions = "off"
		})

	// Test invalid value (header should not be set)
	assertResponseHeader(t, "X-Content-Type-Options", nil,
		func(config *internal.Config) {
			config.XContentTypeOptions = "invalid"
		})
}

func TestStrictTransportSecurity(t *testing.T) {
	// Test "on"
	assertResponseHeader(t, "Strict-Transport-Security", "max-age=31536000; includeSubDomains",
		func(config *internal.Config) {
			config.StrictTransportSecurity = "on"
		})

	// Test "off" (header should not be set)
	assertResponseHeader(t, "Strict-Transport-Security", nil,
		func(config *internal.Config) {
			config.StrictTransportSecurity = "off"
		})
}

func TestReferrerPolicy(t *testing.T) {
	// Test "no-referrer"
	assertResponseHeader(t, "Referrer-Policy", "no-referrer",
		func(config *internal.Config) {
			config.ReferrerPolicy = "no-referrer"
		})

	// Test "no-referrer-when-downgrade"
	assertResponseHeader(t, "Referrer-Policy", "no-referrer-when-downgrade",
		func(config *internal.Config) {
			config.ReferrerPolicy = "no-referrer-when-downgrade"
		})

	// Test "origin"
	assertResponseHeader(t, "Referrer-Policy", "origin",
		func(config *internal.Config) {
			config.ReferrerPolicy = "origin"
		})

	// Test "origin-when-cross-origin"
	assertResponseHeader(t, "Referrer-Policy", "origin-when-cross-origin",
		func(config *internal.Config) {
			config.ReferrerPolicy = "origin-when-cross-origin"
		})

	// Test "same-origin"
	assertResponseHeader(t, "Referrer-Policy", "same-origin",
		func(config *internal.Config) {
			config.ReferrerPolicy = "same-origin"
		})

	// Test "strict-origin"
	assertResponseHeader(t, "Referrer-Policy", "strict-origin",
		func(config *internal.Config) {
			config.ReferrerPolicy = "strict-origin"
		})

	// Test "strict-origin-when-cross-origin"
	assertResponseHeader(t, "Referrer-Policy", "strict-origin-when-cross-origin",
		func(config *internal.Config) {
			config.ReferrerPolicy = "strict-origin-when-cross-origin"
		})

	// Test "unsafe-url"
	assertResponseHeader(t, "Referrer-Policy", "unsafe-url",
		func(config *internal.Config) {
			config.ReferrerPolicy = "unsafe-url"
		})

	// Test "off" (header should not be set)
	assertResponseHeader(t, "Referrer-Policy", nil,
		func(config *internal.Config) {
			config.ReferrerPolicy = "off"
		})
}

func TestXXSSProtection(t *testing.T) {
	// Test "on"
	assertResponseHeader(t, "X-XSS-Protection", "1",
		func(config *internal.Config) {
			config.XXssProtection = "on"
		})

	// Test "block"
	assertResponseHeader(t, "X-XSS-Protection", "1; mode=block",
		func(config *internal.Config) {
			config.XXssProtection = "block"
		})

	// Test "off"
	assertResponseHeader(t, "X-XSS-Protection", "0",
		func(config *internal.Config) {
			config.XXssProtection = "off"
		})
}

func TestCrossOriginOpenerPolicy(t *testing.T) {
	// Test "unsafe-none"
	assertResponseHeader(t, "Cross-Origin-Opener-Policy", "unsafe-none",
		func(config *internal.Config) {
			config.CrossOriginOpenerPolicy = "unsafe-none"
		})

	// Test "same-origin-allow-popups"
	assertResponseHeader(t, "Cross-Origin-Opener-Policy", "same-origin-allow-popups",
		func(config *internal.Config) {
			config.CrossOriginOpenerPolicy = "same-origin-allow-popups"
		})

	// Test "same-origin"
	assertResponseHeader(t, "Cross-Origin-Opener-Policy", "same-origin",
		func(config *internal.Config) {
			config.CrossOriginOpenerPolicy = "same-origin"
		})

	// Test "noopener-allow-popups"
	assertResponseHeader(t, "Cross-Origin-Opener-Policy", "noopener-allow-popups",
		func(config *internal.Config) {
			config.CrossOriginOpenerPolicy = "noopener-allow-popups"
		})

	// Test "off" (header should not be set)
	assertResponseHeader(t, "Cross-Origin-Opener-Policy", nil,
		func(config *internal.Config) {
			config.CrossOriginOpenerPolicy = "off"
		})
}

func TestCrossOriginEmbedderPolicy(t *testing.T) {
	// Test "unsafe-none"
	assertResponseHeader(t, "Cross-Origin-Embedder-Policy", "unsafe-none",
		func(config *internal.Config) {
			config.CrossOriginEmbedderPolicy = "unsafe-none"
		})

	// Test "require-corp"
	assertResponseHeader(t, "Cross-Origin-Embedder-Policy", "require-corp",
		func(config *internal.Config) {
			config.CrossOriginEmbedderPolicy = "require-corp"
		})

	// Test "credentialless"
	assertResponseHeader(t, "Cross-Origin-Embedder-Policy", "credentialless",
		func(config *internal.Config) {
			config.CrossOriginEmbedderPolicy = "credentialless"
		})

	// Test "off" (header should not be set)
	assertResponseHeader(t, "Cross-Origin-Embedder-Policy", nil,
		func(config *internal.Config) {
			config.CrossOriginEmbedderPolicy = "off"
		})
}

func TestOriginAgentCluster(t *testing.T) {
	// Test "on"
	assertResponseHeader(t, "Origin-Agent-Cluster", "?1",
		func(config *internal.Config) {
			config.OriginAgentCluster = "on"
		})

	// Test "off" (header should not be set)
	assertResponseHeader(t, "Origin-Agent-Cluster", nil,
		func(config *internal.Config) {
			config.OriginAgentCluster = "off"
		})
}

func TestCrossOriginResourcePolicy(t *testing.T) {
	// Test "same-origin"
	assertResponseHeader(t, "Cross-Origin-Resource-Policy", "same-origin",
		func(config *internal.Config) {
			config.CrossOriginResourcePolicy = "same-origin"
		})

	// Test "same-site"
	assertResponseHeader(t, "Cross-Origin-Resource-Policy", "same-site",
		func(config *internal.Config) {
			config.CrossOriginResourcePolicy = "same-site"
		})

	// Test "cross-origin"
	assertResponseHeader(t, "Cross-Origin-Resource-Policy", "cross-origin",
		func(config *internal.Config) {
			config.CrossOriginResourcePolicy = "cross-origin"
		})

	// Test "off" (header should not be set)
	assertResponseHeader(t, "Cross-Origin-Resource-Policy", nil,
		func(config *internal.Config) {
			config.CrossOriginResourcePolicy = "off"
		})
}

// TestXPermittedCrossDomainPolicies tests the "X-Permitted-Cross-Domain-Policies" header.
func TestXPermittedCrossDomainPolicies(t *testing.T) {
	// Test "none"
	assertResponseHeader(t, "X-Permitted-Cross-Domain-Policies", "none",
		func(config *internal.Config) {
			config.XPermittedCrossDomainPolicies = "none"
		})

	// Test "master-only"
	assertResponseHeader(t, "X-Permitted-Cross-Domain-Policies", "master-only",
		func(config *internal.Config) {
			config.XPermittedCrossDomainPolicies = "master-only"
		})

	// Test "by-content-type"
	assertResponseHeader(t, "X-Permitted-Cross-Domain-Policies", "by-content-type",
		func(config *internal.Config) {
			config.XPermittedCrossDomainPolicies = "by-content-type"
		})

	// Test "by-ftp-filename"
	assertResponseHeader(t, "X-Permitted-Cross-Domain-Policies", "by-ftp-filename",
		func(config *internal.Config) {
			config.XPermittedCrossDomainPolicies = "by-ftp-filename"
		})

	// Test "all"
	assertResponseHeader(t, "X-Permitted-Cross-Domain-Policies", "all",
		func(config *internal.Config) {
			config.XPermittedCrossDomainPolicies = "all"
		})

	// Test "none-this-response"
	assertResponseHeader(t, "X-Permitted-Cross-Domain-Policies", "none-this-response",
		func(config *internal.Config) {
			config.XPermittedCrossDomainPolicies = "none-this-response"
		})

	// Test "off" (header should not be set)
	assertResponseHeader(t, "X-Permitted-Cross-Domain-Policies", nil,
		func(config *internal.Config) {
			config.XPermittedCrossDomainPolicies = "off"
		})
}

// tests if "X-Powered-By" header is removed when RemovePoweredBy is "on".
func TestRemovePoweredBy(t *testing.T) {
	assertResponseHeader(t, "X-Powered-By", nil,
		func(config *internal.Config) {
			config.RemovePoweredBy = "on"
		})
}

// tests if "Server" header is removed when RemoveServerInfo is "on".
func TestRemoveServerInfo(t *testing.T) {
	assertResponseHeader(t, "Server", nil,
		func(config *internal.Config) {
			config.RemovePoweredBy = "on"
		})
}
