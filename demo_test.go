package superheader

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// createHandler creates the handler with the given configuration.
func createHandler(config *Config) (http.Handler, error) {
	// Mock handler to complete the chain
	mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Just a mock handler to complete the chain
	})
	// Return a new handler with the given config
	return New(context.Background(), mockHandler, config, "test")
}

// assertResponseHeader checks if the expected header is set correctly in the response
func assertResponseHeader(t *testing.T, headerKey string, expectedValue string, configSupplier func(*Config)) {
	// Create a new config and apply inline configuration through the supplier
	config := CreateConfig()
	configSupplier(config)

	// Create the handler with the provided config
	handler, err := createHandler(config)
	if err != nil {
		t.Fatalf("Failed to create handler: %v", err)
	}

	// Create a new HTTP request and response recorder
	req := httptest.NewRequest("GET", "http://example.com", nil)
	rec := httptest.NewRecorder()

	// Call the handler to process the request
	handler.ServeHTTP(rec, req)

	// Retrieve the header from the response
	actualHeader := rec.Header().Get(headerKey)

	// Assert that the actual header matches the expected value
	if actualHeader != expectedValue {
		t.Errorf("Expected %s header to be %s, but got %s", headerKey, expectedValue, actualHeader)
	}
}

// TestXFrameOptions tests the "X-Frame-Options" header.
func TestXFrameOptions(t *testing.T) {
	assertResponseHeader(t, "X-Frame-Options", "SAMEORIGIN", func(config *Config) {
		config.XFrameOptions = "SAMEORIGIN"
	})
}

// TestXDNSPrefetchControl tests the "X-DNS-Prefetch-Control" header.
func TestXDNSPrefetchControl(t *testing.T) {
	assertResponseHeader(t, "X-DNS-Prefetch-Control", "on", func(config *Config) {
		config.XDNSPrefetchControl = "on"
	})
}

// TestXContentTypeOptions tests the "X-Content-Type-Options" header.
func TestXContentTypeOptions(t *testing.T) {
	assertResponseHeader(t, "X-Content-Type-Options", "nosniff", func(config *Config) {
		config.XContentTypeOptions = "on"
	})
}

// TestStrictTransportSecurity tests the "Strict-Transport-Security" header.
func TestStrictTransportSecurity(t *testing.T) {
	assertResponseHeader(t, "Strict-Transport-Security", "max-age=31536000; includeSubDomains", func(config *Config) {
		config.StrictTransportSecurity = "on"
	})
}

// TestReferrerPolicy tests the "Referrer-Policy" header.
func TestReferrerPolicy(t *testing.T) {
	assertResponseHeader(t, "Referrer-Policy", "no-referrer", func(config *Config) {
		config.ReferrerPolicy = "no-referrer"
	})
}

// TestXXSSProtection tests the "X-XSS-Protection" header.
func TestXXSSProtection(t *testing.T) {
	assertResponseHeader(t, "X-XSS-Protection", "1", func(config *Config) {
		config.XXSSProtection = "on"
	})
}

// TestCrossOriginOpenerPolicy tests the "Cross-Origin-Opener-Policy" header.
func TestCrossOriginOpenerPolicy(t *testing.T) {
	assertResponseHeader(t, "Cross-Origin-Opener-Policy", "unsafe-none", func(config *Config) {
		config.CrossOriginOpenerPolicy = "unsafe-none"
	})
}

// TestCrossOriginEmbedderPolicy tests the "Cross-Origin-Embedder-Policy" header.
func TestCrossOriginEmbedderPolicy(t *testing.T) {
	assertResponseHeader(t, "Cross-Origin-Embedder-Policy", "unsafe-none", func(config *Config) {
		config.CrossOriginEmbedderPolicy = "unsafe-none"
	})
}

// TestCrossOriginResourcePolicy tests the "Cross-Origin-Resource-Policy" header.
func TestCrossOriginResourcePolicy(t *testing.T) {
	assertResponseHeader(t, "Cross-Origin-Resource-Policy", "same-origin", func(config *Config) {
		config.CrossOriginResourcePolicy = "same-origin"
	})
}

// TestOriginAgentCluster tests the "Origin-Agent-Cluster" header.
func TestOriginAgentCluster(t *testing.T) {
	assertResponseHeader(t, "Origin-Agent-Cluster", "?1", func(config *Config) {
		config.OriginAgentCluster = "on"
	})
}

// TestXPermittedCrossDomainPolicies tests the "X-Permitted-Cross-Domain-Policies" header.
func TestXPermittedCrossDomainPolicies(t *testing.T) {
	assertResponseHeader(t, "X-Permitted-Cross-Domain-Policies", "none", func(config *Config) {
		config.XPermittedCrossDomainPolicies = "none"
	})
}
