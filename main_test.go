package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/http-wasm/http-wasm-host-go/api"
	"github.com/http-wasm/http-wasm-host-go/handler"
	wasmhttp "github.com/http-wasm/http-wasm-host-go/handler/nethttp"
	"github.com/mridang/traefik-superheader/internal"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tetratelabs/wazero"
)

func loadWasm(t *testing.T) []byte {
	runPluginBuild(t)

	path := "build/plugin.wasm"

	stat, err := os.Stat(path)
	if os.IsNotExist(err) {
		if _, err2 := os.Stat("plugin.wasm"); err2 == nil {
			path = "plugin.wasm"
			stat, _ = os.Stat(path)
		} else {
			t.Fatalf("plugin.wasm not found")
		}
	}

	if stat.Size() == 0 {
		t.Fatalf("plugin.wasm is empty")
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read wasm: %v", err)
	}

	return b
}

func createHandler(t *testing.T, config *internal.Config) (http.Handler, error) {
	mock := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "Go")
		w.Header().Set("X-Powered-By", "Go")
		w.WriteHeader(http.StatusOK)
	})

	wasm := loadWasm(t)

	cfg, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()

	mw, err := wasmhttp.NewMiddleware(ctx, wasm,
		handler.GuestConfig(cfg),
		handler.Logger(api.ConsoleLogger{}),
		handler.ModuleConfig(wazero.NewModuleConfig()),
	)
	if err != nil {
		return nil, err
	}

	t.Cleanup(func() {
		require.NoError(t, mw.Close(ctx))
	})

	return mw.NewHandler(ctx, mock), nil
}

func assertResponseHeader(t *testing.T, key string, expected interface{}, configure func(*internal.Config)) {
	config := &internal.Config{}
	config.SetDefaults()
	configure(config)

	h, err := createHandler(t, config)
	if err != nil {
		t.Fatalf("handler creation failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "https://example.com", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	actual := rec.Header().Get(key)

	switch v := expected.(type) {
	case string:
		assert.Equal(t, strings.ToLower(v), strings.ToLower(actual))
	case nil:
		assert.Empty(t, actual)
	}
}

func TestXFrameOptions(t *testing.T) {
	assertResponseHeader(t, "X-Frame-Options", "DENY", func(c *internal.Config) {
		c.XFrameOptions = "DENY"
	})
	assertResponseHeader(t, "X-Frame-Options", "SAMEORIGIN", func(c *internal.Config) {
		c.XFrameOptions = "SAMEORIGIN"
	})
	assertResponseHeader(t, "X-Frame-Options", nil, func(c *internal.Config) {
		c.XFrameOptions = "invalid"
	})
}

func TestXDNSPrefetchControl(t *testing.T) {
	assertResponseHeader(t, "X-DNS-Prefetch-Control", "on", func(c *internal.Config) {
		c.XDnsPrefetchControl = "on"
	})
	assertResponseHeader(t, "X-DNS-Prefetch-Control", "off", func(c *internal.Config) {
		c.XDnsPrefetchControl = "off"
	})
	assertResponseHeader(t, "X-DNS-Prefetch-Control", nil, func(c *internal.Config) {
		c.XDnsPrefetchControl = "invalid"
	})
}

func TestXContentTypeOptions(t *testing.T) {
	assertResponseHeader(t, "X-Content-Type-Options", "nosniff", func(c *internal.Config) {
		c.XContentTypeOptions = "on"
	})
	assertResponseHeader(t, "X-Content-Type-Options", nil, func(c *internal.Config) {
		c.XContentTypeOptions = "off"
	})
	assertResponseHeader(t, "X-Content-Type-Options", nil, func(c *internal.Config) {
		c.XContentTypeOptions = "invalid"
	})
}

func TestStrictTransportSecurity(t *testing.T) {
	assertResponseHeader(t, "Strict-Transport-Security", "max-age=31536000; includeSubDomains", func(c *internal.Config) {
		c.StrictTransportSecurity = "on"
	})
	assertResponseHeader(t, "Strict-Transport-Security", nil, func(c *internal.Config) {
		c.StrictTransportSecurity = "off"
	})
}

func TestReferrerPolicy(t *testing.T) {
	policies := []string{
		"no-referrer", "no-referrer-when-downgrade", "origin",
		"origin-when-cross-origin", "same-origin", "strict-origin",
		"strict-origin-when-cross-origin", "unsafe-url",
	}

	for _, p := range policies {
		val := p
		assertResponseHeader(t, "Referrer-Policy", p, func(c *internal.Config) {
			c.ReferrerPolicy = val
		})
	}

	assertResponseHeader(t, "Referrer-Policy", nil, func(c *internal.Config) {
		c.ReferrerPolicy = "off"
	})
}

func TestXXSSProtection(t *testing.T) {
	assertResponseHeader(t, "X-XSS-Protection", "1", func(c *internal.Config) {
		c.XXssProtection = "on"
	})
	assertResponseHeader(t, "X-XSS-Protection", "1; mode=block", func(c *internal.Config) {
		c.XXssProtection = "block"
	})
	assertResponseHeader(t, "X-XSS-Protection", "", func(c *internal.Config) {
		c.XXssProtection = "off"
	})
}

func TestCrossOriginOpenerPolicy(t *testing.T) {
	policies := []string{"unsafe-none", "same-origin-allow-popups", "same-origin", "noopener-allow-popups"}

	for _, p := range policies {
		val := p
		assertResponseHeader(t, "Cross-Origin-Opener-Policy", p, func(c *internal.Config) {
			c.CrossOriginOpenerPolicy = val
		})
	}

	assertResponseHeader(t, "Cross-Origin-Opener-Policy", nil, func(c *internal.Config) {
		c.CrossOriginOpenerPolicy = "off"
	})
}

func TestCrossOriginEmbedderPolicy(t *testing.T) {
	policies := []string{"unsafe-none", "require-corp", "credentialless"}

	for _, p := range policies {
		val := p
		assertResponseHeader(t, "Cross-Origin-Embedder-Policy", p, func(c *internal.Config) {
			c.CrossOriginEmbedderPolicy = val
		})
	}

	assertResponseHeader(t, "Cross-Origin-Embedder-Policy", nil, func(c *internal.Config) {
		c.CrossOriginEmbedderPolicy = "off"
	})
}

func TestOriginAgentCluster(t *testing.T) {
	assertResponseHeader(t, "Origin-Agent-Cluster", "?1", func(c *internal.Config) {
		c.OriginAgentCluster = "on"
	})
	assertResponseHeader(t, "Origin-Agent-Cluster", nil, func(c *internal.Config) {
		c.OriginAgentCluster = "off"
	})
}

func TestCrossOriginResourcePolicy(t *testing.T) {
	policies := []string{"same-origin", "same-site", "cross-origin"}

	for _, p := range policies {
		val := p
		assertResponseHeader(t, "Cross-Origin-Resource-Policy", p, func(c *internal.Config) {
			c.CrossOriginResourcePolicy = val
		})
	}

	assertResponseHeader(t, "Cross-Origin-Resource-Policy", nil, func(c *internal.Config) {
		c.CrossOriginResourcePolicy = "off"
	})
}

func TestXPermittedCrossDomainPolicies(t *testing.T) {
	policies := []string{
		"none", "master-only", "by-content-type",
		"by-ftp-filename", "all", "none-this-response",
	}

	for _, p := range policies {
		val := p
		assertResponseHeader(t, "X-Permitted-Cross-Domain-Policies", p, func(c *internal.Config) {
			c.XPermittedCrossDomainPolicies = val
		})
	}

	assertResponseHeader(t, "X-Permitted-Cross-Domain-Policies", nil, func(c *internal.Config) {
		c.XPermittedCrossDomainPolicies = "off"
	})
}

func TestRemovePoweredBy(t *testing.T) {
	assertResponseHeader(t, "X-Powered-By", nil, func(c *internal.Config) {
		c.RemovePoweredBy = "on"
	})
	assertResponseHeader(t, "X-Powered-By", "go", func(c *internal.Config) {
		c.RemovePoweredBy = "off"
	})
}
