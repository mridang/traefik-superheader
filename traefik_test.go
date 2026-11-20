package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os/exec"
	"regexp"
	"testing"
	"time"

	"github.com/steinfletcher/apitest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const baseURL = "http://localhost:7080"
const composeFile = "etc/docker-compose.yml"

func TestTraefikPlugin(t *testing.T) {
	runPluginBuild(t)

	upCmd := exec.Command("docker", "compose", "-f", composeFile, "up", "-d", "--wait")
	upOut, err := upCmd.CombinedOutput()
	require.NoError(t, err, "failed to start docker compose: %s", upOut)

	defer func() {
		downCmd := exec.Command("docker", "compose", "-f", composeFile, "down")
		downOut, downErr := downCmd.CombinedOutput()
		assert.NoError(t, downErr, "failed to tear down docker compose: %s", downOut)
	}()

	waitForRoutes(t, baseURL+"/hello/", baseURL+"/whoami/")

	t.Run("HelloService_StrictHeaders", func(t *testing.T) {
		apitest.New().
			EnableNetworking().
			Get(baseURL+"/hello/").
			Expect(t).
			Status(http.StatusOK).
			Header("X-Frame-Options", "deny").
			Header("X-Content-Type-Options", "nosniff").
			Header("X-Dns-Prefetch-Control", "on").
			HeaderPresent("Server-Timing").
			Assert(serverTimingAssertion).
			End()
	})

	t.Run("WhoamiService_RelaxedHeaders", func(t *testing.T) {
		apitest.New().
			EnableNetworking().
			Get(baseURL+"/whoami/").
			Expect(t).
			Status(http.StatusOK).
			Header("X-Frame-Options", "sameorigin").
			Header("X-Dns-Prefetch-Control", "off").
			HeaderPresent("Server-Timing").
			Assert(serverTimingAssertion).
			End()
	})
}

func serverTimingAssertion(res *http.Response, _ *http.Request) error {
	st := res.Header.Get("Server-Timing")
	if st == "" {
		return errors.New("Server-Timing header is missing")
	}

	re := regexp.MustCompile(`dur=\d+(\.\d+)?`)
	if !re.MatchString(st) {
		return fmt.Errorf("invalid Server-Timing header: %q", st)
	}

	return nil
}

// waitForRoutes blocks until Traefik serves every URL with a non-404 status,
// because the Docker provider publishes the routes some time after startup.
func waitForRoutes(t *testing.T, urls ...string) {
	t.Helper()

	for _, url := range urls {
		require.Eventually(t, func() bool {
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
			if err != nil {
				return false
			}

			res, err := http.DefaultClient.Do(req)
			if err != nil {
				return false
			}
			defer func() { _ = res.Body.Close() }()

			return res.StatusCode != http.StatusNotFound
		}, 60*time.Second, 500*time.Millisecond, "route %s never became available", url)
	}
}
