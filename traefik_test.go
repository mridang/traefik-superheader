package main

import (
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

	time.Sleep(2 * time.Second)

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
