package superheader_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
	"time"

	timeit "github.com/mridang/traefik-superheader"
	"golang.org/x/exp/rand"
)

func TestDemo(t *testing.T) {
	cfg := timeit.CreateConfig()

	ctx := context.Background()
	rand.Seed(uint64(time.Now().UnixNano()))

	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		sleepDuration := time.Duration(rand.Intn(501)+500) * time.Millisecond
		time.Sleep(sleepDuration)

	})

	handler, err := timeit.New(ctx, next, cfg, "demo-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	handler.ServeHTTP(recorder, req)
	res := recorder.Result()

	for key, values := range res.Header {
		for _, value := range values {
			fmt.Printf("%s: %s\n", key, value)
		}
	}

	assertHeader(t, res, "Server-Timing", `^cache;desc="([^"]+)";dur=([0-9]*\.[0-9]+)$`)
}

func assertHeader(t *testing.T, req *http.Response, key, expected string) {
	t.Helper()

	values, ok := req.Header[key]
	if !ok {
		t.Errorf("Header '%s' not found", key)
		return
	}

	re, err := regexp.Compile(expected)
	if err != nil {
		t.Errorf("Invalid regex pattern: %v", err)
		return
	}

	for _, value := range values {
		if re.MatchString(value) {
			return // Header matched the regex
		}
	}

	t.Errorf("Header '%s' with value matching '%s' not found", key, expected)
}
