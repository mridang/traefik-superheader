package main

import (
	_ "embed"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/http-wasm/http-wasm-guest-tinygo/handler"
	"github.com/http-wasm/http-wasm-guest-tinygo/handler/api"
	"github.com/mridang/traefik-superheader/internal"
)

const (
	milli   = int64(time.Millisecond)
	ctxMask = 0xFFF
)

//nolint:gochecknoglobals // Traefik WASM requires global configuration and timing state.
var (
	cfg        internal.Config
	startTimes [ctxMask + 1]int64
	reqCounter uint32
)

//go:embed VERSION
var Version string

func main() {
	handler.Host.EnableFeatures(api.FeatureBufferResponse)
	handler.Host.Log(api.LogLevelInfo, "plugin version: "+strings.TrimSpace(Version))

	configBytes := handler.Host.GetConfig()
	if len(configBytes) > 0 {
		_ = json.Unmarshal(configBytes, &cfg)
	} else {
		cfg = internal.Config{
			XFrameOptions:                 "DENY",
			XDnsPrefetchControl:           "on",
			XContentTypeOptions:           "on",
			StrictTransportSecurity:       "on",
			ReferrerPolicy:                "on",
			XXssProtection:                "on",
			CrossOriginOpenerPolicy:       "on",
			CrossOriginEmbedderPolicy:     "on",
			CrossOriginResourcePolicy:     "on",
			OriginAgentCluster:            "on",
			XPermittedCrossDomainPolicies: "on",
			RemovePoweredBy:               "on",
		}
	}

	//nolint:reassign // WASM runtime requires assigning to handler.HandleRequestFn.
	handler.HandleRequestFn = func(_ api.Request, _ api.Response) (bool, uint32) {
		reqCounter++
		reqCtx := reqCounter & ctxMask
		startTimes[reqCtx] = time.Now().UnixNano()
		return true, reqCtx
	}

	//nolint:reassign // WASM runtime requires assigning to handler.HandleResponseFn.
	handler.HandleResponseFn = func(reqCtx uint32, _ api.Request, resp api.Response, isError bool) {
		if isError {
			return
		}

		start := startTimes[reqCtx&ctxMask]
		elapsedMs := (time.Now().UnixNano() - start) / milli

		resp.Headers().Add(
			internal.ServerTiming,
			"wasm;dur="+strconv.FormatInt(elapsedMs, 10),
		)

		internal.AddSecureHeaders(&cfg, resp)

		if cfg.RemovePoweredBy == "on" {
			internal.StripHeaders(resp)
		}
	}
}
