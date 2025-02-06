package timeit

import (
	"context"
	"fmt"
	"net/http"

	"github.com/felixge/httpsnoop"
)

type Config struct {
	//
}

func CreateConfig() *Config {
	return &Config{}
}

type Demo struct {
	//
}

func New(c context.Context, next http.Handler, _ *Config, name string) (http.Handler, error) {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m := httpsnoop.CaptureMetrics(next, w, r)
		ff := m.Duration.Milliseconds()
		duratio := fmt.Sprintf("cache;desc=\"Traefik Ingress\";dur=%.1f", float64(ff)/1000)
		w.Header().Set("Server-Timing", duratio)

	}), nil
}
