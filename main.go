//nolint:revive,stylecheck // traefik needs this
package traefik_superheader

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"mridang/traefik-superheader/internal"
)

type Middleware struct {
	next   http.Handler
	name   string
	config *internal.Config
}

// CreateConfig is a function that is required by Traefik to instantiate
// the configuration.
//
//goland:noinspection ALL
func CreateConfig() *internal.Config {
	return internal.CreateConfig()
}

func New(_ context.Context, next http.Handler, config *internal.Config, name string) (http.Handler, error) {
	return &Middleware{
		next:   next,
		name:   name,
		config: config,
	}, nil
}

// TimingHeaderWriter is a custom wrapper for http.ResponseWriter that captures
// the time taken to process the request and adds a "Server-Timing" header
// with the processing duration. This hook is necessary for injecting custom
// timing information into the response headers before the body is written.
// Additionally, it allows stripping headers if configured, ensuring that
// headers are modified before the final response is sent.
//
// This hook is needed because HTTP response headers must be set before the
// body is sent. By using a custom writer, we ensure that the timing information
// (via the "Server-Timing" header) is added at the correct point in the
// response lifecycle, right before the response body is written. This guarantees
// that the header is included with the response and the timing data is accurate
// without prematurely sending any data to the client.
type TimingHeaderWriter struct {
	http.ResponseWriter
	startTime    time.Time
	stripHeaders bool
}

// WriteHeader captures the status code and sets the "Server-Timing" header.
// It also checks if the headers need to be stripped based on the configuration
// and does so before writing the final response. The "Server-Timing" header
// is added with the processing time in seconds. The WriteHeader method is
// invoked when the status code is set and before the response body is sent.
func (writer *TimingHeaderWriter) WriteHeader(statusCode int) {
	// Strip headers if needed
	if writer.stripHeaders {
		internal.StripHeaders(writer.ResponseWriter)
	}

	elapsedTime := time.Since(writer.startTime)
	//nolint:lll // linter rule suppression
	serverTimingValue := fmt.Sprintf("name=\"traefik\", dur=%.2f, desc=\"Middleware time\"", float64(elapsedTime.Milliseconds()))

	writer.ResponseWriter.Header().Add(internal.ServerTiming, serverTimingValue)
	writer.ResponseWriter.WriteHeader(statusCode)
}

// ServeHTTP processes the incoming HTTP request, strips certain headers if
// configured, and adds a Server-Timing header to the response.
// The execution time of the request handling is measured and formatted in
// milliseconds (e.g., "123.45ms") and added to the response header as
// "Server-Timing".
func (plugin *Middleware) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	startTime := time.Now()
	internal.AddSecureHeaders(plugin.config, rw)

	cw := &TimingHeaderWriter{
		ResponseWriter: rw,
		startTime:      startTime,
		stripHeaders:   plugin.config.RemovePoweredBy == "on",
	}

	plugin.next.ServeHTTP(cw, req)
}
