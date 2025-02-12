package superheader

import (
	"context"
	"net/http"
)

type Config struct {
	//
}

func CreateConfig() *Config {
	return &Config{
		//
	}
}

type Demo struct {
	next    http.Handler
	headers map[string]string
	name    string
}

// New created a new Demo plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {

	return &Demo{
		next: next,
		name: name,
	}, nil
}

func (a *Demo) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	req.Header.Set("key", "ar")
	a.next.ServeHTTP(rw, req)
}
