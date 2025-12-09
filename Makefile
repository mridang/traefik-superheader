.PHONY: lint test vendor clean format build default

export GO111MODULE=on

GOIMPORTS_BIN := goimports
GOLANGCI_LINT_BIN := golangci-lint

BUILD_DIR := build
WASM_TARGET := $(BUILD_DIR)/plugin.wasm
SOURCES := main.go $(wildcard internal/*.go)

default: lint test

lint: $(GOLANGCI_LINT_BIN)
	$(GOLANGCI_LINT_BIN) run

$(GOIMPORTS_BIN):
	go install golang.org/x/tools/cmd/goimports@v0.19.0

$(GOLANGCI_LINT_BIN):
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# Run all Go tests
test:
	go test -v -cover -count=1 ./...

# Manage module dependencies locally
vendor:
	go mod vendor

# Build the Wasm plugin using TinyGo
# Creates the build directory and places the binary inside.
build: $(WASM_TARGET)

$(WASM_TARGET): $(SOURCES)
	mkdir -p $(BUILD_DIR)
	tinygo build -o $@ -scheduler=none --no-debug -target=wasip1 main.go

# Format all Go files
format: $(GOIMPORTS_BIN)
	go fmt ./...
	$(GOIMPORTS_BIN) -w .
	gofmt -s -w .

# Clean generated directories and files, including Go build caches
clean:
	go clean -cache -testcache -modcache
	rm -rf ./vendor $(BUILD_DIR)
