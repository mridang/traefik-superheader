.PHONY: lint test vendor clean format build default ensure-gotestsum

export GO111MODULE=on

GOIMPORTS_BIN := goimports
GOLANGCI_LINT_BIN := golangci-lint
PATH := $(GOBIN):$(PATH)
GOTESTSUM ?= gotestsum
TEST_FORMAT ?= pkgname-and-test-fails
JUNIT_FILE := .out/junit.xml
LCOV_FILE := .out/lcov.info

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
	@command -v $(GOTESTSUM) >/dev/null 2>&1 || $(MAKE) ensure-gotestsum
	rm -rf .out
	mkdir -p $(GOCACHE) $(GOTMPDIR) $(dir $(LCOV_FILE))
	GOFLAGS= CGO_ENABLED=1 GOCACHE=$(GOCACHE) GOTMPDIR=$(GOTMPDIR) $(GOTESTSUM) --junitfile $(JUNIT_FILE) --format $(TEST_FORMAT) -- -mod=mod -coverpkg=./... -covermode=atomic -coverprofile=$(LCOV_FILE) -count=1 ./...

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

ensure-gotestsum:
	@if ! command -v $(GOTESTSUM) >/dev/null 2>&1; then \
		GOFLAGS=-mod=mod go install gotest.tools/gotestsum@v1.12.0; \
	fi
