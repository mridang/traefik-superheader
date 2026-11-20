.PHONY: default build test lint format format-check generate clean clean-coverage

export GO111MODULE=on

GOTESTSUM ?= go tool gotestsum
TEST_FORMAT ?= pkgname-and-test-fails
COVER_DIR := .out/cover
JUNIT_FILE := .out/junit.xml
LCOV_FILE := .out/lcov.info

BUILD_DIR := build
WASM_TARGET := $(BUILD_DIR)/plugin.wasm
SOURCES := main.go $(wildcard internal/*.go)

default: test

# Build the Wasm plugin using TinyGo
# Creates the build directory and places the binary inside.
build: $(WASM_TARGET)

$(WASM_TARGET): $(SOURCES)
	mkdir -p $(BUILD_DIR)
	tinygo build -o $@ -scheduler=none --no-debug -target=wasip1 -buildmode=wasi-legacy main.go

test: clean-coverage
	mkdir -p $(dir $(LCOV_FILE))
	$(GOTESTSUM) --junitfile $(JUNIT_FILE) --format $(TEST_FORMAT) -- -coverpkg=./... -covermode=atomic -coverprofile=$(LCOV_FILE) -count=1 ./...

lint:
	go tool golangci-lint run --verbose

format:
	dprint fmt
	go fmt ./...

format-check:
	dprint check
	test -z "$$(gofmt -s -l .)"

generate:
	go generate ./...

clean-coverage:
	rm -rf .out

clean: clean-coverage
	rm -rf $(BUILD_DIR)
