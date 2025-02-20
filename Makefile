.PHONY: lint test vendor clean

export GO111MODULE=on

default: lint test

lint:
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	golangci-lint run

test:
	go test -v -cover -count=1 ./...

yaegi_test:
	yaegi test -v .

vendor:
	go mod vendor

clean:
	rm -rf ./vendor

format:
	go install golang.org/x/tools/cmd/goimports@latest
	goimports -w .
	gofmt -s -w .