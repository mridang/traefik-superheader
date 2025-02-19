.PHONY: lint test vendor clean

export GO111MODULE=on

default: lint test

lint:
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
	goimports -w .
	gofmt -s -w .