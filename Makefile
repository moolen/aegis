.PHONY: build test lint docker fmt

GO_FILES := $(shell find . -name '*.go' -not -path './.worktrees/*' -not -path './vendor/*')

build:
	mkdir -p bin
	go build -o ./bin/aegis ./cmd/aegis

test:
	go test ./...

lint:
	test -n "$(GO_FILES)" && gofmt -w $(GO_FILES) || true
	go test ./...

docker:
	docker build -t aegis:dev .

fmt:
	test -n "$(GO_FILES)" && gofmt -w $(GO_FILES) || true
