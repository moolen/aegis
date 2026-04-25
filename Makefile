.PHONY: build test lint docker fmt e2e e2e-kind

GO ?= $(shell command -v go 2>/dev/null || printf '/usr/local/go/bin/go')
GOFMT ?= $(shell command -v gofmt 2>/dev/null || printf '/usr/local/go/bin/gofmt')
GO_FILES := $(shell find . -name '*.go' \
	-not -path './.worktrees/*' \
	-not -path './vendor/*' \
	-not -path './.cache/*' \
	-not -path './.gocache/*' \
	-not -path './.gomodcache/*')
GOFMT_DIFF := $(shell $(GOFMT) -l $(GO_FILES))

build:
	mkdir -p bin
	$(GO) build -o ./bin/aegis ./cmd/aegis

test:
	$(GO) test ./...

e2e:
	$(GO) test -tags e2e ./e2e/...

e2e-kind:
	$(GO) test -tags kind_e2e -timeout 30m ./e2e/...

lint:
	test -z "$(GOFMT_DIFF)"
	$(GO) test ./...

docker:
	docker build -t aegis:dev .

fmt:
	test -n "$(GO_FILES)" && $(GOFMT) -w $(GO_FILES) || true
