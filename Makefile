.PHONY: build test lint docker fmt e2e e2e-kind \
	perf-local-http perf-local-connect perf-local-mitm \
	perf-kind-http perf-kind-connect perf-kind-mitm

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
	$(GO) test -tags kind_e2e -timeout 45m ./e2e/...

lint:
	test -z "$(GOFMT_DIFF)"
	$(GO) test ./...

docker:
	docker build -t aegis:dev .

fmt:
	test -n "$(GO_FILES)" && $(GOFMT) -w $(GO_FILES) || true

perf-local-http:
	./perf/scripts/run-local-http.sh

perf-local-connect:
	./perf/scripts/run-local-connect-passthrough.sh

perf-local-mitm:
	./perf/scripts/run-local-connect-mitm.sh

perf-kind-http:
	./perf/scripts/run-kind-http.sh

perf-kind-connect:
	./perf/scripts/run-kind-connect-passthrough.sh

perf-kind-mitm:
	./perf/scripts/run-kind-connect-mitm.sh
