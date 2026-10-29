MODULE := github.com/entire-vc/evc-keep
BINARIES := keep keep-server keep-runner
LDFLAGS := -X '$(MODULE)/internal/version.Version=$(shell git describe --tags --always --dirty 2>/dev/null || echo dev)' \
           -X '$(MODULE)/internal/version.Commit=$(shell git rev-parse HEAD 2>/dev/null || echo unknown)' \
           -X '$(MODULE)/internal/version.BuildDate=$(shell date -u +%Y-%m-%dT%H:%M:%SZ)'

.PHONY: all build fmt fmt-check vet lint test race build-check clean

all: build

build:
	@for b in $(BINARIES); do \
		echo "building $$b"; \
		go build -ldflags "$(LDFLAGS)" -o bin/$$b ./cmd/$$b || exit 1; \
	done

fmt:
	gofmt -w .

fmt-check:
	@out="$$(gofmt -l .)"; \
	if [ -n "$$out" ]; then \
		echo "gofmt needs to be run on:"; echo "$$out"; exit 1; \
	fi

vet:
	go vet ./...

lint: fmt-check vet
	golangci-lint run ./...

test:
	# -p 1: see .gitlab-ci.yml's test job — internal/store's migration
	# tests reset the whole schema mid-run, and test/security's dumpDB reads
	# every row of every table, either of which races against any other
	# package's test if packages run concurrently against one shared database.
	go test -p 1 ./...

race:
	# -p 1: see .gitlab-ci.yml's test job — internal/store's migration
	# tests reset the whole schema mid-run, which races against any other
	# package's test reading a real table if packages run concurrently
	# against one shared database.
	go test -race -p 1 ./...

build-check: fmt-check vet
	go build ./...

clean:
	rm -rf bin/
