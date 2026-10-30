# receipts-log — common tasks. `make check` runs the checks of CI's test
# job; CI also runs `make fuzz`, `make build`, `make interop` (which needs
# a verifiable-receipts checkout) and a container build.

GO        ?= go
BIN       ?= dist/receipts-log
VERSION   ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
FUZZTIME  ?= 15s
# 2026.2.1 supports Go up to 1.26; CI runs it there (see ci.yml).
STATICCHECK_VERSION ?= 2026.2.1
VERIFIABLE_RECEIPTS_DIR ?= ../verifiable-receipts
IMAGE     ?= receipts-log:$(VERSION)

FUZZ_TARGETS := \
	merkle:FuzzVerifyInclusion merkle:FuzzVerifyConsistency merkle:FuzzParseHashes \
	sth:FuzzCanonicalString sth:FuzzParseCanonical sth:FuzzVerify \
	keys:FuzzParsePEM store:FuzzScan translog:FuzzAppend translog:FuzzVerifyIssued server:FuzzHandler

.PHONY: all build test race vet fmt fmt-check staticcheck fuzz interop check docker clean

all: check build

build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="-s -w -X main.version=$(VERSION)" -o $(BIN) ./cmd/receipts-log

test:
	$(GO) test ./...

race:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

fmt:
	gofmt -w .

fmt-check:
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

staticcheck:
	$(GO) run honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION) ./...

# Runs every fuzz target for FUZZTIME each.
fuzz:
	@set -e; for t in $(FUZZ_TARGETS); do \
		pkg=$${t%%:*}; fn=$${t##*:}; \
		echo "fuzz $$pkg $$fn ($(FUZZTIME))"; \
		$(GO) test -run '^$$' -fuzz "^$$fn$$" -fuzztime $(FUZZTIME) ./internal/$$pkg/; \
	done

# Cross-checks against verifiable-receipts' TypeScript, Python and Go code.
# Needs node >= 22.6, python3 with cryptography, and a checkout.
interop:
	VERIFIABLE_RECEIPTS_DIR="$(abspath $(VERIFIABLE_RECEIPTS_DIR))" $(GO) test -race -count=1 -v ./interop/

check: fmt-check vet staticcheck race

docker:
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE) .

clean:
	rm -rf dist
