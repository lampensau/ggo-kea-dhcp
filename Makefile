# ggo-kea-dhcp - build helpers.
#
# IMPORTANT: every target regenerates templ components first. Editing a *.templ
# file and running a bare `go build` will NOT pick up the change - `go build`
# compiles the already-generated *_templ.go. Always go through these targets
# (or run `templ generate` yourself before building).

TEMPL    ?= $(shell go env GOPATH)/bin/templ
NFPM     ?= $(shell go env GOPATH)/bin/nfpm
GOLANGCI ?= $(shell go env GOPATH)/bin/golangci-lint
# Pinned to match ci.yml so `make check` mirrors CI's vuln gate exactly.
GOVULNCHECK_VERSION ?= v1.5.0
GOVULNCHECK ?= $(shell go env GOPATH)/bin/govulncheck
GOFLAGS_VENDOR := -mod=vendor

# Version stamped into the .deb. Defaults to the single source of truth in
# internal/version/version.go (const Number), so a bare `make deb` is correctly
# versioned. Override only for a one-off (the release workflow passes the git tag).
GGO_VERSION ?= $(shell sed -n 's/.*Number = "\(.*\)".*/\1/p' internal/version/version.go)

# Live-deploy target (make deploy). Override host/user as needed:
#   make deploy DEPLOY_HOST=10.10.0.1 DEPLOY_USER=timo
DEPLOY_HOST ?= 10.0.0.1
DEPLOY_USER ?= timo

.PHONY: generate build vet test all check cover-gate cover-floors pi deb deploy release

generate:
	$(TEMPL) generate

build: generate
	go build $(GOFLAGS_VENDOR) .

vet: generate
	go vet $(GOFLAGS_VENDOR) ./...

test: generate
	go test $(GOFLAGS_VENDOR) -race -coverprofile=coverage.txt -covermode=atomic ./...

all: generate build vet test

# Mirror every CI gate locally so `make release` (and you) can confirm the tree
# is clean and green before tagging: templ output committed, gofmt, vendor in
# sync, vet, test, native + arm64 build, golangci-lint, govulncheck, shellcheck.
check: generate
	@[ -z "$$(git status --porcelain -- '*_templ.go')" ] || { echo "stale or untracked templ output - run 'templ generate' and commit *_templ.go"; git status --porcelain -- '*_templ.go'; exit 1; }
	@files=$$(git ls-files --cached --others --exclude-standard '*.go' | grep -vE '^vendor/|_templ\.go$$'); \
		unformatted=$$(gofmt -l $$files); \
		[ -z "$$unformatted" ] || { echo "gofmt needed:"; echo "$$unformatted"; exit 1; }
	go mod verify
	go mod vendor
	@[ -z "$$(git status --porcelain -- vendor go.mod go.sum)" ] || { echo "vendor out of sync or untracked - run 'go mod vendor' and commit vendor/ go.mod go.sum"; git status --porcelain -- vendor go.mod go.sum; exit 1; }
	go vet $(GOFLAGS_VENDOR) ./...
	go test $(GOFLAGS_VENDOR) -race -coverprofile=coverage.txt -covermode=atomic ./...
	$(MAKE) cover-gate
	go build $(GOFLAGS_VENDOR) .
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build $(GOFLAGS_VENDOR) -o ggo-kea-dhcp-arm64 .
	$(GOLANGCI) run
	go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)
	$(GOVULNCHECK) ./...
	@if command -v shellcheck >/dev/null; then \
		shellcheck -S error install.sh packaging/scripts/*.sh; \
	else \
		echo "shellcheck not installed - skipping (CI still runs it)"; \
	fi

# Enforce the total-coverage threshold AND the per-package regression floors
# (scripts/cover_floors.sh) on an existing coverage.txt (produced by `make
# test`). Single source of truth - CI calls this too.
cover-gate: cover-floors
	@go tool cover -func=coverage.txt | awk -v threshold="50.0" '/total:/ { \
		split($$NF, a, "%"); \
		coverage = a[1]; \
		if (coverage < threshold) { \
			print "Error: Code coverage (" coverage "%) is below threshold (" threshold "%)" > "/dev/stderr"; \
			exit 1; \
		} else { \
			print "Success: Code coverage (" coverage "%) meets threshold (" threshold "%)"; \
		} \
	}'

cover-floors:
	@./scripts/cover_floors.sh

# Cross-compile for the Raspberry Pi (ARM64). Adjust GOARCH=arm + GOARM=7 for 32-bit.
pi: generate
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build $(GOFLAGS_VENDOR) -o ggo-kea-dhcp-arm64 .

# Build the installable .deb into dist/ (cross-compiles first). Requires nfpm:
#   go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest
# Copy dist/*.deb next to install.sh onto the Pi; see BUILD_AND_DEPLOY.md.
deb: pi
	mkdir -p dist
	GGO_VERSION=$(GGO_VERSION) $(NFPM) package --packager deb --config packaging/nfpm.yaml --target dist/

# Cross-compile and replace the running binary on DEPLOY_HOST, then restart the
# service. Needs passwordless sudo on the target (the .deb install sets that up).
deploy: pi
	scp ggo-kea-dhcp-arm64 $(DEPLOY_USER)@$(DEPLOY_HOST):/tmp/ggo-kea-dhcp-new
	@LOCAL=$$(sha256sum ggo-kea-dhcp-arm64 | cut -d' ' -f1); \
	REMOTE=$$(ssh $(DEPLOY_USER)@$(DEPLOY_HOST) ' \
		sudo install -o root -g root -m 0755 /tmp/ggo-kea-dhcp-new /usr/bin/ggo-kea-dhcp && \
		sudo systemctl restart ggo-kea-dhcp && \
		rm -f /tmp/ggo-kea-dhcp-new && \
		systemctl is-active ggo-kea-dhcp >/dev/null && \
		sha256sum /usr/bin/ggo-kea-dhcp | cut -d" " -f1'); \
	if [ "$$LOCAL" = "$$REMOTE" ]; then \
		echo "deploy OK: $$REMOTE (service active)"; \
	else \
		echo "deploy FAILED: local=$$LOCAL remote=$$REMOTE (mismatch or service down)"; exit 1; \
	fi

# Cut a release: bump version.go to VERSION, commit, tag vVERSION, push. Pushing
# the tag triggers .github/workflows/release.yml (which re-checks the tag matches
# version.go). Releases come from main with a clean tree. Usage:
#   make release VERSION=1.2.3
release:
	@test -n "$(VERSION)" || { echo "usage: make release VERSION=X.Y.Z"; exit 1; }
	@echo "$(VERSION)" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$$' || { echo "VERSION must be X.Y.Z (got '$(VERSION)')"; exit 1; }
	@test "$$(git rev-parse --abbrev-ref HEAD)" = "main" || { echo "release from main, not $$(git rev-parse --abbrev-ref HEAD)"; exit 1; }
	@git diff --quiet && git diff --cached --quiet || { echo "working tree dirty - commit or stash first"; exit 1; }
	$(MAKE) check
	sed -i 's/Number = ".*"/Number = "$(VERSION)"/' internal/version/version.go
	git add internal/version/version.go
	git commit -m "release: v$(VERSION)"
	git tag v$(VERSION)
	git push origin main v$(VERSION)
