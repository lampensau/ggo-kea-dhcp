# ggo-kea-dhcp - build helpers.
#
# IMPORTANT: every target regenerates templ components first. Editing a *.templ
# file and running a bare `go build` will NOT pick up the change - `go build`
# compiles the already-generated *_templ.go. Always go through these targets
# (or run `templ generate` yourself before building).

TEMPL ?= $(shell go env GOPATH)/bin/templ
NFPM  ?= $(shell go env GOPATH)/bin/nfpm
GOFLAGS_VENDOR := -mod=vendor

# Version stamped into the .deb. Defaults to the single source of truth in
# internal/version/version.go (const Number), so a bare `make deb` is correctly
# versioned. Override only for a one-off (the release workflow passes the git tag).
GGO_VERSION ?= $(shell sed -n 's/.*Number = "\(.*\)".*/\1/p' internal/version/version.go)

# Live-deploy target (make deploy). Override host/user as needed:
#   make deploy DEPLOY_HOST=10.10.0.1 DEPLOY_USER=timo
DEPLOY_HOST ?= 10.0.0.1
DEPLOY_USER ?= timo

.PHONY: generate build vet test all pi deb deploy release

generate:
	$(TEMPL) generate

build: generate
	go build $(GOFLAGS_VENDOR) .

vet: generate
	go vet $(GOFLAGS_VENDOR) ./...

test: generate
	go test $(GOFLAGS_VENDOR) ./...

all: generate build vet test

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
	sed -i 's/Number = ".*"/Number = "$(VERSION)"/' internal/version/version.go
	git add internal/version/version.go
	git commit -m "release: v$(VERSION)"
	git tag v$(VERSION)
	git push origin main v$(VERSION)
