# Contributing

Bug reports, focused pull requests and good issue reproductions are all welcome. This page covers the mechanics; `internal/web/DESIGN.md` holds the web UI's design system and conventions.

## Development setup

You need the Go toolchain (version per `go.mod`) and the [templ](https://github.com/a-h/templ) CLI (the exact version CI uses is pinned in `.github/workflows/`). For packaging work you also need [nfpm](https://github.com/goreleaser/nfpm). All dependencies are vendored; every Go command takes `-mod=vendor`.

The appliance targets a Raspberry Pi. The development loop is: build and unit-test locally, deploy to a Pi for live verification. The binary runs on a dev machine too - system tools it cannot find (`nmcli`, `kea-dhcp4`, ...) log `[Dev Mode]` and no-op, so the web UI is explorable without appliance hardware:

```sh
./ggo-kea-dhcp --bind 127.0.0.1:8080 --db ./appliance.db
```

## The Makefile

Every target regenerates the templ components first. This is the one build rule that bites people:

> [!WARNING]
> After editing a `.templ` file, a bare `go build` silently compiles the stale generated `*_templ.go` and your change does not exist. Always build through `make` (or run `templ generate` yourself first).

| Target | What it does | When you use it |
| --- | --- | --- |
| `make generate` | Runs `templ generate` alone | Rarely by hand; every other target calls it |
| `make build` | Generate + native `go build` | The normal edit-compile loop |
| `make vet` | Generate + `go vet` on all packages | Quick static check |
| `make test` | Generate + `go test -race` with coverage written to `coverage.txt` | Before every push |
| `make all` | build + vet + test in one go | A fuller local gate |
| `make check` | Mirrors every CI gate: committed templ output, gofmt, vendor in sync (`go mod verify` + `vendor/` diff), vet, race tests, the coverage threshold, native and arm64 builds, golangci-lint, shellcheck | Before opening a PR; if this is green, CI will be |
| `make cover-gate` | Enforces the total-coverage threshold on an existing `coverage.txt` | Called by `check` and CI; standalone after `make test` |
| `make pi` | Cross-compiles the arm64 binary (`ggo-kea-dhcp-arm64`, static, CGO off) | Anything that ends up on a Pi |
| `make deb` | `pi` + builds the installable `.deb` into `dist/` via nfpm, stamped with the version from `internal/version/version.go` | Testing the packaged install path |
| `make deploy` | `pi` + copies the binary to a test Pi over SSH, installs it, restarts the service and verifies the running checksum. Host/user via `DEPLOY_HOST`/`DEPLOY_USER` | The live-verification loop against real hardware |
| `make release VERSION=X.Y.Z` | Guarded release cut: requires `main`, a clean tree and a green `make check`; bumps `version.go`, commits, tags `vX.Y.Z` and pushes. The tag push triggers the release workflow, which independently re-checks that tag and version match | Cutting a release |

Variables worth knowing: `GGO_VERSION` (the `.deb` version, defaulting to `version.go` - override only for one-offs) and `DEPLOY_HOST`/`DEPLOY_USER` for `make deploy`.

## UI changes

Read `internal/web/DESIGN.md` first; every page is held to it. The stack is templ + Datastar + SSE with all assets embedded - no client frameworks, nothing fetched at runtime. Include a screenshot in PRs that change the UI.

## Conventions

- Plain hyphens, never em-dashes, in comments, strings and docs
- Small, focused PRs over large mixed ones
- Commit messages: short and precise, no prose
- Files named `_preview_*.html` under `internal/web/static/` are throwaway render-preview artifacts; never commit them

## Packaging and releases

The `.deb` is built with nfpm from `packaging/nfpm.yaml`; the runtime pieces it installs (systemd unit, Caddyfile, sudoers drop-in, apt pin) live under `packaging/`. Releases are cut with `make release`, published by CI on the `v*` tag. See `docs/install.md` for how the released artifact is consumed.

## Security issues

Do not open public issues for vulnerabilities; use the process in [SECURITY.md](.github/SECURITY.md).
