# Development

## Setup

Go 1.26 or later is required (`go.mod`).

```bash
git clone https://github.com/davidgroves/rndc-go.git
cd rndc-go
go mod download
```

## Building

```bash
make build
# or
go build -o rndc-go ./cmd/rndc-go
```

### Versioning (git tags)

CLI version comes from `runtime/debug.ReadBuildInfo()` when installed with a module version (`go install …@vX.Y.Z`). Release binaries from GoReleaser inject the tag via `-ldflags "-X main.version=…"`.

Release tags should look like `v0.1.0`.

## Testing

Unit tests (no Docker):

```bash
make test
# or
go test ./...
```

Integration tests against ISC BIND 9.20 in Docker (testcontainers):

```bash
make test-integration
# or
go test -tags integration ./...
```

The BIND configuration is in [testdata/named.conf](testdata/named.conf).

Coverage HTML (not enforced in CI):

```bash
make cover
```

## Code quality

```bash
make fmt
make lint   # golangci-lint v2.14+
```

### Pre-commit hooks

Install [pre-commit](https://pre-commit.com/), then enable the git hooks. Commits fail unless golangci-lint formatting, golangci-lint, and `go test -race` all pass.

```bash
pipx install pre-commit   # or: pip install pre-commit
pre-commit install
```

Run every hook against the tree:

```bash
make pre-commit
# or
pre-commit run --all-files
```

Hooks and CI use [golangci-lint](https://golangci-lint.run/) **v2.14.0**, which typechecks Go 1.27. `gofumpt` is applied via `golangci-lint fmt`.

## Releasing

Pushing a tag matching `v*` runs [`.github/workflows/release.yml`](.github/workflows/release.yml) with GoReleaser (archives plus a GitHub Release). Consumers of the library use:

```bash
go get github.com/davidgroves/rndc-go@vX.Y.Z
```
