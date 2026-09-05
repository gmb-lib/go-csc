# Contributing

Thank you for considering a contribution. Bug reports, fixes and improvements are welcome. For
anything that could be exploited, use the private route in [SECURITY.md](SECURITY.md) — never a
public issue.

For anything larger than a small fix, please open an issue first and describe what you want to
change and why. It protects your time: a change that fights the library's design is better
redirected before it is written than after.

## Building and testing

You need the Go toolchain at the version named in [go.mod](go.mod). The gate a change must pass is
the same one CI runs:

```sh
go build ./...
go vet ./...
go test -race -count=1 ./...
```

Three more checks run in CI and are worth running before you push:

- **Lint** — `golangci-lint run`, at the version pinned in
  [.github/workflows/ci.yml](.github/workflows/ci.yml); the repo's [.golangci.yml](.golangci.yml)
  carries the configuration.
- **Vulnerabilities** — `go run golang.org/x/vuln/cmd/govulncheck@latest ./...`.
- **Fuzz** — every `Fuzz*` target runs for 30 seconds. The response parsers are the place for fuzz
  targets, because they read bytes a remote service produced; a change to parsing should extend them
  rather than work around them.

The committed tree must already be tidy: CI runs `go mod tidy -diff` and fails if it would change
anything, so run `go mod tidy` after touching dependencies. All Go code is `gofmt`-formatted, and
`.gitattributes` pins Go files to LF line endings — leave that alone, it keeps the tidy-diff gate
stable across platforms.

## What a change to this library needs

This library has one job: send exactly what the Cloud Signature Consortium API specification says,
and read exactly what it says comes back. Every request field and every response field is pinned to
its clause in the specification by a test, and a provider's departure from the specification lives in
a **profile**, never in the core. So:

- A change to a request or response type needs the clause it implements named in the test that
  asserts it, and the test must fail without the change.
- Provider-specific behaviour — a required field the specification makes optional, an extra
  parameter, a vendor vocabulary in `authorization_details`, a lifetime — goes into that provider's
  profile package. If you find yourself adding a provider's habit to the core, stop and open an issue.
- Nothing here logs, stores or prints an access token, a client secret or an authorization code.
  A test that needs one builds it at run time from its parts; a literal secret-shaped value in the
  tree fails the repository's secret scan.

## Sign-off

Every commit carries a `Signed-off-by:` line (`git commit -s`) as the Developer Certificate of Origin
attestation; CI checks it on pull requests.
