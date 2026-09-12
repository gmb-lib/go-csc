# Changelog

All notable changes to this library are recorded here, newest first. Versions are git tags; the
library follows semantic versioning once it reaches `v1.0.0`.

## v0.1.1

No library code changed since v0.1.0, so nothing this library does behaves differently. There is
one thing to act on before you bump: **it now needs Go 1.27**.

### Changed

- **The module declares `go 1.27.0`** (was `1.26.6`), so your own module has to be on Go 1.27
  before it can build against this one. A dependency's `go` line does **not** make the go command
  fetch a newer toolchain for you — measured both ways: a consumer whose own `go` directive is
  lower stops with a `requires go >= 1.27.0 (running go 1.26.6)` error, and it stops there with
  `GOTOOLCHAIN` on its `auto` default just as it does under `local`. Raise your own `go` directive
  to `1.27.0` first; from there the go command downloads and uses the 1.27 toolchain by itself, so
  nobody has to install Go by hand. CI that reads `go-version-file: go.mod` follows the bump with
  no workflow edit — a workflow naming a Go version in the YAML needs that line changed.

  This library still has **no module dependencies at all**: the standard library is the whole
  dependency surface, as it has been since v0.1.0.

### Notes

- The gate is green on Go 1.27: `go mod verify`, `go mod tidy -diff`, build, vet, `gofmt`, and
  `go test -race` across both packages with **0 races**; `govulncheck` finds nothing.

## v0.1.0

Initial code.
