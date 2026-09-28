# Changelog

All notable changes to this library are recorded here, newest first. Versions are git tags; the
library follows semantic versioning once it reaches `v1.0.0`.

## v0.2.0

The `lvrtc` profile now describes what the eParaksts CSC service **does**, measured end to end on its
pre-production instance (a real eID card and eID Scan, a signed document validated by the provider),
rather than what its integration guide says. The core gains the checks a signing application owes around
`signHash`. Nothing existing was removed or renamed; one value changed.

### Added

- **`Credential.CheckSigning(numSignatures, at)`** — refuses a credential whose key is not enabled, whose
  certificate the service reports as not valid, whose `multisign` is lower than the signatures asked for,
  or whose certificate is not valid at the moment `at`. Pass a moment in the future when a second
  authorization is still to come.
- **`Credential.SignAlgoFor(hashAlgorithmOID)`** — the `signAlgo` for `signHash`, chosen from the
  credential's own `key/algo` list: the algorithm that names the digest when one is listed, otherwise the
  bare key algorithm, with the digest then carried by `hashAlgorithmOID`.
- **`VerifySignature(cert, signAlgo, hashAlgorithmOID, digest, signature)`** — checks a returned value
  is a signature by the credential's key over the digest that was sent. ECDSA is accepted DER-encoded or
  as raw r‖s; RSA is PKCS #1 v1.5; anything else is reported as unsupported, never as valid.
- **`Credential.Certificate()`** (the parsed end-entity certificate), **`DigestLength(oid)`**, and the OID
  constants for SHA-256/384/512 and the ECDSA and RSA signature algorithms built on them.
- **`lvrtc.CredentialLifetime`** (15 minutes) and the **error codes** the service answers with
  (`invalid_authorization_details`, `invalidSad`, `invalidCredentialId`,
  `InsufficientPrivilegesException`).

```go
cred, _ := c.CredentialsInfo(ctx, tok.AccessToken, csc.CredentialsInfoRequest{CredentialID: tok.CredentialID, Certificates: csc.CertificatesSingle})
if err := cred.CheckSigning(len(digests), time.Now().Add(2*time.Minute)); err != nil { /* start again later */ }
algo, _ := cred.SignAlgoFor(csc.OIDSHA384) // "1.2.840.10045.4.3.3" for the provider's P-384 key
// … the second authorization, then signHash with SignAlgo: algo …
cert, _ := cred.Certificate()
err := csc.VerifySignature(cert, algo, csc.OIDSHA384, digests[0], sig)
```

### Changed

- **`lvrtc.Profile.TokenLifetime` is 600 s** (was 120 s, the guide's figure): both token responses say
  `expires_in` 600. The value is informational, as before; `TokenResponse.ExpiresAt` reads what the
  service returns.
- `lvrtc.HashAlgorithmOIDSHA384` and `lvrtc.SignAlgoECDSASHA384` are now the core's constants; the values
  are the same.

### What the measurements settled (the `lvrtc` package comment carries them)

- The authorize `hashes` are standard Base64 only; base64url is refused before the person sees a login.
- A short-term credential is **reused** inside its 15 minutes, which count from its first registration,
  so a second signing in that window can meet a certificate close to expiry — `CheckSigning` is the guard.
- The sign token is single-use, and a **refused `signHash` spends it**: never retry on the same token.
- Signatures are DER ECDSA over P-384 and verify against the credential's certificate.

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
