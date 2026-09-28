# go-csc

A Go client for remote signing services that implement the **Cloud Signature Consortium (CSC) API,
version 2** — the protocol a signing application uses to have a qualified electronic signature created
on a key that a trust service provider holds for the signer. Written to the specification's text
(CSC API v2.2.0.0 with the CSC data model v1.0.0), field by field, with a test pinning each field to
its clause.

```
go get github.com/gmb-lib/go-csc
```

See [`CHANGELOG.md`](./CHANGELOG.md) for what each release changed, and what it means for code that
already uses this library, before you bump.

Standard library only. No logging, no storage, no key material: the library sends requests, reads
answers, and hands the caller typed values.

## Three layers

**The core** (`package csc`) is the API as the specification writes it: `info`, `oauth2/pushed_authorize`,
`oauth2/authorize`, `oauth2/token`, `credentials/list`, `credentials/info`, `signatures/signHash`. Request
and response types carry the specification's member names. Members the specification defines are typed;
what a provider adds beyond it (`authorization_details` vocabularies) is kept raw for a profile to read.

**A profile** (`csc.Profile`) is the handful of choices a provider makes where the specification leaves
room, or where the provider departs from it: which Base64 alphabet the authorize `hashes` parameter
uses, whether `hashAlgorithmOID` is always sent to `signHash`, whether authorization requests must be
pushed, what the lifetimes are. `csc.Specification` is the text itself. A provider's profile lives in its
own package and is the only place its habits go — the core never learns them.

**User authentication** (`csc.UserAuthentication`) is how the person is authenticated during an
authorization: an eID card selected through `acr_values`, a mobile app, a wallet. The specification
leaves this to the authorization server, so the caller supplies it as a value that adds its parameters
to the request.

## The flow

```go
c := &csc.Client{BaseURI: lvrtc.BaseURIPREP, ClientID: id, ClientSecret: secret, Profile: lvrtc.Profile}

// 1. A short-term signing credential for the authenticated person.
pkce, _ := csc.NewPKCE()
state, _ := csc.NewState()
par, err := c.PushedAuthorize(ctx, lvrtc.CredentialRequest(redirectURI, state, pkce, lvrtc.EIDFlows{lvrtc.CardOnComputer}))
// send the browser to c.AuthorizeURL(par) — before par.ExpiresAt(); receive code + state on redirectURI
tok, err := c.Token(ctx, code, redirectURI, pkce.Verifier)          // tok.CredentialID names the new credential
cred, err := c.CredentialsInfo(ctx, tok.AccessToken, csc.CredentialsInfoRequest{CredentialID: tok.CredentialID, CertInfo: true, AuthInfo: true})
err = cred.CheckSigning(len(digests), time.Now().Add(2*time.Minute)) // key enabled, multisign, and still valid when the signing lands
algo, err := cred.SignAlgoFor(lvrtc.HashAlgorithmOIDSHA384)           // signAlgo from the credential's key/algo

// 2. Authorize exactly these digests, then sign them — inside the token's lifetime.
pkce2, _ := csc.NewPKCE()
state2, _ := csc.NewState()
par2, err := c.PushedAuthorize(ctx, lvrtc.SigningRequest(redirectURI, state2, pkce2, lvrtc.EIDFlows{lvrtc.CardOnComputer}, cred.CredentialID, digests, lvrtc.HashAlgorithmOIDSHA384))
// browser again; the person confirms the signature
sign, err := c.Token(ctx, code2, redirectURI, pkce2.Verifier)
ds, err := lvrtc.Signing(sign)                                      // the provider's digest_signing entry
if err := lvrtc.Bound(ds, cred.CredentialID, digests); err != nil { /* refuse: not what the person confirmed */ }
out, err := c.SignHash(ctx, sign.AccessToken, csc.SignHashRequest{CredentialID: cred.CredentialID, Hashes: digests, HashAlgorithmOID: lvrtc.HashAlgorithmOIDSHA384, SignAlgo: algo})
sig, err := out.Signature(0)
cert, err := cred.Certificate()
err = csc.VerifySignature(cert, algo, lvrtc.HashAlgorithmOIDSHA384, digests[0], sig) // before the value goes anywhere
```

A refused `signHash` is not retried on the same token: with this provider the refusal spends the
person's confirmation, and signing again takes a new second authorization.

With `csc.Specification` instead of a provider profile the same calls speak the plain text of the
standard: base64url `hashes` on the authorize parameter, `hashAlgorithmOID` omitted when `signAlgo`
implies the hash, the classic `AuthorizeURLClassic` available beside the pushed one.

## Profiles

| Package | Provider | What it fixes |
|---|---|---|
| `lvrtc` | eParaksts (LVRTC, Latvia) — TrustedX CSC layer, declares CSC 2.0.0.2 | PAR-only entry · the eID card and eID Scan as the two user flows (`acr_values`) · `scope=credential` + `signatureQualifier=eu_eidas_qes` for a short-term credential, valid 15 minutes from its first registration and reused inside them · a second, hash-bound authorization · the sign token as the `signHash` Bearer, no SAD, single-use and spent by a refusal · `hashAlgorithmOID` always · standard-Base64 `hashes` (base64url is refused) · 60 s `request_uri`, 600 s tokens · DER ECDSA P-384 signatures · the `sign_identity_registration` / `digest_signing` vocabulary and `Bound`, the check the provider requires before `signHash` · the error codes it answers with |

A profile is a value plus a few readers; adding a provider means adding a package, never editing the core.
The `lvrtc` values were measured against the provider's pre-production service; its integration guide
fills in only what a measurement could not observe.

## Before and after `signHash`

The core also carries the checks a signing application owes around the call, because every CSC
integration owes them and none of them is provider-specific:

- `Credential.CheckSigning(n, at)` — the key is enabled, the certificate valid (when the service says
  so), `n` does not exceed `multisign`, and the moment `at` is inside the certificate's validity.
- `Credential.SignAlgoFor(hashOID)` — the `signAlgo` for that digest, chosen from the credential's own
  `key/algo` list, never guessed.
- `VerifySignature(cert, signAlgo, hashOID, digest, signature)` — the returned value is a signature by
  the credential's key over the digest that was sent (ECDSA as DER or raw r‖s, RSA PKCS #1 v1.5).

## Errors

A non-2xx answer is a `*csc.Error` with the HTTP status and the specification's `error` /
`error_description` members when the body is JSON; a body that is not JSON keeps its bytes. Errors
never carry the client secret, a token or an authorization code. `ErrNoAccessToken` and
`ErrSignatureCount` name the two answers that are 2xx and still wrong.

## Scope / non-goals

- No container assembly — embed the verified signature with the tools that own that step.
- No token storage, no refresh loop, no browser: the caller owns the redirect and the clocks
  (`PushedAuthorization.ExpiresAt`, `TokenResponse.ExpiresAt` say when they run out).
- `signatures/signDoc`, `credentials/authorize` (explicit SAD), `extendTransaction`, asynchronous
  polling and timestamps are not implemented; a provider that offers them is a reason to add them
  to the core, with their clauses.

## Contributing

Bug reports and pull requests are welcome. [CONTRIBUTING.md](CONTRIBUTING.md) names the gate a
change has to pass, what a change to this library needs, and the sign-off every commit carries.

Suspected vulnerabilities go through the private route in [SECURITY.md](SECURITY.md) — never a
public issue.

## License

MIT — see [LICENSE](./LICENSE).
