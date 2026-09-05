# Security policy

This library is a client for remote signing services that speak the Cloud Signature Consortium
(CSC) API. It carries OAuth client credentials and short-lived access tokens on behalf of its caller,
sends document digests to be signed under a person's sole control, and returns signature values the
caller embeds into signed documents. A defect here can leak a credential, sign a digest the person did
not approve, or accept a signature that does not belong to the credential. Please report security
problems privately. Do not open a public issue, pull request or discussion for anything that could be
exploited before a fix exists.

## How to report

Use **[private vulnerability reporting](https://github.com/gmb-lib/go-csc/security/advisories/new)**
on this repository. The report stays visible only to you and the maintainers until an advisory is
published. Please include the library version (or commit), the profile in use, what you sent, what came
back, and what you expected — a failing test is the best report of all.

You will get an acknowledgement within a few working days. Fixes ship as a new tag and the advisory
credits the reporter unless they ask otherwise.

## What counts

- A token, secret or authorization code written to a log, an error message or a returned value where
  the caller did not ask for it.
- A request sent to a host the caller did not configure, or over a connection the caller did not
  configure (this library never downgrades TLS and never follows a redirect on a token endpoint).
- A `signHash` call made with an authorization that was not bound to the digests being signed when
  the profile says it must be (the SCAL 2 rule).
- A response accepted without the checks the specification or the profile requires — a signature
  count that does not match the hashes, a credential whose certificate is not the one the token
  authorized.

## What does not count

- Behaviour of a remote signing service itself. Report that to its operator; if you believe this
  library should refuse the behaviour, open an issue.
- Findings that require a compromised caller process or a modified copy of the library.

## Supported versions

The latest tag. Older tags receive fixes only when a caller cannot move.
