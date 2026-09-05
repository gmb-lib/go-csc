// Package lvrtc is the profile of the eParaksts remote-signing service operated by
// LVRTC (Latvia), whose CSC layer runs on TrustedX and declares CSC API 2.0.0.2.
//
// Everything here is what that provider does where the specification leaves room
// or where it departs from it, as its integration guide describes and as measured
// against its pre-production instance. The core stays untouched: a caller uses the
// csc package with Profile and the values below, and this package reads the
// provider's own authorization_details vocabulary out of the token responses.
//
// The flow this provider documents is two authorizations, both pushed (PAR) and
// both confirmed by the person in the browser:
//
//  1. scope=credential + signatureQualifier=eu_eidas_qes + the eID flow → a token
//     that names a new SHORT-TERM credential (credentialID); its certificate is
//     valid for about fifteen minutes;
//  2. scope=credential + credentialID + numSignatures + hashes + hashAlgorithmOID →
//     a token bound to those digests; that token is the Bearer of signHash.
//
// There is no service-scope authorization and no SAD; hashAlgorithmOID is always
// sent; the authorize `hashes` parameter is standard Base64 in the guide (the
// specification says base64url — the profile follows the guide until measured
// otherwise). Access tokens live 120 s, a request_uri 60 s.
package lvrtc

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/gmb-lib/go-csc"
)

// Service base URIs (CSC v2 base, no trailing slash).
const (
	BaseURIPREP = "https://eidas-demo.eparaksts.lv/trustedx-resources/csc/v2"
	BaseURIPROD = "https://eidas.eparaksts.lv/trustedx-resources/csc/v2"
)

// Profile is the provider's set of choices.
var Profile = csc.Profile{
	Name:                       "LVRTC eParaksts CSC (TrustedX; declares CSC 2.0.0.2)",
	HashesEncoding:             csc.Base64Std,
	AlwaysSendHashAlgorithmOID: true,
	RequirePAR:                 true,
	RequestURILifetime:         60 * time.Second,
	TokenLifetime:              120 * time.Second,
}

// The qualifier and the algorithm OIDs the provider's profile uses: a P-384 key,
// SHA-384 digests, ECDSA-with-SHA-384 signatures. The credential's own key.algo is
// the final word on signAlgo.
const (
	SignatureQualifierQES  = "eu_eidas_qes"
	HashAlgorithmOIDSHA384 = "2.16.840.1.101.3.4.2.2"
	SignAlgoECDSASHA384    = "1.2.840.10045.4.3.3"
	CurveOIDSecp384r1      = "1.3.132.0.34"
)

// EIDFlow is one of the provider's user-authentication flows, selected with the
// OAuth acr_values parameter.
type EIDFlow string

const (
	// CardOnComputer is the eID card in a reader with the eID software.
	CardOnComputer EIDFlow = "urn:eparaksts:authentication:flow:sc_plugin"
	// EIDScan is the eID card read by a phone with the eID Scan app.
	EIDScan EIDFlow = "urn:eparaksts:authentication:flow:mobile-eid"
)

// EIDFlows is the user-authentication half of an authorization request for this
// provider: one or more flows, joined with "|" in acr_values. Empty lets the
// authorization server show its own chooser.
type EIDFlows []EIDFlow

// ApplyTo implements csc.UserAuthentication.
func (f EIDFlows) ApplyTo(v url.Values) {
	if len(f) == 0 {
		return
	}
	parts := make([]string, len(f))
	for i, x := range f {
		parts[i] = string(x)
	}
	v.Set("acr_values", strings.Join(parts, "|"))
}

// CredentialRequest is the first authorization: a short-term signing credential
// for the authenticated person.
func CredentialRequest(redirectURI, state string, pkce csc.PKCE, flows EIDFlows) csc.AuthorizationRequest {
	return csc.AuthorizationRequest{
		RedirectURI: redirectURI,
		State:       state,
		PKCE:        pkce,
		Scope:       "credential",
		Credential:  &csc.CredentialAuthorization{SignatureQualifier: SignatureQualifierQES},
		User:        flows,
	}
}

// SigningRequest is the second authorization: the credential bound to the digests
// about to be signed.
func SigningRequest(redirectURI, state string, pkce csc.PKCE, flows EIDFlows, credentialID string, digests [][]byte, hashAlgorithmOID string) csc.AuthorizationRequest {
	return csc.AuthorizationRequest{
		RedirectURI: redirectURI,
		State:       state,
		PKCE:        pkce,
		Scope:       "credential",
		Credential: &csc.CredentialAuthorization{
			CredentialID:     credentialID,
			NumSignatures:    len(digests),
			Hashes:           digests,
			HashAlgorithmOID: hashAlgorithmOID,
		},
		User: flows,
	}
}

// --- the provider's authorization_details vocabulary -------------------------

// SignIdentityRegistration is the authorization_details entry the first token
// carries: the credential was registered for the qualifier groups listed.
type SignIdentityRegistration struct {
	Type        string   `json:"type"`
	GroupLabels []string `json:"group_labels"`
}

// Digest is one entry of DigestSigning.Digests: the authorized digest (Base64) and
// the name of its algorithm ("SHA-384").
type Digest struct {
	Value     string `json:"value"`
	Algorithm string `json:"algorithm"`
}

// DigestSigning is the authorization_details entry the second token carries: the
// digests the person confirmed, the credential, and how many signatures.
type DigestSigning struct {
	Type           string   `json:"type"`
	Digests        []Digest `json:"digests"`
	SignIdentityID string   `json:"sign_identity_id"`
	NumSignatures  int      `json:"num_signatures"`
}

// Types of the two entries.
const (
	TypeSignIdentityRegistration = "sign_identity_registration"
	TypeDigestSigning            = "digest_signing"
)

// ErrNoDetails is returned when a token carries no authorization_details entry of
// the type asked for.
var ErrNoDetails = errors.New("lvrtc: token carries no authorization_details of that type")

// Registration reads the sign_identity_registration entry out of a token response.
func Registration(tok csc.TokenResponse) (SignIdentityRegistration, error) {
	var out SignIdentityRegistration
	found, err := pick(tok.AuthorizationDetails, TypeSignIdentityRegistration, &out)
	if err != nil {
		return out, err
	}
	if !found {
		return out, ErrNoDetails
	}
	return out, nil
}

// Signing reads the digest_signing entry out of a token response.
func Signing(tok csc.TokenResponse) (DigestSigning, error) {
	var out DigestSigning
	found, err := pick(tok.AuthorizationDetails, TypeDigestSigning, &out)
	if err != nil {
		return out, err
	}
	if !found {
		return out, ErrNoDetails
	}
	return out, nil
}

func pick(raw json.RawMessage, typ string, out any) (bool, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return false, nil
	}
	var entries []json.RawMessage
	if err := json.Unmarshal(raw, &entries); err != nil {
		return false, fmt.Errorf("lvrtc: authorization_details is not an array: %w", err)
	}
	for _, e := range entries {
		var head struct {
			Type string `json:"type"`
		}
		if json.Unmarshal(e, &head) == nil && head.Type == typ {
			return true, json.Unmarshal(e, out)
		}
	}
	return false, nil
}

// ErrNotBound is returned by Bound when the token is not bound to what the caller
// is about to sign.
var ErrNotBound = errors.New("lvrtc: the sign token is not bound to these digests")

// Bound checks the guide's rule for the integrator: before signHash, the token's
// digests, credential and count must be exactly what the person confirmed. It
// returns nil when the digest_signing entry names credentialID, exactly len(digests)
// signatures, and every digest (in either Base64 alphabet).
func Bound(ds DigestSigning, credentialID string, digests [][]byte) error {
	if ds.SignIdentityID != credentialID {
		return fmt.Errorf("%w: sign_identity_id %q, credential %q", ErrNotBound, ds.SignIdentityID, credentialID)
	}
	if ds.NumSignatures != len(digests) {
		return fmt.Errorf("%w: num_signatures %d, digests %d", ErrNotBound, ds.NumSignatures, len(digests))
	}
	if len(ds.Digests) != len(digests) {
		return fmt.Errorf("%w: %d digests in the token, %d to sign", ErrNotBound, len(ds.Digests), len(digests))
	}
	for i, d := range digests {
		std := base64.StdEncoding.EncodeToString(d)
		raw := base64.RawURLEncoding.EncodeToString(d)
		if ds.Digests[i].Value != std && ds.Digests[i].Value != raw {
			return fmt.Errorf("%w: digest %d differs", ErrNotBound, i)
		}
	}
	return nil
}
