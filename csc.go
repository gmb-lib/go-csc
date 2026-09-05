// Package csc is a client for remote signing services that implement the Cloud
// Signature Consortium (CSC) API, version 2 — "Architectures and protocols for
// remote signature applications".
//
// The package has three layers, and keeping them apart is its whole design:
//
//   - The core: the API methods as the specification writes them — info,
//     oauth2/pushed_authorize, oauth2/authorize, oauth2/token, credentials/list,
//     credentials/info, signatures/signHash — with request and response types whose
//     fields carry the specification's names. Every field is pinned to its clause by
//     a test. The core sends nothing the specification does not name and reads
//     nothing it does not define; unknown response members are kept raw where a
//     caller may need them (authorization_details).
//   - A Profile: the handful of choices a particular provider makes where the
//     specification leaves room, or departs from it — which Base64 alphabet the
//     authorize `hashes` use, whether hashAlgorithmOID is always sent, whether the
//     authorization request must be pushed, what the lifetimes are. The
//     Specification profile is the text itself; a provider's profile lives in its
//     own package (see the lvrtc package) and is the only place provider habits go.
//   - UserAuthentication: how the user-authentication half of an authorization
//     request is shaped. The specification leaves that to the authorization server
//     (an eID card, a mobile app, a wallet); the caller supplies it as a value that
//     adds its parameters to the request. The core never guesses it.
//
// The flow a caller runs, in the specification's order:
//
//	pkce, _ := csc.NewPKCE()
//	par, _ := c.PushedAuthorize(ctx, csc.AuthorizationRequest{...})   // or AuthorizeURL for the classic entry
//	// send the user to c.AuthorizeURL(par); receive code + state on the redirect URI
//	tok, _ := c.Token(ctx, code, redirectURI, pkce.Verifier)
//	cred, _ := c.CredentialsInfo(ctx, tok.AccessToken, csc.CredentialsInfoRequest{CredentialID: tok.CredentialID})
//	sig, _ := c.SignHash(ctx, tok.AccessToken, csc.SignHashRequest{...})
//
// Nothing here logs, stores or prints a client secret, an access token or an
// authorization code; errors carry the service's error body and status, never the
// request that produced them.
package csc

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Version is the edition of the CSC API this core is written to.
const Version = "2.2.0.0"

// Encoding names a Base64 alphabet, [IETF RFC 4648 §4] (standard, padded) or [IETF RFC 4648 §5] (URL-safe, unpadded).
type Encoding int

const (
	// Base64URL is what the specification requires for the authorize `hashes` parameter ([CSC API §8.2.2]).
	Base64URL Encoding = iota
	// Base64Std is what the specification requires for the signHash `hashes` body member ([CSC API §11.13]),
	// and what some providers also accept or require on the authorize parameter.
	Base64Std
)

// Encode returns b in the alphabet.
func (e Encoding) Encode(b []byte) string {
	if e == Base64Std {
		return base64.StdEncoding.EncodeToString(b)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func (e Encoding) String() string {
	if e == Base64Std {
		return "base64"
	}
	return "base64url"
}

// Profile is the set of choices a provider makes where the specification leaves
// room, or where it departs from the specification. The zero value is not a
// profile; use Specification or a provider package's value.
type Profile struct {
	// Name identifies the profile in errors and diagnostics.
	Name string
	// HashesEncoding is the alphabet of the authorize / pushed_authorize `hashes`
	// parameter. The specification says base64url ([CSC API §8.2.2]).
	HashesEncoding Encoding
	// AlwaysSendHashAlgorithmOID sends signHash's hashAlgorithmOID even when signAlgo
	// implies the hash algorithm. The specification lets it be omitted then ([CSC API §11.13]);
	// a provider may require it.
	AlwaysSendHashAlgorithmOID bool
	// RequirePAR means the provider documents oauth2/pushed_authorize as the only
	// entry into authorization. The core still offers the classic URL; a caller
	// following the profile uses PushedAuthorize.
	RequirePAR bool
	// RequestURILifetime and TokenLifetime are the provider's documented lifetimes,
	// informational — the values the service actually returns (expires_in) win.
	RequestURILifetime time.Duration
	TokenLifetime      time.Duration
}

// Specification is the profile of the text itself: no departures.
var Specification = Profile{
	Name:           "CSC API v" + Version,
	HashesEncoding: Base64URL,
}

// Client speaks CSC API v2 to one remote service.
type Client struct {
	// BaseURI is the remote service base URI; the specification says it ends with
	// "/csc/v2" ([CSC API §7.2]). No trailing slash.
	BaseURI string
	// OAuthBase is the base of the OAuth 2.0 endpoints when the service publishes
	// them elsewhere (info.oauth2, [CSC API §7.2] / [CSC API §11.1]). Empty means BaseURI.
	OAuthBase string
	// ClientID and ClientSecret authenticate the application at the token and
	// pushed-authorization endpoints with HTTP Basic ([CSC API §8.2.3], [CSC API §8.2.4]).
	ClientID     string
	ClientSecret string
	// HTTP is the transport. nil means a client with a 30 s timeout that never
	// follows redirects — a redirect answer's Location is data, not a next hop.
	HTTP *http.Client
	// Profile is the provider's set of choices. Zero-valued Name means Specification.
	Profile Profile
}

// UserAuthentication shapes the user-authentication half of an authorization
// request: the parameters that tell the authorization server how the person is to
// be authenticated (an eID card via acr_values, a wallet via OpenID4VP details, …).
// The specification leaves this to the authorization server, so the core takes it
// as a value and adds whatever it contributes.
type UserAuthentication interface {
	ApplyTo(v url.Values)
}

// PKCE is a Proof Key for Code Exchange pair (RFC 7636), method S256 ([CSC API §8.2.2]).
type PKCE struct {
	Verifier  string
	Challenge string
}

// NewPKCE returns a fresh pair: a 43-character base64url verifier of 32 random
// bytes and its S256 challenge.
func NewPKCE() (PKCE, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return PKCE{}, err
	}
	verifier := base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(verifier))
	return PKCE{Verifier: verifier, Challenge: base64.RawURLEncoding.EncodeToString(sum[:])}, nil
}

// NewState returns a random base64url state value for an authorization request.
func NewState() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// --- errors ------------------------------------------------------------------

// Error is a non-2xx answer from the service. The specification says an error
// body is JSON with "error" and an optional "error_description" ([CSC API §10.1]); a body
// that is not that (an HTML page, an empty body) leaves Code empty and keeps the
// bytes in Body.
type Error struct {
	Method      string
	Status      int
	Code        string
	Description string
	Body        []byte
}

func (e *Error) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("csc: %s answered HTTP %d (non-JSON body, %d bytes)", e.Method, e.Status, len(e.Body))
	}
	if e.Description == "" {
		return fmt.Sprintf("csc: %s answered HTTP %d %s", e.Method, e.Status, e.Code)
	}
	return fmt.Sprintf("csc: %s answered HTTP %d %s: %s", e.Method, e.Status, e.Code, e.Description)
}

// ErrNoAccessToken is returned when a 2xx token response carries no access_token.
var ErrNoAccessToken = errors.New("csc: token response carries no access_token")

// ErrSignatureCount is returned when signHash returns a different number of
// signatures than hashes were sent ([CSC API §11.13]: same order, one per hash).
var ErrSignatureCount = errors.New("csc: signatures count differs from hashes count")

// --- info ([CSC API §11.1]) -------------------------------------------------------------

// Info is the output of the info method ([CSC API §11.1]). Members the service omits are
// zero; SupportedHashTypes is nil when absent (editions before 2.1 do not define it).
type Info struct {
	Specs                     string   `json:"specs"`
	Name                      string   `json:"name"`
	Logo                      string   `json:"logo"`
	Region                    string   `json:"region"`
	Lang                      string   `json:"lang"`
	Description               string   `json:"description"`
	AuthType                  []string `json:"authType"`
	OAuth2                    string   `json:"oauth2"`
	OAuth2Issuer              string   `json:"oauth2Issuer"`
	SupportsRAR               *bool    `json:"supportsRar"`
	SupportedHashTypes        []string `json:"supportedHashTypes"`
	AsynchronousOperationMode *bool    `json:"asynchronousOperationMode"`
	ValidationInfo            *bool    `json:"validationInfo"`
	Methods                   []string `json:"methods"`
	SignAlgorithms            struct {
		Algos      []string `json:"algos"`
		AlgoParams []string `json:"algoParams"`
	} `json:"signAlgorithms"`
	DocumentTypes    []string `json:"documentTypes"`
	SignatureFormats struct {
		Formats            []string `json:"formats"`
		EnvelopeProperties []any    `json:"envelope_properties"`
	} `json:"signature_formats"`
	ConformanceLevels []string `json:"conformance_levels"`
}

// Supports reports whether the service lists the method (e.g. "signatures/signHash").
func (i Info) Supports(method string) bool {
	for _, m := range i.Methods {
		if m == method {
			return true
		}
	}
	return false
}

// Info calls the info method. It needs no authorization and is the one method
// every conforming service implements ([CSC API §11.1]).
func (c *Client) Info(ctx context.Context) (Info, error) {
	var out Info
	err := c.postJSON(ctx, "info", c.BaseURI+"/info", "", map[string]any{}, &out)
	return out, err
}

// --- authorization ([CSC API §8.2]) -------------------------------------------------------

// CredentialAuthorization is the credential-scope half of an authorization
// request ([CSC API §8.2.2], "Credential scope and authorization details"). At least one of
// CredentialID and SignatureQualifier is required; with SCAL "2" the hashes are.
type CredentialAuthorization struct {
	// CredentialID names an existing credential to authorize.
	CredentialID string
	// SignatureQualifier asks the authorization server for a credential able to
	// create that kind of signature (e.g. "eu_eidas_qes") — how a short-term
	// credential is requested.
	SignatureQualifier string
	// NumSignatures is the number of signatures to authorize; zero omits it.
	NumSignatures int
	// Hashes are the raw digests the authorization binds to; the alphabet on the
	// wire comes from the profile.
	Hashes [][]byte
	// HashAlgorithmOID is the OID of the algorithm that produced Hashes.
	HashAlgorithmOID string
	// Description is a free-form text for the consent screen (max 500 characters).
	Description string
}

// AuthorizationRequest is an OAuth 2.0 authorization request as the specification
// shapes it ([CSC API §8.2.2]): response_type=code, PKCE, a scope, and — for scope
// "credential" — the credential parameters, plus the user-authentication half.
type AuthorizationRequest struct {
	RedirectURI string
	State       string
	PKCE        PKCE
	// Scope is "service" or "credential" ([CSC API §8.2.2]). Empty omits the parameter.
	Scope string
	// Credential is required when Scope is "credential".
	Credential *CredentialAuthorization
	// User adds the user-authentication parameters; nil adds none.
	User UserAuthentication
	// Lang and ClientData are the optional [CSC API §8.2.2] parameters of those names.
	Lang       string
	ClientData string
	// Extra is appended verbatim; for parameters this package does not name.
	Extra url.Values
}

// Values renders the request as the authorize / pushed_authorize parameters.
func (c *Client) values(r AuthorizationRequest) url.Values {
	v := url.Values{}
	v.Set("response_type", "code")
	v.Set("client_id", c.ClientID)
	v.Set("redirect_uri", r.RedirectURI)
	if r.State != "" {
		v.Set("state", r.State)
	}
	if r.Scope != "" {
		v.Set("scope", r.Scope)
	}
	if r.PKCE.Challenge != "" {
		v.Set("code_challenge_method", "S256")
		v.Set("code_challenge", r.PKCE.Challenge)
	}
	if r.Credential != nil {
		cr := r.Credential
		if cr.CredentialID != "" {
			v.Set("credentialID", cr.CredentialID)
		}
		if cr.SignatureQualifier != "" {
			v.Set("signatureQualifier", cr.SignatureQualifier)
		}
		if cr.NumSignatures > 0 {
			v.Set("numSignatures", strconv.Itoa(cr.NumSignatures))
		}
		if len(cr.Hashes) > 0 {
			enc := c.profile().HashesEncoding
			parts := make([]string, len(cr.Hashes))
			for i, h := range cr.Hashes {
				parts[i] = enc.Encode(h)
			}
			// "Multiple hash values can be passed as comma separated values" ([CSC API §8.2.2]).
			v.Set("hashes", strings.Join(parts, ","))
		}
		if cr.HashAlgorithmOID != "" {
			v.Set("hashAlgorithmOID", cr.HashAlgorithmOID)
		}
		if cr.Description != "" {
			v.Set("description", cr.Description)
		}
	}
	if r.Lang != "" {
		v.Set("lang", r.Lang)
	}
	if r.ClientData != "" {
		v.Set("clientData", r.ClientData)
	}
	if r.User != nil {
		r.User.ApplyTo(v)
	}
	for k, vs := range r.Extra {
		for _, x := range vs {
			v.Add(k, x)
		}
	}
	return v
}

// AuthorizeURLClassic is the oauth2/authorize URL with the request's parameters in
// the query string ([CSC API §8.2.2]) — the entry a provider without pushed authorization uses.
func (c *Client) AuthorizeURLClassic(r AuthorizationRequest) string {
	return c.oauthBase() + "/oauth2/authorize?" + c.values(r).Encode()
}

// PushedAuthorization is the answer to oauth2/pushed_authorize ([CSC API §8.2.3], RFC 9126):
// a one-time request_uri and its lifetime in seconds.
type PushedAuthorization struct {
	RequestURI string `json:"request_uri"`
	ExpiresIn  int    `json:"expires_in"`
	// IssuedAt is when the answer arrived; the request_uri must be used before
	// IssuedAt + ExpiresIn.
	IssuedAt time.Time `json:"-"`
}

// ExpiresAt is the moment the request_uri stops being usable.
func (p PushedAuthorization) ExpiresAt() time.Time {
	return p.IssuedAt.Add(time.Duration(p.ExpiresIn) * time.Second)
}

// PushedAuthorize pushes the authorization request to the authorization server
// ([CSC API §8.2.3]): the same parameters as oauth2/authorize, as a form body, with the client
// authenticated the way the token endpoint authenticates it (HTTP Basic here).
func (c *Client) PushedAuthorize(ctx context.Context, r AuthorizationRequest) (PushedAuthorization, error) {
	var out PushedAuthorization
	at, err := c.postForm(ctx, "oauth2/pushed_authorize", c.oauthBase()+"/oauth2/pushed_authorize", c.values(r), &out)
	if err != nil {
		return out, err
	}
	if out.RequestURI == "" {
		return out, &Error{Method: "oauth2/pushed_authorize", Status: http.StatusOK, Code: "", Body: []byte("2xx without request_uri")}
	}
	out.IssuedAt = at
	return out, nil
}

// AuthorizeURL is the oauth2/authorize URL for a pushed request: client_id and
// request_uri, nothing else ([CSC API §8.2.3]).
func (c *Client) AuthorizeURL(p PushedAuthorization) string {
	v := url.Values{}
	v.Set("client_id", c.ClientID)
	v.Set("request_uri", p.RequestURI)
	return c.oauthBase() + "/oauth2/authorize?" + v.Encode()
}

// TokenResponse is the output of oauth2/token ([CSC API §8.2.4]). AuthorizationDetails is
// kept raw: the specification defines the "credential" type, and providers add
// their own; a profile package reads what it knows.
type TokenResponse struct {
	AccessToken          string          `json:"access_token"`
	RefreshToken         string          `json:"refresh_token"`
	TokenType            string          `json:"token_type"`
	ExpiresIn            int             `json:"expires_in"`
	Scope                string          `json:"scope"`
	CredentialID         string          `json:"credentialID"`
	AuthorizationDetails json.RawMessage `json:"authorization_details"`
	IssuedAt             time.Time       `json:"-"`
}

// ExpiresAt is the moment the access token stops being usable. The specification's
// default when expires_in is omitted is 3600 s ([CSC API §8.2.4]).
func (t TokenResponse) ExpiresAt() time.Time {
	n := t.ExpiresIn
	if n == 0 {
		n = 3600
	}
	return t.IssuedAt.Add(time.Duration(n) * time.Second)
}

// Token exchanges an authorization code for an access token ([CSC API §8.2.4],
// grant_type=authorization_code) with the PKCE verifier and HTTP Basic client
// authentication. redirectURI is the one the authorization request carried.
func (c *Client) Token(ctx context.Context, code, redirectURI, codeVerifier string) (TokenResponse, error) {
	v := url.Values{}
	v.Set("grant_type", "authorization_code")
	v.Set("client_id", c.ClientID)
	v.Set("code", code)
	v.Set("redirect_uri", redirectURI)
	if codeVerifier != "" {
		v.Set("code_verifier", codeVerifier)
	}
	var out TokenResponse
	at, err := c.postForm(ctx, "oauth2/token", c.oauthBase()+"/oauth2/token", v, &out)
	if err != nil {
		return out, err
	}
	if out.AccessToken == "" {
		return out, ErrNoAccessToken
	}
	out.IssuedAt = at
	return out, nil
}

// --- credentials ([CSC API §11.6], [CSC API §11.7]) ----------------------------------------------

// CredentialsListRequest is the input of credentials/list ([CSC API §11.6]). UserID must be
// absent under a user-specific authorization.
type CredentialsListRequest struct {
	UserID         string `json:"userID,omitempty"`
	CredentialInfo bool   `json:"credentialInfo,omitempty"`
	Certificates   string `json:"certificates,omitempty"`
	CertInfo       bool   `json:"certInfo,omitempty"`
	AuthInfo       bool   `json:"authInfo,omitempty"`
	OnlyValid      bool   `json:"onlyValid,omitempty"`
	Lang           string `json:"lang,omitempty"`
	ClientData     string `json:"clientData,omitempty"`
}

// CredentialsListResponse is the output of credentials/list ([CSC API §11.6]).
type CredentialsListResponse struct {
	CredentialIDs   []string     `json:"credentialIDs"`
	CredentialInfos []Credential `json:"credentialInfos"`
	OnlyValid       *bool        `json:"onlyValid"`
}

// CredentialsList calls credentials/list with a service or credential access token.
func (c *Client) CredentialsList(ctx context.Context, accessToken string, r CredentialsListRequest) (CredentialsListResponse, error) {
	var out CredentialsListResponse
	err := c.postJSON(ctx, "credentials/list", c.BaseURI+"/credentials/list", accessToken, r, &out)
	return out, err
}

// Certificates values for credentials/info and credentials/list ([CSC API §11.7]).
const (
	CertificatesNone   = "none"
	CertificatesSingle = "single"
	CertificatesChain  = "chain"
)

// CredentialsInfoRequest is the input of credentials/info ([CSC API §11.7]).
type CredentialsInfoRequest struct {
	CredentialID string `json:"credentialID"`
	Certificates string `json:"certificates,omitempty"`
	CertInfo     bool   `json:"certInfo,omitempty"`
	AuthInfo     bool   `json:"authInfo,omitempty"`
	Lang         string `json:"lang,omitempty"`
	ClientData   string `json:"clientData,omitempty"`
}

// Credential is the output of credentials/info ([CSC API §11.7]) and the credentialInfo
// object of credentials/list ([CSC API §11.6]).
type Credential struct {
	CredentialID       string `json:"credentialID"`
	Description        string `json:"description"`
	SignatureQualifier string `json:"signatureQualifier"`
	Key                struct {
		Status string   `json:"status"`
		Algo   []string `json:"algo"`
		Len    int      `json:"len"`
		Curve  string   `json:"curve"`
	} `json:"key"`
	Cert struct {
		Status       string   `json:"status"`
		Certificates []string `json:"certificates"`
		IssuerDN     string   `json:"issuerDN"`
		SerialNumber string   `json:"serialNumber"`
		SubjectDN    string   `json:"subjectDN"`
		ValidFrom    string   `json:"validFrom"`
		ValidTo      string   `json:"validTo"`
		Policy       []string `json:"policy"`
	} `json:"cert"`
	Auth struct {
		Mode       string `json:"mode"`
		Expression string `json:"expression"`
		Objects    []any  `json:"objects"`
	} `json:"auth"`
	SCAL      string `json:"SCAL"`
	Multisign int    `json:"multisign"`
	Lang      string `json:"lang"`
}

// SCALValue is the credential's SCAL, defaulting to "1" when omitted ([CSC API §11.7]).
func (cr Credential) SCALValue() string {
	if cr.SCAL == "" {
		return "1"
	}
	return cr.SCAL
}

// CanSignWith reports whether signAlgo is among the credential's key.algo.
func (cr Credential) CanSignWith(signAlgo string) bool {
	for _, a := range cr.Key.Algo {
		if a == signAlgo {
			return true
		}
	}
	return false
}

// LeafCertificate returns the first certificate, base64-decoded to DER, or nil.
func (cr Credential) LeafCertificate() ([]byte, error) {
	if len(cr.Cert.Certificates) == 0 {
		return nil, errors.New("csc: credential carries no certificate")
	}
	return base64.StdEncoding.DecodeString(strings.TrimSpace(cr.Cert.Certificates[0]))
}

// CredentialsInfo calls credentials/info ([CSC API §11.7]).
func (c *Client) CredentialsInfo(ctx context.Context, accessToken string, r CredentialsInfoRequest) (Credential, error) {
	var out Credential
	err := c.postJSON(ctx, "credentials/info", c.BaseURI+"/credentials/info", accessToken, r, &out)
	if err == nil && out.CredentialID == "" {
		out.CredentialID = r.CredentialID
	}
	return out, err
}

// --- signatures/signHash ([CSC API §11.13]) ------------------------------------------------

// SignHashRequest is the input of signatures/signHash ([CSC API §11.13] plus the
// signingAlgorithm of the CSC data model [CSC DM §7.6]). Hashes are raw digests; the body
// carries them standard-Base64 as the specification requires.
type SignHashRequest struct {
	CredentialID string
	// SAD is the signature activation data from an explicit credential
	// authorization. Not needed when the Authorization header carries an access
	// token with scope "credential" ([CSC API §11.13]) — the OAuth path this package walks.
	SAD    string
	Hashes [][]byte
	// HashAlgorithmOID is the OID of the algorithm that produced Hashes. The
	// specification lets it be omitted when signAlgo implies it; the profile decides
	// whether it is sent anyway.
	HashAlgorithmOID string
	// SignAlgo is the signature algorithm OID; SignAlgoParams the base64 DER
	// parameters some algorithms need [CSC DM §7.6].
	SignAlgo       string
	SignAlgoParams string
	// OperationMode is "S" (synchronous, the default) or "A"; ClientData optional.
	OperationMode string
	ClientData    string
}

type signHashBody struct {
	CredentialID     string   `json:"credentialID"`
	SAD              string   `json:"SAD,omitempty"`
	Hashes           []string `json:"hashes"`
	HashAlgorithmOID string   `json:"hashAlgorithmOID,omitempty"`
	SignAlgo         string   `json:"signAlgo"`
	SignAlgoParams   string   `json:"signAlgoParams,omitempty"`
	OperationMode    string   `json:"operationMode,omitempty"`
	ClientData       string   `json:"clientData,omitempty"`
}

// SignHashResponse is the output of signatures/signHash ([CSC API §11.13]): one
// base64-encoded signature per hash, in the same order, or a responseID in
// asynchronous mode.
type SignHashResponse struct {
	Signatures []string `json:"signatures"`
	ResponseID string   `json:"responseID"`
}

// Signature returns the i-th signature decoded from Base64 (standard, then
// base64url as a fallback for providers that answer that way).
func (r SignHashResponse) Signature(i int) ([]byte, error) {
	if i < 0 || i >= len(r.Signatures) {
		return nil, fmt.Errorf("csc: no signature %d in %d", i, len(r.Signatures))
	}
	s := strings.TrimSpace(r.Signatures[i])
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawURLEncoding.DecodeString(s)
}

// SignHash calls signatures/signHash with the given access token as Bearer. In
// synchronous mode it checks that exactly one signature came back per hash.
func (c *Client) SignHash(ctx context.Context, accessToken string, r SignHashRequest) (SignHashResponse, error) {
	body := signHashBody{
		CredentialID:   r.CredentialID,
		SAD:            r.SAD,
		Hashes:         make([]string, len(r.Hashes)),
		SignAlgo:       r.SignAlgo,
		SignAlgoParams: r.SignAlgoParams,
		OperationMode:  r.OperationMode,
		ClientData:     r.ClientData,
	}
	for i, h := range r.Hashes {
		body.Hashes[i] = Base64Std.Encode(h) // "base64-encoded raw message digest(s)" ([CSC API §11.13])
	}
	if r.HashAlgorithmOID != "" && (c.profile().AlwaysSendHashAlgorithmOID || !impliesHash(r.SignAlgo)) {
		body.HashAlgorithmOID = r.HashAlgorithmOID
	}
	var out SignHashResponse
	if err := c.postJSON(ctx, "signatures/signHash", c.BaseURI+"/signatures/signHash", accessToken, body, &out); err != nil {
		return out, err
	}
	if r.OperationMode != "A" && len(out.Signatures) != len(r.Hashes) {
		return out, fmt.Errorf("%w: %d for %d", ErrSignatureCount, len(out.Signatures), len(r.Hashes))
	}
	return out, nil
}

// impliesHash reports whether a signature algorithm OID names its hash algorithm
// (ECDSA-with-SHAx, sha*WithRSAEncryption), so hashAlgorithmOID may be omitted.
func impliesHash(signAlgo string) bool {
	switch signAlgo {
	case "1.2.840.10045.4.3.2", "1.2.840.10045.4.3.3", "1.2.840.10045.4.3.4", // ecdsa-with-SHA256/384/512
		"1.2.840.113549.1.1.11", "1.2.840.113549.1.1.12", "1.2.840.113549.1.1.13": // sha256/384/512WithRSAEncryption
		return true
	}
	return false
}

// --- transport -------------------------------------------------------------------

func (c *Client) profile() Profile {
	if c.Profile.Name == "" {
		return Specification
	}
	return c.Profile
}

func (c *Client) oauthBase() string {
	if c.OAuthBase != "" {
		return strings.TrimSuffix(c.OAuthBase, "/")
	}
	return strings.TrimSuffix(c.BaseURI, "/")
}

func (c *Client) http() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{
		Timeout:       30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// postJSON sends a JSON body, with a Bearer token when given, and decodes a 2xx
// JSON answer into out. A non-2xx answer becomes *Error.
func (c *Client) postJSON(ctx context.Context, method, endpoint, bearer string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	_, err = c.do(method, req, out)
	return err
}

// postForm sends a form body with HTTP Basic client authentication and decodes a
// 2xx JSON answer into out; it returns the time the answer arrived.
func (c *Client) postForm(ctx context.Context, method, endpoint string, form url.Values, out any) (time.Time, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return time.Time{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(c.ClientID, c.ClientSecret)
	return c.do(method, req, out)
}

func (c *Client) do(method string, req *http.Request, out any) (time.Time, error) {
	resp, err := c.http().Do(req)
	if err != nil {
		return time.Time{}, fmt.Errorf("csc: %s: %w", method, err)
	}
	defer func() { _ = resp.Body.Close() }()
	at := time.Now()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return at, fmt.Errorf("csc: %s: reading the answer: %w", method, err)
	}
	if resp.StatusCode/100 != 2 {
		return at, parseError(method, resp.StatusCode, raw)
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return at, nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return at, fmt.Errorf("csc: %s: the answer is not the JSON the specification defines: %w", method, err)
	}
	return at, nil
}

func parseError(method string, status int, raw []byte) *Error {
	e := &Error{Method: method, Status: status, Body: raw}
	var body struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if json.Unmarshal(raw, &body) == nil {
		e.Code, e.Description = body.Error, body.Description
	}
	return e
}
