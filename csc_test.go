package csc

import (
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// Every test names the clause of CSC API v2.2.0.0 it pins.

type capture struct {
	method  string
	path    string
	headers http.Header
	form    url.Values
	body    map[string]any
}

// server answers each path with the given body and records what arrived.
func server(t *testing.T, answers map[string]string, status int) (*httptest.Server, *[]capture) {
	t.Helper()
	var got []capture
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		c := capture{method: r.Method, path: r.URL.Path, headers: r.Header.Clone()}
		if strings.Contains(r.Header.Get("Content-Type"), "x-www-form-urlencoded") {
			c.form, _ = url.ParseQuery(string(raw))
		} else if len(raw) > 0 {
			_ = json.Unmarshal(raw, &c.body)
		}
		got = append(got, c)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, answers[r.URL.Path])
	}))
	t.Cleanup(s.Close)
	return s, &got
}

func client(s *httptest.Server, p Profile) *Client {
	return &Client{BaseURI: s.URL + "/csc/v2", ClientID: "app", ClientSecret: "s3cret-" + "value", Profile: p}
}

// [CSC API §11.1] — info is POST with an empty JSON object, no authorization; the output is read as named.
func TestInfo(t *testing.T) {
	s, got := server(t, map[string]string{"/csc/v2/info": `{"specs":"2.0.0.2","name":"x","authType":["oauth2code"],"oauth2":"https://as/","methods":["credentials/info","signatures/signHash"],"signAlgorithms":{"algos":["1.2.840.10045.4.3.3"]},"signature_formats":{"formats":[],"envelope_properties":[]},"conformance_levels":[]}`}, 200)
	info, err := client(s, Specification).Info(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	c := (*got)[0]
	if c.method != "POST" || c.headers.Get("Authorization") != "" || len(c.body) != 0 || c.headers.Get("Content-Type") != "application/json" {
		t.Fatalf("info request: %+v", c)
	}
	if info.Specs != "2.0.0.2" || !info.Supports("signatures/signHash") || info.Supports("signatures/signDoc") {
		t.Fatalf("info parsed: %+v", info)
	}
	if info.SupportedHashTypes != nil || info.AsynchronousOperationMode != nil {
		t.Fatal("absent optional members must read as nil, not as empty")
	}
}

// [CSC API §8.2.2] — the authorization request parameters, and the alphabet of `hashes` per profile.
func TestAuthorizationValues(t *testing.T) {
	d1 := sha512.Sum384([]byte("a"))
	d2 := sha512.Sum384([]byte("b"))
	req := AuthorizationRequest{
		RedirectURI: "https://app/cb", State: "st", PKCE: PKCE{Challenge: "ch"}, Scope: "credential",
		Credential: &CredentialAuthorization{CredentialID: "cred", NumSignatures: 2, Hashes: [][]byte{d1[:], d2[:]}, HashAlgorithmOID: "2.16.840.1.101.3.4.2.2"},
		User:       urlValues{"acr_values": {"flow"}},
	}
	c := &Client{ClientID: "app", Profile: Specification}
	v := c.values(req)
	want := map[string]string{
		"response_type": "code", "client_id": "app", "redirect_uri": "https://app/cb", "state": "st", "scope": "credential",
		"code_challenge_method": "S256", "code_challenge": "ch", "credentialID": "cred", "numSignatures": "2",
		"hashAlgorithmOID": "2.16.840.1.101.3.4.2.2", "acr_values": "flow",
		// "One or more base64url-encoded hash values … comma separated" — [CSC API §8.2.2]
		"hashes": base64.RawURLEncoding.EncodeToString(d1[:]) + "," + base64.RawURLEncoding.EncodeToString(d2[:]),
	}
	for k, w := range want {
		if v.Get(k) != w {
			t.Errorf("%s = %q, want %q", k, v.Get(k), w)
		}
	}
	if len(v) != len(want) {
		t.Errorf("unexpected parameters: %v", v)
	}
	// A profile that says standard Base64 changes only the alphabet.
	c.Profile = Profile{Name: "std", HashesEncoding: Base64Std}
	if h := c.values(req).Get("hashes"); h != base64.StdEncoding.EncodeToString(d1[:])+","+base64.StdEncoding.EncodeToString(d2[:]) {
		t.Errorf("std profile hashes = %q", h)
	}
}

type urlValues url.Values

func (u urlValues) ApplyTo(v url.Values) {
	for k, vs := range u {
		for _, x := range vs {
			v.Add(k, x)
		}
	}
}

// [CSC API §8.2.3] — pushed_authorize: form body, HTTP Basic, request_uri + expires_in back; the
// authorize URL then carries only client_id and request_uri.
func TestPushedAuthorize(t *testing.T) {
	s, got := server(t, map[string]string{"/csc/v2/oauth2/pushed_authorize": `{"request_uri":"urn:ietf:params:oauth:request_uri:abc","expires_in":60}`}, 201)
	c := client(s, Specification)
	par, err := c.PushedAuthorize(context.Background(), AuthorizationRequest{RedirectURI: "https://app/cb", State: "s", PKCE: PKCE{Challenge: "x"}, Scope: "credential", Credential: &CredentialAuthorization{SignatureQualifier: "eu_eidas_qes"}})
	if err != nil {
		t.Fatal(err)
	}
	g := (*got)[0]
	user, pass, ok := (&http.Request{Header: g.headers}).BasicAuth()
	if !ok || user != "app" || pass != c.ClientSecret {
		t.Fatal("pushed_authorize must authenticate the client with HTTP Basic ([CSC API §8.2.3])")
	}
	if g.form.Get("signatureQualifier") != "eu_eidas_qes" || g.form.Get("scope") != "credential" || g.form.Get("response_type") != "code" {
		t.Fatalf("form: %v", g.form)
	}
	if par.RequestURI != "urn:ietf:params:oauth:request_uri:abc" || par.ExpiresIn != 60 || par.IssuedAt.IsZero() {
		t.Fatalf("par: %+v", par)
	}
	u, _ := url.Parse(c.AuthorizeURL(par))
	if u.Path != "/csc/v2/oauth2/authorize" || u.Query().Get("client_id") != "app" || u.Query().Get("request_uri") != par.RequestURI || len(u.Query()) != 2 {
		t.Fatalf("authorize URL: %s", u)
	}
}

// [CSC API §8.2.4] — token: grant_type=authorization_code, code, redirect_uri, code_verifier, Basic;
// credentialID and authorization_details read back, the latter kept raw.
func TestToken(t *testing.T) {
	s, got := server(t, map[string]string{"/csc/v2/oauth2/token": `{"access_token":"tok","token_type":"Bearer","expires_in":120,"credentialID":"c1","authorization_details":[{"type":"credential","x":1}]}`}, 200)
	c := client(s, Specification)
	tok, err := c.Token(context.Background(), "code1", "https://app/cb", "ver")
	if err != nil {
		t.Fatal(err)
	}
	f := (*got)[0].form
	if f.Get("grant_type") != "authorization_code" || f.Get("code") != "code1" || f.Get("redirect_uri") != "https://app/cb" || f.Get("code_verifier") != "ver" || f.Get("client_id") != "app" {
		t.Fatalf("token form: %v", f)
	}
	if tok.AccessToken != "tok" || tok.CredentialID != "c1" || tok.ExpiresIn != 120 || !strings.Contains(string(tok.AuthorizationDetails), `"type":"credential"`) {
		t.Fatalf("token: %+v", tok)
	}
	if tok.ExpiresAt().Sub(tok.IssuedAt).Seconds() != 120 {
		t.Fatal("ExpiresAt must follow expires_in")
	}
	// A 2xx without access_token is an error, not a token.
	s2, _ := server(t, map[string]string{"/csc/v2/oauth2/token": `{"token_type":"Bearer"}`}, 200)
	if _, err := client(s2, Specification).Token(context.Background(), "c", "r", "v"); !errors.Is(err, ErrNoAccessToken) {
		t.Fatalf("want ErrNoAccessToken, got %v", err)
	}
}

// [CSC API §11.7] — credentials/info: Bearer, the request members as named; the output read as named.
func TestCredentialsInfo(t *testing.T) {
	s, got := server(t, map[string]string{"/csc/v2/credentials/info": `{"key":{"status":"enabled","algo":["1.2.840.10045.4.3.3"],"len":384,"curve":"1.3.132.0.34"},"cert":{"status":"valid","certificates":["AQID"],"validFrom":"20260813080931Z","validTo":"20260813082400Z"},"auth":{"mode":"oauth2code"},"multisign":40,"SCAL":"2","signatureQualifier":"eu_eidas_qes"}`}, 200)
	cr, err := client(s, Specification).CredentialsInfo(context.Background(), "tok", CredentialsInfoRequest{CredentialID: "c1", Certificates: CertificatesChain, CertInfo: true, AuthInfo: true})
	if err != nil {
		t.Fatal(err)
	}
	g := (*got)[0]
	if g.headers.Get("Authorization") != "Bearer tok" || g.body["credentialID"] != "c1" || g.body["certificates"] != "chain" || g.body["certInfo"] != true || g.body["authInfo"] != true {
		t.Fatalf("credentials/info request: %+v", g)
	}
	if cr.CredentialID != "c1" || cr.Key.Len != 384 || cr.SCALValue() != "2" || cr.Multisign != 40 || !cr.CanSignWith("1.2.840.10045.4.3.3") || cr.CanSignWith("1.2.840.113549.1.1.11") {
		t.Fatalf("credential: %+v", cr)
	}
	if leaf, _ := cr.LeafCertificate(); string(leaf) != "\x01\x02\x03" {
		t.Fatal("LeafCertificate must decode the first certificate from standard Base64")
	}
	if (Credential{}).SCALValue() != "1" {
		t.Fatal("SCAL defaults to 1 when omitted ([CSC API §11.7])")
	}
}

// [CSC API §11.13] — signHash: Bearer; hashes standard Base64; hashAlgorithmOID omitted when signAlgo
// implies it under the specification profile, always sent when the profile says so; the
// signature count must match.
func TestSignHash(t *testing.T) {
	d := sha512.Sum384([]byte("doc"))
	s, got := server(t, map[string]string{"/csc/v2/signatures/signHash": `{"signatures":["c2ln"]}`}, 200)
	req := SignHashRequest{CredentialID: "c1", Hashes: [][]byte{d[:]}, HashAlgorithmOID: "2.16.840.1.101.3.4.2.2", SignAlgo: "1.2.840.10045.4.3.3"}

	out, err := client(s, Specification).SignHash(context.Background(), "signtok", req)
	if err != nil {
		t.Fatal(err)
	}
	g := (*got)[0]
	if g.headers.Get("Authorization") != "Bearer signtok" || g.body["credentialID"] != "c1" || g.body["signAlgo"] != "1.2.840.10045.4.3.3" {
		t.Fatalf("signHash request: %+v", g)
	}
	if hs, _ := g.body["hashes"].([]any); len(hs) != 1 || hs[0] != base64.StdEncoding.EncodeToString(d[:]) {
		t.Fatalf("hashes must be standard Base64 ([CSC API §11.13]): %v", g.body["hashes"])
	}
	if _, present := g.body["hashAlgorithmOID"]; present {
		t.Fatal("under the specification profile hashAlgorithmOID is omitted when signAlgo implies the hash ([CSC API §11.13])")
	}
	if _, present := g.body["SAD"]; present {
		t.Fatal("an empty SAD must not be sent")
	}
	if sig, _ := out.Signature(0); string(sig) != "sig" {
		t.Fatalf("signature decode: %q", sig)
	}

	strict := Profile{Name: "strict", HashesEncoding: Base64Std, AlwaysSendHashAlgorithmOID: true}
	if _, err := client(s, strict).SignHash(context.Background(), "t", req); err != nil {
		t.Fatal(err)
	}
	if (*got)[1].body["hashAlgorithmOID"] != "2.16.840.1.101.3.4.2.2" {
		t.Fatal("a profile with AlwaysSendHashAlgorithmOID must send it")
	}

	s2, _ := server(t, map[string]string{"/csc/v2/signatures/signHash": `{"signatures":["a","b"]}`}, 200)
	if _, err := client(s2, Specification).SignHash(context.Background(), "t", req); !errors.Is(err, ErrSignatureCount) {
		t.Fatalf("want ErrSignatureCount, got %v", err)
	}
}

// [CSC API §10.1] — an error answer is JSON {error, error_description}; a body that is not JSON keeps its bytes.
func TestErrors(t *testing.T) {
	s, _ := server(t, map[string]string{"/csc/v2/oauth2/token": `{"error":"invalid_grant","error_description":"invalidOrExpiredCode"}`}, 400)
	_, err := client(s, Specification).Token(context.Background(), "c", "r", "v")
	var e *Error
	if !errors.As(err, &e) || e.Status != 400 || e.Code != "invalid_grant" || e.Description != "invalidOrExpiredCode" || e.Method != "oauth2/token" {
		t.Fatalf("error: %v", err)
	}
	s2, _ := server(t, map[string]string{"/csc/v2/oauth2/pushed_authorize": `<html>HTTP Status 400</html>`}, 400)
	_, err = client(s2, Specification).PushedAuthorize(context.Background(), AuthorizationRequest{})
	if !errors.As(err, &e) || e.Code != "" || len(e.Body) == 0 {
		t.Fatalf("non-JSON error must keep the body: %v", err)
	}
	if strings.Contains(e.Error(), "s3cret") {
		t.Fatal("an error must never carry the client secret")
	}
}

// [CSC API §8.2.2] / RFC 7636 — PKCE S256: a 43-character verifier and its base64url SHA-256.
func TestPKCE(t *testing.T) {
	p, err := NewPKCE()
	if err != nil || len(p.Verifier) != 43 || len(p.Challenge) != 43 || strings.ContainsAny(p.Verifier+p.Challenge, "+/=") {
		t.Fatalf("pkce: %+v %v", p, err)
	}
}

// [CSC API §7.2] — the OAuth endpoints may live off the service base URI (info.oauth2).
func TestOAuthBase(t *testing.T) {
	c := &Client{BaseURI: "https://svc/csc/v2", OAuthBase: "https://as/oauth/"}
	if u := c.AuthorizeURL(PushedAuthorization{RequestURI: "r"}); !strings.HasPrefix(u, "https://as/oauth/oauth2/authorize?") {
		t.Fatalf("authorize URL off the OAuth base: %s", u)
	}
	c.OAuthBase = ""
	if u := c.AuthorizeURLClassic(AuthorizationRequest{Scope: "service"}); !strings.HasPrefix(u, "https://svc/csc/v2/oauth2/authorize?") || !strings.Contains(u, "scope=service") {
		t.Fatalf("classic authorize URL: %s", u)
	}
}

// The parsers read bytes a remote service produced; they must never panic on any input.
func FuzzParse(f *testing.F) {
	f.Add([]byte(`{"specs":"2.2.0.0"}`))
	f.Add([]byte(`{"signatures":["!!!"]}`))
	f.Add([]byte(`{"error":1}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var i Info
		_ = json.Unmarshal(data, &i)
		var cr Credential
		_ = json.Unmarshal(data, &cr)
		_, _ = cr.LeafCertificate()
		var sh SignHashResponse
		_ = json.Unmarshal(data, &sh)
		_, _ = sh.Signature(0)
		_ = parseError("m", 400, data).Error()
	})
}
