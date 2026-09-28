package lvrtc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gmb-lib/go-csc"
)

// The two token responses in the shape the provider returns them (measured on its pre-production
// instance; the guide's sections 11.4 and 15.4 show the same members with expires_in 120).
const (
	credentialTokenJSON = `{"access_token":"a","token_type":"Bearer","expires_in":600,"authorization_details":[{"type":"sign_identity_registration","group_labels":["urn:csc:signatureQualifier:eu_eidas_qes"]}],"credentialID":"cred-1"}`
	signTokenJSON       = `{"access_token":"b","token_type":"Bearer","expires_in":600,"authorization_details":[{"type":"digest_signing","digests":[{"value":"%s","algorithm":"SHA-384"}],"sign_identity_id":"cred-1","num_signatures":1}]}`
)

func TestEIDFlowsAcrValues(t *testing.T) {
	v := url.Values{}
	EIDFlows{CardOnComputer, EIDScan}.ApplyTo(v)
	if v.Get("acr_values") != "urn:eparaksts:authentication:flow:sc_plugin|urn:eparaksts:authentication:flow:mobile-eid" {
		t.Fatalf("acr_values: %q", v.Get("acr_values"))
	}
	EIDFlows(nil).ApplyTo(v)
	if len(v) != 1 {
		t.Fatal("no flows adds nothing")
	}
}

// The first authorization (provider guide, section 9): scope=credential, signatureQualifier, acr_values, PKCE.
func TestCredentialRequestShape(t *testing.T) {
	c := &csc.Client{ClientID: "app", Profile: Profile}
	u, _ := url.Parse(c.AuthorizeURLClassic(CredentialRequest("https://app/cb", "st", csc.PKCE{Challenge: "ch"}, EIDFlows{CardOnComputer})))
	q := u.Query()
	for k, w := range map[string]string{"scope": "credential", "signatureQualifier": "eu_eidas_qes", "acr_values": string(CardOnComputer), "code_challenge_method": "S256", "code_challenge": "ch", "state": "st"} {
		if q.Get(k) != w {
			t.Errorf("%s = %q, want %q", k, q.Get(k), w)
		}
	}
	if q.Has("credentialID") || q.Has("hashes") {
		t.Fatal("the credential request names no credential and no hashes")
	}
}

// The second authorization (provider guide, section 14): credentialID, numSignatures, hashes in STANDARD Base64, hashAlgorithmOID.
func TestSigningRequestShape(t *testing.T) {
	d := sha512.Sum384([]byte("doc"))
	c := &csc.Client{ClientID: "app", Profile: Profile}
	u, _ := url.Parse(c.AuthorizeURLClassic(SigningRequest("https://app/cb", "st2", csc.PKCE{Challenge: "ch2"}, EIDFlows{CardOnComputer}, "cred-1", [][]byte{d[:]}, HashAlgorithmOIDSHA384)))
	q := u.Query()
	if q.Get("credentialID") != "cred-1" || q.Get("numSignatures") != "1" || q.Get("hashAlgorithmOID") != "2.16.840.1.101.3.4.2.2" || q.Has("signatureQualifier") {
		t.Fatalf("signing request: %v", q)
	}
	if q.Get("hashes") != base64.StdEncoding.EncodeToString(d[:]) {
		t.Fatalf("the guide's hashes are standard Base64: %q", q.Get("hashes"))
	}
}

func TestRegistrationAndSigning(t *testing.T) {
	var tok csc.TokenResponse
	if err := json.Unmarshal([]byte(credentialTokenJSON), &tok); err != nil {
		t.Fatal(err)
	}
	reg, err := Registration(tok)
	if err != nil || len(reg.GroupLabels) != 1 || reg.GroupLabels[0] != "urn:csc:signatureQualifier:eu_eidas_qes" || tok.CredentialID != "cred-1" {
		t.Fatalf("registration: %+v %v", reg, err)
	}
	if _, err := Signing(tok); !errors.Is(err, ErrNoDetails) {
		t.Fatalf("the credential token carries no digest_signing: %v", err)
	}

	d := sha512.Sum384([]byte("doc"))
	var sign csc.TokenResponse
	_ = json.Unmarshal([]byte(fmtSign(base64.StdEncoding.EncodeToString(d[:]))), &sign)
	ds, err := Signing(sign)
	if err != nil || ds.SignIdentityID != "cred-1" || ds.NumSignatures != 1 || ds.Digests[0].Algorithm != "SHA-384" {
		t.Fatalf("digest_signing: %+v %v", ds, err)
	}
	if err := Bound(ds, "cred-1", [][]byte{d[:]}); err != nil {
		t.Fatalf("bound: %v", err)
	}
	other := sha512.Sum384([]byte("other"))
	if err := Bound(ds, "cred-1", [][]byte{other[:]}); !errors.Is(err, ErrNotBound) {
		t.Fatal("a different digest must not pass Bound")
	}
	if err := Bound(ds, "cred-2", [][]byte{d[:]}); !errors.Is(err, ErrNotBound) {
		t.Fatal("a different credential must not pass Bound")
	}
	// The same digest echoed in base64url is still the same digest.
	var signURL csc.TokenResponse
	_ = json.Unmarshal([]byte(fmtSign(base64.RawURLEncoding.EncodeToString(d[:]))), &signURL)
	ds2, _ := Signing(signURL)
	if err := Bound(ds2, "cred-1", [][]byte{d[:]}); err != nil {
		t.Fatalf("base64url echo: %v", err)
	}
}

func fmtSign(v string) string {
	return fmtReplace(signTokenJSON, v)
}

func fmtReplace(tpl, v string) string {
	out := make([]byte, 0, len(tpl)+len(v))
	for i := 0; i < len(tpl); i++ {
		if tpl[i] == '%' && i+1 < len(tpl) && tpl[i+1] == 's' {
			out = append(out, v...)
			i++
			continue
		}
		out = append(out, tpl[i])
	}
	return string(out)
}

// Measured: the authorize hashes are accepted in standard Base64 only; a digest whose two spellings differ
// (it carries both '+' and '/') must reach the wire in the standard alphabet and never in base64url.
func TestSigningRequestSendsStandardBase64(t *testing.T) {
	var d []byte
	for i := 0; ; i++ {
		sum := sha512.Sum384([]byte{byte(i), byte(i >> 8)})
		std := base64.StdEncoding.EncodeToString(sum[:])
		if strings.ContainsRune(std, '+') && strings.ContainsRune(std, '/') {
			d = sum[:]
			break
		}
	}
	c := &csc.Client{ClientID: "app", Profile: Profile}
	u, _ := url.Parse(c.AuthorizeURLClassic(SigningRequest("https://app/cb", "st", csc.PKCE{Challenge: "ch"}, EIDFlows{EIDScan}, "cred-1", [][]byte{d}, HashAlgorithmOIDSHA384)))
	got := u.Query().Get("hashes")
	if got != base64.StdEncoding.EncodeToString(d) || strings.ContainsAny(got, "-_") {
		t.Fatalf("hashes %q: the provider refuses anything but standard Base64", got)
	}
}

// The credential in the shape the provider returns it: a P-384 key offering ECDSA with SHA-256/384/512,
// multisign 40, SCAL "2", a certificate valid for fifteen minutes.
func TestShortTermCredential(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	issued := time.Now().Add(-10 * time.Minute) // registered ten minutes ago, then reused
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "short-term signer"}, NotBefore: issued, NotAfter: issued.Add(CredentialLifetime)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	body := `{"description":"sign","key":{"status":"enabled","algo":["1.2.840.10045.4.3.2","1.2.840.10045.4.3.3","1.2.840.10045.4.3.4"],"len":384,"curve":"1.3.132.0.34"},` +
		`"cert":{"status":"valid","certificates":["` + base64.StdEncoding.EncodeToString(der) + `"]},"auth":{"mode":"oauth2code"},"multisign":40,"signatureQualifier":"eu_eidas_qes","SCAL":"2"}`
	var cred csc.Credential
	if err := json.Unmarshal([]byte(body), &cred); err != nil {
		t.Fatal(err)
	}
	if algo, err := cred.SignAlgoFor(HashAlgorithmOIDSHA384); err != nil || algo != SignAlgoECDSASHA384 {
		t.Fatalf("signAlgo for SHA-384: %q %v", algo, err)
	}
	if err := cred.CheckSigning(1, time.Now().Add(2*time.Minute)); err != nil {
		t.Fatalf("five minutes left, two needed: %v", err)
	}
	if err := cred.CheckSigning(1, time.Now().Add(6*time.Minute)); !errors.Is(err, csc.ErrCertificateValidity) {
		t.Fatalf("a reused credential expires with its first registration: %v", err)
	}
	if err := cred.CheckSigning(41, time.Now()); !errors.Is(err, csc.ErrMultisign) {
		t.Fatalf("41 signatures in one authorization: %v", err)
	}
}

func TestProfileValues(t *testing.T) {
	if Profile.HashesEncoding != csc.Base64Std || !Profile.AlwaysSendHashAlgorithmOID || !Profile.RequirePAR || Profile.TokenLifetime.Seconds() != 600 || Profile.RequestURILifetime.Seconds() != 60 {
		t.Fatalf("profile: %+v", Profile)
	}
}
