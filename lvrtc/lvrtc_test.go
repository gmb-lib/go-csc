package lvrtc

import (
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"testing"

	"github.com/gmb-lib/go-csc"
)

// The provider guide's two token responses (its sections 11.4 and 15.4), read as the profile's vocabulary.
const (
	credentialTokenJSON = `{"access_token":"a","token_type":"Bearer","expires_in":120,"authorization_details":[{"type":"sign_identity_registration","group_labels":["urn:csc:signatureQualifier:eu_eidas_qes"]}],"credentialID":"cred-1"}`
	signTokenJSON       = `{"access_token":"b","token_type":"Bearer","expires_in":120,"authorization_details":[{"type":"digest_signing","digests":[{"value":"%s","algorithm":"SHA-384"}],"sign_identity_id":"cred-1","num_signatures":1}]}`
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

func TestProfileValues(t *testing.T) {
	if Profile.HashesEncoding != csc.Base64Std || !Profile.AlwaysSendHashAlgorithmOID || !Profile.RequirePAR || Profile.TokenLifetime.Seconds() != 120 || Profile.RequestURILifetime.Seconds() != 60 {
		t.Fatalf("profile: %+v", Profile)
	}
}
