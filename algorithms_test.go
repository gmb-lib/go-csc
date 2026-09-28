package csc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"testing"
	"time"
)

// certificate returns a self-signed certificate for key, valid from notBefore to notAfter.
func certificate(t *testing.T, key crypto.Signer, notBefore, notAfter time.Time) (*x509.Certificate, string) {
	t.Helper()
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test signer"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c, base64.StdEncoding.EncodeToString(der)
}

// [CSC API §11.7] key/algo lists the OIDs the credential signs with; [CSC API §11.13] signAlgo "SHALL be one
// of the values allowed by the credential", and a signAlgo that names no digest leaves it to hashAlgorithmOID.
func TestSignAlgoFor(t *testing.T) {
	ec := Credential{}
	ec.Key.Algo = []string{OIDECDSAWithSHA256, OIDECDSAWithSHA384, OIDECDSAWithSHA512}
	for digest, want := range map[string]string{OIDSHA256: OIDECDSAWithSHA256, OIDSHA384: OIDECDSAWithSHA384, OIDSHA512: OIDECDSAWithSHA512} {
		if got, err := ec.SignAlgoFor(digest); err != nil || got != want {
			t.Errorf("EC credential, digest %s: %q %v, want %q", digest, got, err, want)
		}
	}

	rsaCred := Credential{}
	rsaCred.Key.Algo = []string{OIDRSAEncryption, OIDSHA256WithRSA}
	if got, _ := rsaCred.SignAlgoFor(OIDSHA256); got != OIDSHA256WithRSA {
		t.Errorf("the algorithm that names the digest wins over the bare key algorithm: %q", got)
	}
	if got, _ := rsaCred.SignAlgoFor(OIDSHA384); got != OIDRSAEncryption {
		t.Errorf("without a matching combined algorithm the bare key algorithm is chosen: %q", got)
	}

	onlyOther := Credential{}
	onlyOther.Key.Algo = []string{OIDECDSAWithSHA256}
	if _, err := onlyOther.SignAlgoFor(OIDSHA384); !errors.Is(err, ErrNoSignAlgo) {
		t.Errorf("no algorithm for the digest must be refused: %v", err)
	}
	if _, err := ec.SignAlgoFor("1.2.3"); !errors.Is(err, ErrNoSignAlgo) {
		t.Errorf("an unknown digest algorithm must be refused: %v", err)
	}
	if DigestLength(OIDSHA384) != 48 || DigestLength(OIDSHA256) != 32 || DigestLength("1.2.3") != 0 {
		t.Error("DigestLength")
	}
}

// [CSC API §11.7] key/status, cert/status and multisign, and the end-entity certificate's validity period.
func TestCheckSigning(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	now := time.Now()
	_, b64 := certificate(t, key, now.Add(-time.Minute), now.Add(14*time.Minute))
	cred := func() Credential {
		var cr Credential
		cr.Key.Status = "enabled"
		cr.Cert.Status = "valid"
		cr.Cert.Certificates = []string{b64}
		cr.Multisign = 40
		return cr
	}

	if err := cred().CheckSigning(1, now); err != nil {
		t.Fatalf("a usable credential: %v", err)
	}
	if err := cred().CheckSigning(40, now.Add(10*time.Minute)); err != nil {
		t.Fatalf("multisign is the ceiling, inclusive: %v", err)
	}
	if err := cred().CheckSigning(41, now); !errors.Is(err, ErrMultisign) {
		t.Errorf("more than multisign: %v", err)
	}
	if err := cred().CheckSigning(1, now.Add(15*time.Minute)); !errors.Is(err, ErrCertificateValidity) {
		t.Errorf("after notAfter: %v", err)
	}
	if err := cred().CheckSigning(1, now.Add(-2*time.Minute)); !errors.Is(err, ErrCertificateValidity) {
		t.Errorf("before notBefore: %v", err)
	}
	disabled := cred()
	disabled.Key.Status = "disabled"
	if err := disabled.CheckSigning(1, now); !errors.Is(err, ErrKeyDisabled) {
		t.Errorf("a disabled key: %v", err)
	}
	expired := cred()
	expired.Cert.Status = "expired"
	if err := expired.CheckSigning(1, now); !errors.Is(err, ErrCertificateStatus) {
		t.Errorf("a certificate the service says is expired: %v", err)
	}
	silent := cred()
	silent.Key.Status, silent.Cert.Status, silent.Multisign = "", "", 0
	if err := silent.CheckSigning(5, now); err != nil {
		t.Errorf("absent optional members add no refusal: %v", err)
	}
	if err := (Credential{}).CheckSigning(1, now); err == nil {
		t.Error("a credential without a certificate cannot be checked, and must not pass")
	}
}

// [CSC API §11.13] signatures are the signed hashes; the application checks each against the credential's
// certificate before it embeds one.
func TestVerifySignatureECDSA(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	cert, _ := certificate(t, key, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	digest := sha512.Sum384([]byte("document"))

	der, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySignature(cert, OIDECDSAWithSHA384, "", digest[:], der); err != nil {
		t.Fatalf("DER signature: %v", err)
	}
	if err := VerifySignature(cert, OIDECPublicKey, OIDSHA384, digest[:], der); err != nil {
		t.Fatalf("a bare key algorithm takes the digest from hashAlgorithmOID: %v", err)
	}

	r, s, _ := ecdsa.Sign(rand.Reader, key, digest[:])
	raw := append(r.FillBytes(make([]byte, 48)), s.FillBytes(make([]byte, 48))...)
	if err := VerifySignature(cert, OIDECDSAWithSHA384, "", digest[:], raw); err != nil {
		t.Fatalf("raw r‖s signature: %v", err)
	}

	flipped := append([]byte(nil), der...)
	flipped[len(flipped)-1] ^= 1
	if err := VerifySignature(cert, OIDECDSAWithSHA384, "", digest[:], flipped); !errors.Is(err, ErrSignatureInvalid) {
		t.Errorf("one flipped bit: %v", err)
	}
	other := sha512.Sum384([]byte("another document"))
	if err := VerifySignature(cert, OIDECDSAWithSHA384, "", other[:], der); !errors.Is(err, ErrSignatureInvalid) {
		t.Errorf("a signature over another digest: %v", err)
	}
	short := sha256.Sum256([]byte("document"))
	if err := VerifySignature(cert, OIDECDSAWithSHA384, "", short[:], der); !errors.Is(err, ErrSignatureInvalid) {
		t.Errorf("a digest of the wrong length: %v", err)
	}
	if err := VerifySignature(cert, OIDSHA384WithRSA, "", digest[:], der); !errors.Is(err, ErrSignatureInvalid) {
		t.Errorf("an RSA algorithm on an EC key: %v", err)
	}
	if err := VerifySignature(cert, "1.2.840.113549.1.1.10", OIDSHA384, digest[:], der); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Errorf("an algorithm the core does not verify: %v", err)
	}
	if err := VerifySignature(cert, OIDECPublicKey, "", digest[:], der); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Errorf("a bare key algorithm without hashAlgorithmOID: %v", err)
	}
}

func TestVerifySignatureRSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := certificate(t, key, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	digest := sha256.Sum256([]byte("document"))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySignature(cert, OIDSHA256WithRSA, "", digest[:], sig); err != nil {
		t.Fatalf("sha256WithRSAEncryption: %v", err)
	}
	if err := VerifySignature(cert, OIDRSAEncryption, OIDSHA256, digest[:], sig); err != nil {
		t.Fatalf("rsaEncryption + hashAlgorithmOID: %v", err)
	}
	sig[0] ^= 1
	if err := VerifySignature(cert, OIDSHA256WithRSA, "", digest[:], sig); !errors.Is(err, ErrSignatureInvalid) {
		t.Errorf("a changed signature: %v", err)
	}
}
