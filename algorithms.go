package csc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// Object identifiers of the digest and signature algorithms the core names. The
// specification expresses every algorithm as an OID ([CSC API §7.6]).
const (
	OIDSHA256 = "2.16.840.1.101.3.4.2.1"
	OIDSHA384 = "2.16.840.1.101.3.4.2.2"
	OIDSHA512 = "2.16.840.1.101.3.4.2.3"

	// OIDECPublicKey and OIDRSAEncryption name a key algorithm without a digest;
	// a signAlgo of either needs hashAlgorithmOID beside it ([CSC API §11.13]).
	OIDECPublicKey   = "1.2.840.10045.2.1"
	OIDRSAEncryption = "1.2.840.113549.1.1.1"

	OIDECDSAWithSHA256 = "1.2.840.10045.4.3.2"
	OIDECDSAWithSHA384 = "1.2.840.10045.4.3.3"
	OIDECDSAWithSHA512 = "1.2.840.10045.4.3.4"

	OIDSHA256WithRSA = "1.2.840.113549.1.1.11"
	OIDSHA384WithRSA = "1.2.840.113549.1.1.12"
	OIDSHA512WithRSA = "1.2.840.113549.1.1.13"
)

// digestAlgorithms maps a digest OID to the Go hash that produces it.
var digestAlgorithms = map[string]crypto.Hash{
	OIDSHA256: crypto.SHA256,
	OIDSHA384: crypto.SHA384,
	OIDSHA512: crypto.SHA512,
}

// signatureAlgorithm is what a signature-algorithm OID says: the key family and,
// when the OID names one, the digest.
type signatureAlgorithm struct {
	family string // "ec" | "rsa"
	digest string // a digest OID, or "" when the OID leaves it to hashAlgorithmOID
}

var signatureAlgorithms = map[string]signatureAlgorithm{
	OIDECPublicKey:     {family: "ec"},
	OIDECDSAWithSHA256: {family: "ec", digest: OIDSHA256},
	OIDECDSAWithSHA384: {family: "ec", digest: OIDSHA384},
	OIDECDSAWithSHA512: {family: "ec", digest: OIDSHA512},
	OIDRSAEncryption:   {family: "rsa"},
	OIDSHA256WithRSA:   {family: "rsa", digest: OIDSHA256},
	OIDSHA384WithRSA:   {family: "rsa", digest: OIDSHA384},
	OIDSHA512WithRSA:   {family: "rsa", digest: OIDSHA512},
}

// DigestLength returns the length in bytes of a digest the OID names, or 0 for a
// digest algorithm the core does not know.
func DigestLength(hashAlgorithmOID string) int {
	if h, ok := digestAlgorithms[hashAlgorithmOID]; ok {
		return h.Size()
	}
	return 0
}

// ErrNoSignAlgo is returned when none of the credential's key algorithms can sign
// a digest of the requested algorithm.
var ErrNoSignAlgo = errors.New("csc: the credential offers no signature algorithm for this digest")

// SignAlgoFor chooses the signAlgo for signHash from the credential's key/algo list
// ([CSC API §11.7]; the signHash signAlgo "SHALL be one of the values allowed by the
// credential"): the algorithm that names this digest when the credential lists
// one (ECDSA-with-SHA384 for SHA-384), otherwise the bare key algorithm
// (rsaEncryption, ecPublicKey), which leaves the digest to hashAlgorithmOID.
func (cr Credential) SignAlgoFor(hashAlgorithmOID string) (string, error) {
	if _, ok := digestAlgorithms[hashAlgorithmOID]; !ok {
		return "", fmt.Errorf("%w: unknown digest algorithm %q", ErrNoSignAlgo, hashAlgorithmOID)
	}
	bare := ""
	for _, a := range cr.Key.Algo {
		sa, ok := signatureAlgorithms[a]
		if !ok {
			continue
		}
		if sa.digest == hashAlgorithmOID {
			return a, nil
		}
		if sa.digest == "" && bare == "" {
			bare = a
		}
	}
	if bare != "" {
		return bare, nil
	}
	return "", fmt.Errorf("%w: key/algo %v, digest %s", ErrNoSignAlgo, cr.Key.Algo, hashAlgorithmOID)
}

// Certificate parses the credential's end-entity certificate (the first of
// cert/certificates).
func (cr Credential) Certificate() (*x509.Certificate, error) {
	der, err := cr.LeafCertificate()
	if err != nil {
		return nil, err
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("csc: the credential's certificate does not parse: %w", err)
	}
	return c, nil
}

// Reasons CheckSigning refuses a credential.
var (
	ErrKeyDisabled         = errors.New("csc: the credential's key is not enabled")
	ErrCertificateStatus   = errors.New("csc: the credential's certificate is not valid")
	ErrCertificateValidity = errors.New("csc: the credential's certificate is outside its validity period")
	ErrMultisign           = errors.New("csc: more signatures than the credential allows in one authorization")
)

// CheckSigning reports whether the credential can create numSignatures signatures
// at the moment at: its key is enabled and its certificate valid ([CSC API §11.7]
// key/status, cert/status, when the service returns them), at is inside the
// end-entity certificate's validity period, and numSignatures does not exceed
// multisign, the most one authorization allows ([CSC API §11.7]). A caller that
// needs the credential to stay usable through an authorization still to come
// passes a moment in the future.
func (cr Credential) CheckSigning(numSignatures int, at time.Time) error {
	if cr.Key.Status != "" && cr.Key.Status != "enabled" {
		return fmt.Errorf("%w: key/status %q", ErrKeyDisabled, cr.Key.Status)
	}
	if cr.Cert.Status != "" && cr.Cert.Status != "valid" {
		return fmt.Errorf("%w: cert/status %q", ErrCertificateStatus, cr.Cert.Status)
	}
	if cr.Multisign > 0 && numSignatures > cr.Multisign {
		return fmt.Errorf("%w: %d signatures, multisign %d", ErrMultisign, numSignatures, cr.Multisign)
	}
	c, err := cr.Certificate()
	if err != nil {
		return err
	}
	if at.Before(c.NotBefore) || at.After(c.NotAfter) {
		return fmt.Errorf("%w: %s is outside %s to %s", ErrCertificateValidity,
			at.UTC().Format(time.RFC3339), c.NotBefore.UTC().Format(time.RFC3339), c.NotAfter.UTC().Format(time.RFC3339))
	}
	return nil
}

// Reasons VerifySignature refuses a signature.
var (
	ErrSignatureInvalid     = errors.New("csc: the signature does not verify against the certificate")
	ErrUnsupportedAlgorithm = errors.New("csc: signature algorithm not supported for verification")
)

// VerifySignature checks one signatures/signHash result against the certificate
// it claims: signature must be a signature by the certificate's key over digest,
// made with signAlgo (and hashAlgorithmOID when signAlgo names no digest). ECDSA
// signatures are accepted DER-encoded (an ECDSA-Sig-Value) or as raw r‖s; RSA
// signatures are PKCS #1 v1.5. The signing application verifies before it embeds a
// signature, so a value that is not the signature it asked for never reaches a
// document.
func VerifySignature(cert *x509.Certificate, signAlgo, hashAlgorithmOID string, digest, signature []byte) error {
	sa, ok := signatureAlgorithms[signAlgo]
	if !ok {
		return fmt.Errorf("%w: %q", ErrUnsupportedAlgorithm, signAlgo)
	}
	digestOID := sa.digest
	if digestOID == "" {
		digestOID = hashAlgorithmOID
	}
	h, ok := digestAlgorithms[digestOID]
	if !ok {
		return fmt.Errorf("%w: digest %q", ErrUnsupportedAlgorithm, digestOID)
	}
	if len(digest) != h.Size() {
		return fmt.Errorf("%w: a %d-byte digest for a %d-byte algorithm", ErrSignatureInvalid, len(digest), h.Size())
	}
	switch k := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if sa.family != "ec" {
			return fmt.Errorf("%w: an EC key and signAlgo %s", ErrSignatureInvalid, signAlgo)
		}
		if ecdsa.VerifyASN1(k, digest, signature) {
			return nil
		}
		n := (k.Curve.Params().BitSize + 7) / 8
		if len(signature) == 2*n {
			r := new(big.Int).SetBytes(signature[:n])
			s := new(big.Int).SetBytes(signature[n:])
			if ecdsa.Verify(k, digest, r, s) {
				return nil
			}
		}
		return ErrSignatureInvalid
	case *rsa.PublicKey:
		if sa.family != "rsa" {
			return fmt.Errorf("%w: an RSA key and signAlgo %s", ErrSignatureInvalid, signAlgo)
		}
		if err := rsa.VerifyPKCS1v15(k, h, digest, signature); err != nil {
			return ErrSignatureInvalid
		}
		return nil
	default:
		return fmt.Errorf("%w: public key %T", ErrUnsupportedAlgorithm, cert.PublicKey)
	}
}
