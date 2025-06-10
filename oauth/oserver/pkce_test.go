package oserver

import (
	"regexp"
	"testing"
)

func TestGenerateCodeVerifier(t *testing.T) {
	const minLen, maxLen = 43, 128

	v1, err := GenerateCodeVerifier()
	if err != nil {
		t.Fatalf("GenerateCodeVerifier returned error: %v", err)
	}
	if l := len(v1); l < minLen || l > maxLen {
		t.Errorf("verifier length = %d, want between %d and %d", l, minLen, maxLen)
	}

	// only URL‐safe base64 chars (A–Z, a–z, 0–9, '-', '_')
	validChars := regexp.MustCompile(`^[A-Za-z0-9\-_]+$`)
	if !validChars.MatchString(v1) {
		t.Errorf("verifier contains invalid characters: %q", v1)
	}

	// ensure two successive calls differ (extremely unlikely to collide)
	v2, err := GenerateCodeVerifier()
	if err != nil {
		t.Fatalf("GenerateCodeVerifier returned error: %v", err)
	}
	if v1 == v2 {
		t.Errorf("two verifiers should not be equal (got %q twice)", v1)
	}
}

func TestGenerateCodeChallenge_RFCExample(t *testing.T) {
	// Example from RFC 7636 §4.2:
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	want := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	got := GenerateCodeChallenge(verifier)
	if got != want {
		t.Errorf("GenerateCodeChallenge(%q) = %q; want %q", verifier, got, want)
	}
}

func TestValidateCodeChallenge(t *testing.T) {
	// matching case
	verifier := "test-verifier-123"
	challenge := GenerateCodeChallenge(verifier)
	if !ValidateCodeChallenge(verifier, challenge) {
		t.Errorf("ValidateCodeChallenge should succeed for matching verifier/challenge")
	}

	// non‐matching case
	if ValidateCodeChallenge(verifier, challenge+"x") {
		t.Errorf("ValidateCodeChallenge should fail for non-matching challenge")
	}
	
}
