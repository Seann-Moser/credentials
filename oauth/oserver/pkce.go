package oserver

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// GenerateCodeVerifier returns a cryptographically-secure random string
// (code_verifier) conforming to RFC 7636 (length 43–128, unreserved chars).
func GenerateCodeVerifier() (string, error) {
	// 64 random bytes → 86-character base64url string (within 43–128)
	b := make([]byte, 64)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("pkce: failed to generate verifier: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// GenerateCodeChallenge returns the S256 code_challenge for the given verifier.
func GenerateCodeChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// ValidateCodeChallenge checks that SHA256(verifier) matches the challenge.
func ValidateCodeChallenge(verifier, challenge string) bool {
	return GenerateCodeChallenge(verifier) == challenge
}
