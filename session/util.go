package session

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

var SameSite = http.SameSiteNoneMode
var UseDomain = false

func GetSession(ctx context.Context) (*UserSessionData, error) {
	v := ctx.Value(sessionKey)
	if v == nil {
		return nil, errors.New("no session in context")
	}
	u, ok := v.(*UserSessionData)
	if !ok {
		return nil, errors.New("invalid session type in context")
	}
	return u, nil
}

// Compute HMAC-SHA256 signature of a message using secret
func computeHMAC(message string, secret []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(message))
	return base64.URLEncoding.EncodeToString(mac.Sum(nil))
}

// Validate HMAC signature
func validateHMAC(message, sig string, secret []byte) bool {
	expected := computeHMAC(message, secret)
	return hmac.Equal([]byte(sig), []byte(expected))
}

// SetSessionCookie serializes session data, signs it, and sets it as an HTTP cookie
func SetSessionCookie(w http.ResponseWriter, u *UserSessionData, secret []byte) error {
	// JSON encode
	jsonData, err := json.Marshal(u)
	if err != nil {
		return err
	}
	// Base64 encode
	value := base64.URLEncoding.EncodeToString(jsonData)
	// Sign
	sig := computeHMAC(value, secret)
	cookieValue := fmt.Sprintf("%s|%s", value, sig)
	var expires time.Time
	if u.ExpiresAt > 0 {
		expires = time.Unix(u.ExpiresAt, 0)
	}
	c := &http.Cookie{
		Name:        sessionCookieName,
		Value:       cookieValue,
		Path:        "/",
		Expires:     expires,
		HttpOnly:    false,
		Secure:      true,
		SameSite:    SameSite,
		Partitioned: true,
	}
	if UseDomain {
		c.Domain = u.Domain
	}
	http.SetCookie(w, c)
	return nil
}

// ClearSessionCookie clears the session cookie by setting its expiration to a past date.
func ClearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0), // Set to a past time to expire immediately
		HttpOnly: true,
		Secure:   true,
		SameSite: SameSite,
	})
}
