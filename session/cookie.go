package session

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

// GetSessionFromCookie reads and verifies the session cookie
func GetSessionFromCookie(r *http.Request, secret []byte) (*UserSessionData, error) {
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return nil, err
	}
	return decode(c, secret)
}

func decode(c *http.Cookie, secret []byte) (*UserSessionData, error) {
	parts := strings.Split(c.Value, "|")
	if len(parts) != 2 {
		return nil, errors.New("invalid session cookie format")
	}
	value, sig := parts[0], parts[1]
	if !validateHMAC(value, sig, secret) {
		return nil, errors.New("invalid session signature")
	}
	jsonData, err := base64.URLEncoding.DecodeString(value)
	if err != nil {
		return nil, err
	}
	var u UserSessionData
	if err := json.Unmarshal(jsonData, &u); err != nil {
		return nil, err
	}
	// Check expiration
	if time.Now().Unix() > u.ExpiresAt {
		return nil, errors.New("session expired")
	}
	return &u, nil
}

//""
