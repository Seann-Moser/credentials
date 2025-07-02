package session

import (
	"context"
)

type contextKey string

const (
	sessionKey contextKey = "USER_SESSION_DATA"
)
const sessionCookieName = "session"

// UserSessionData holds authenticated user information
type UserSessionData struct {
	UserID         string   `json:"user_id"`
	AccountID      string   `json:"account_id,omitempty"`
	Roles          []string `json:"roles,omitempty"`
	SignedIn       bool     `json:"signed_in"`
	ServiceAccount bool     `json:"service_account,omitempty"`
	ExpiresAt      int64    `json:"expires_at"`
	Domain         string   `json:"domain,omitempty"`
}

// WithContext attaches session data to context
func (u *UserSessionData) WithContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, sessionKey, u)
}

type TokenInfo struct {
	UserID    string
	AccountID string
	ExpiresIn int64
	Scopes    []string
}
