package session

import (
	"context"
	"fmt"
	"github.com/Seann-Moser/credentials/oauth/oserver"
	"github.com/Seann-Moser/credentials/utils"
	"github.com/Seann-Moser/rbac"
	"net/http"
	"strings"
	"time"
)

// Client manages authentication, session cookies, and role loading
type Client struct {
	ttl         time.Duration
	secret      []byte
	oauthServer oserver.OServer
	rbacManager *rbac.Manager
}

// NewClient constructs a Client
func NewClient(oauthServer oserver.OServer, rbacManager *rbac.Manager, secret []byte, sessionTTL time.Duration) *Client {
	return &Client{
		ttl:         sessionTTL,
		secret:      secret,
		oauthServer: oauthServer,
		rbacManager: rbacManager,
	}
}

// Authenticate loads or creates a session, storing it in a cookie and context
func (c *Client) Authenticate(w http.ResponseWriter, r *http.Request) (*UserSessionData, context.Context, error) {
	// Try cookie
	u, err := GetSessionFromCookie(r, c.secret)
	if err == nil {
		// attach to context
		reqCtx := u.WithContext(r.Context())
		return u, reqCtx, nil
	}
	// Fall back to OAuth introspection
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(strings.ToLower(authHeader), "bearer ") && c.oauthServer != nil {
		token := strings.TrimSpace(authHeader[7:])
		info, err := c.oauthServer.Introspect(r.Context(), oserver.IntrospectRequest{
			Token: token,
		})
		if err == nil && info != nil && info.Active {
			// build session
			u = &UserSessionData{
				UserID:         info.UserID,
				AccountID:      info.AccountID,
				SignedIn:       true,
				ServiceAccount: strings.HasPrefix(info.UserID, "service-"),
				ExpiresAt:      info.Exp,
				Domain:         utils.GetDomain(r),
			}
			// load roles
			roles, err := c.rbacManager.ListRolesForUser(r.Context(), u.UserID)
			if err == nil {
				u.Roles = roles
			}
			// set cookie
			_ = SetSessionCookie(w, u, c.secret)
			reqCtx := u.WithContext(r.Context())
			return u, reqCtx, nil
		}
	}
	// Anonymous session
	u = &UserSessionData{
		UserID:    fmt.Sprintf("anon-%d", time.Now().UnixNano()),
		SignedIn:  false,
		ExpiresAt: time.Now().Add(c.ttl).Unix(),
		Roles:     []string{"default"},
		Domain:    utils.GetDomain(r),
	}
	_ = SetSessionCookie(w, u, c.secret)
	reqCtx := u.WithContext(r.Context())
	return u, reqCtx, nil
}
