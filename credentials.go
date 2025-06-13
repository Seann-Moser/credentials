package credentials

import (
	"fmt"
	"net/http"

	"github.com/Seann-Moser/credentials/oauth/oserver"
	"github.com/Seann-Moser/rbac"
)

type Credentials struct {
	oServer oserver.OServer
	rbac    rbac.Manager
}

func NewCredentials(oServer oserver.OServer, rba rbac.Manager) *Credentials {
	return &Credentials{
		oServer: oServer,
		rbac:    rba,
	}
}
func (c *Credentials) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := fullURL(r)
		hasAccess, err := c.oServer.HasAccess(r, u, func(resource string, userId string, scopes ...string) bool {
			_, _ = c.rbac.HasPermission(r.Context(), userId, resource) //todo idk

			return false
		})
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if !hasAccess {
			w.WriteHeader(http.StatusForbidden)
			return
		}

	})
}

func fullURL(r *http.Request) string {
	// Default to the original scheme
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}

	host := r.Host
	if fwdHost := r.Header.Get("Host"); fwdHost != "" {
		host = fwdHost
		scheme = "https"
	}

	// Trust X-Forwarded-Proto if set (e.g., behind Nginx)
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		scheme = proto
	}

	// Use X-Forwarded-Host if available
	if fwdHost := r.Header.Get("X-Forwarded-Host"); fwdHost != "" {
		host = fwdHost
		scheme = "https"
	}

	return fmt.Sprintf("%s://%s%s", scheme, host, r.RequestURI)
}

type UserCredentials struct {
	ID        string   `json:"id"`
	AccountID string   `json:"account_id"`
	Username  string   `json:"username"`
	Roles     []string `json:"roles"`
}
