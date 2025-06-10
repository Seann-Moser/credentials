package oserver

import (
	"context"
	"net/http"
)

type OServer interface {
	// --- OAuth2 endpoints ---
	Authorize(ctx context.Context, req AuthRequest) (*AuthResponse, error)
	Token(ctx context.Context, req TokenRequest) (*TokenResponse, error)
	Revoke(ctx context.Context, req RevocationRequest) error
	Introspect(ctx context.Context, req IntrospectRequest) (*IntrospectResponse, error)
	JWKs(ctx context.Context) (*JWKSet, error)

	// --- client management ---
	RegisterClient(ctx context.Context, client *OAuthClient) (*OAuthClient, error)
	UpdateClient(ctx context.Context, client *OAuthClient) (*OAuthClient, error)
	DeleteClient(ctx context.Context, clientID string) error
	GetClient(ctx context.Context, clientID string) (*OAuthClient, error)
	ListClients(ctx context.Context, accountID string) ([]*OAuthClient, error)

	// --- convenience on HTTP handlers ---
	SetClientImage(r *http.Request, clientID string) error
	SendClientImage(w http.ResponseWriter, r *http.Request, clientID string) error

	HasAccess(r *http.Request, resource string, hasRbacAccess func(resource string, userId string, scopes ...string) bool) (bool, error)
}
