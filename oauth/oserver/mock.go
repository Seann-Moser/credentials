package oserver

import (
	"context"
	"net/http"
)

// MockOServer provides customizable hooks for testing OServer behavior.
type MockOServer struct {
	AuthorizeFunc       func(ctx context.Context, req AuthRequest) (*AuthResponse, error)
	TokenFunc           func(ctx context.Context, req TokenRequest) (*TokenResponse, error)
	RevokeFunc          func(ctx context.Context, req RevocationRequest) error
	IntrospectFunc      func(ctx context.Context, req IntrospectRequest) (*IntrospectResponse, error)
	JWKsFunc            func(ctx context.Context) (*JWKSet, error)
	RegisterClientFunc  func(ctx context.Context, client *OAuthClient) (*OAuthClient, error)
	UpdateClientFunc    func(ctx context.Context, client *OAuthClient) (*OAuthClient, error)
	DeleteClientFunc    func(ctx context.Context, clientID string) error
	GetClientFunc       func(ctx context.Context, clientID string) (*OAuthClient, error)
	ListClientsFunc     func(ctx context.Context, accountID string) ([]*OAuthClient, error)
	SetClientImageFunc  func(r *http.Request, clientID string) error
	SendClientImageFunc func(w http.ResponseWriter, r *http.Request, clientID string) error
	HasAccessFunc       func(r *http.Request, resource string, hasRbacAccess func(resource string, userId, accountId string, scopes ...string) bool) (bool, error)
}

// Ensure MockOServer implements OServer
var _ OServer = (*MockOServer)(nil)

// Authorize calls AuthorizeFunc if set, otherwise returns nil, nil
func (m *MockOServer) Authorize(ctx context.Context, req AuthRequest) (*AuthResponse, error) {
	if m.AuthorizeFunc != nil {
		return m.AuthorizeFunc(ctx, req)
	}
	return nil, nil
}

// Token calls TokenFunc if set, otherwise returns nil, nil
func (m *MockOServer) Token(ctx context.Context, req TokenRequest) (*TokenResponse, error) {
	if m.TokenFunc != nil {
		return m.TokenFunc(ctx, req)
	}
	return nil, nil
}

// Revoke calls RevokeFunc if set, otherwise returns nil
func (m *MockOServer) Revoke(ctx context.Context, req RevocationRequest) error {
	if m.RevokeFunc != nil {
		return m.RevokeFunc(ctx, req)
	}
	return nil
}

// Introspect calls IntrospectFunc if set, otherwise returns nil, nil
func (m *MockOServer) Introspect(ctx context.Context, req IntrospectRequest) (*IntrospectResponse, error) {
	if m.IntrospectFunc != nil {
		return m.IntrospectFunc(ctx, req)
	}
	return nil, nil
}

// JWKs calls JWKsFunc if set, otherwise returns nil, nil
func (m *MockOServer) JWKs(ctx context.Context) (*JWKSet, error) {
	if m.JWKsFunc != nil {
		return m.JWKsFunc(ctx)
	}
	return nil, nil
}

// RegisterClient calls RegisterClientFunc if set, otherwise returns client, nil
func (m *MockOServer) RegisterClient(ctx context.Context, client *OAuthClient) (*OAuthClient, error) {
	if m.RegisterClientFunc != nil {
		return m.RegisterClientFunc(ctx, client)
	}
	return client, nil
}

// UpdateClient calls UpdateClientFunc if set, otherwise returns client, nil
func (m *MockOServer) UpdateClient(ctx context.Context, client *OAuthClient) (*OAuthClient, error) {
	if m.UpdateClientFunc != nil {
		return m.UpdateClientFunc(ctx, client)
	}
	return client, nil
}

// DeleteClient calls DeleteClientFunc if set, otherwise returns nil
func (m *MockOServer) DeleteClient(ctx context.Context, clientID string) error {
	if m.DeleteClientFunc != nil {
		return m.DeleteClientFunc(ctx, clientID)
	}
	return nil
}

// GetClient calls GetClientFunc if set, otherwise returns nil, nil
func (m *MockOServer) GetClient(ctx context.Context, clientID string) (*OAuthClient, error) {
	if m.GetClientFunc != nil {
		return m.GetClientFunc(ctx, clientID)
	}
	return nil, nil
}

// ListClients calls ListClientsFunc if set, otherwise returns nil, nil
func (m *MockOServer) ListClients(ctx context.Context, accountID string) ([]*OAuthClient, error) {
	if m.ListClientsFunc != nil {
		return m.ListClientsFunc(ctx, accountID)
	}
	return nil, nil
}

// SetClientImage calls SetClientImageFunc if set, otherwise returns nil
func (m *MockOServer) SetClientImage(r *http.Request, clientID string) error {
	if m.SetClientImageFunc != nil {
		return m.SetClientImageFunc(r, clientID)
	}
	return nil
}

// SendClientImage calls SendClientImageFunc if set, otherwise returns nil
func (m *MockOServer) SendClientImage(w http.ResponseWriter, r *http.Request, clientID string) error {
	if m.SendClientImageFunc != nil {
		return m.SendClientImageFunc(w, r, clientID)
	}
	return nil
}

// HasAccess calls HasAccessFunc if set, otherwise returns false, nil
func (m *MockOServer) HasAccess(r *http.Request, resource string, hasRbacAccess func(resource string, userId, accountId string, scopes ...string) bool) (bool, error) {
	if m.HasAccessFunc != nil {
		return m.HasAccessFunc(r, resource, hasRbacAccess)
	}
	return false, nil
}
