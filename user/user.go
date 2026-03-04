package user

import (
	"context"

	"github.com/go-webauthn/webauthn/webauthn"
)

// =============================================================================
// Database Interface
// =============================================================================

// Store defines the interface for user and passkey storage operations.
// This allows for different database backends (e.g., MongoDB, PostgreSQL, Redis).
type Store interface {
	// Users
	GetUserByID(ctx context.Context, userID string) (*User, error)
	GetUserByUsername(ctx context.Context, username string) (*User, error)
	CreateUser(ctx context.Context, user *User) error
	UpdateUser(ctx context.Context, user *User) error
	DeleteUser(ctx context.Context, userID string) error

	// Passkeys (Credentials)
	AddPasskey(ctx context.Context, userID string, credential webauthn.Credential) error
	GetPasskeysByUserID(ctx context.Context, userID string) ([]webauthn.Credential, error)
	GetPasskeyByCredentialID(ctx context.Context, credentialID []byte) (*webauthn.Credential, *User, error)
	UpdatePasskey(ctx context.Context, userID string, credential webauthn.Credential) error
	DeletePasskey(ctx context.Context, userID string, credentialID []byte) error
}
