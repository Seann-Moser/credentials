package oclient

import "context"

// OAuthService defines all operations around integrations and tokens
type OAuthService interface {
	// ----- Integration management -----

	// AddIntegration registers a new OAuth client configuration for an account.
	AddIntegration(ctx context.Context, accountID string, integration Integration) error

	// UpdateIntegration updates the client credentials or settings.
	UpdateIntegration(ctx context.Context, accountID, provider string, integration Integration) error

	// DeleteIntegration removes the integration and any associated tokens.
	DeleteIntegration(ctx context.Context, accountID, provider string) error

	// ListIntegrations returns all configured OAuth providers for an account.
	ListIntegrations(ctx context.Context, accountID string) ([]Integration, error)

	// GetIntegration fetches the integration details for one provider.
	GetIntegration(ctx context.Context, accountID, provider string) (Integration, error)

	// ----- Token management -----

	// StoreTokens persists a user's access + refresh token pair.
	StoreTokens(ctx context.Context, accountID, userID, provider string, tokens TokenPair) error

	// GetTokens retrieves the last-stored tokens for a user+provider.
	GetTokens(ctx context.Context, accountID, userID, provider string) (TokenPair, error)

	// RefreshTokens uses the refresh token to obtain a new access token (and possibly a new refresh token).
	RefreshTokens(ctx context.Context, accountID, userID, provider string) (TokenPair, error)

	// RevokeTokens revokes both access and refresh tokens for the user+provider.
	RevokeTokens(ctx context.Context, accountID, userID, provider string) error

	// DeleteTokens deletes any stored token pair (e.g. when unlinking).
	DeleteTokens(ctx context.Context, accountID, userID, provider string) error
}
