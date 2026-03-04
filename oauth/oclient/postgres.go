// file: oclient/postgres_oauth_service.go
package oclient

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/oauth2"
)

var _ OAuthService = &PostgresOAuthService{}

// PostgresOAuthService is a PostgreSQL-backed implementation of OAuthService.
type PostgresOAuthService struct {
	db *pgxpool.Pool
}

// NewPostgresOAuthService creates a new service and ensures the schema exists.
func NewPostgresOAuthService(ctx context.Context, db *pgxpool.Pool) (*PostgresOAuthService, error) {
	s := &PostgresOAuthService{db: db}
	if err := s.ensureSchema(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

// -----------------------------------------------------------------------------
// Schema
// -----------------------------------------------------------------------------

func (s *PostgresOAuthService) ensureSchema(ctx context.Context) error {
	_, err := s.db.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS oauth_integrations (
			account_id    TEXT        NOT NULL,
			provider      TEXT        NOT NULL,
			client_id     TEXT        NOT NULL DEFAULT '',
			client_secret TEXT        NOT NULL DEFAULT '',
			redirect_url  TEXT        NOT NULL DEFAULT '',
			scopes        TEXT[]      NOT NULL DEFAULT '{}',
			created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			PRIMARY KEY (account_id, provider)
		);

		CREATE TABLE IF NOT EXISTS oauth_tokens (
			account_id    TEXT        NOT NULL,
			user_id       TEXT        NOT NULL,
			provider      TEXT        NOT NULL,
			access_token  TEXT        NOT NULL DEFAULT '',
			refresh_token TEXT        NOT NULL DEFAULT '',
			expires_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			issued_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			PRIMARY KEY (account_id, user_id, provider)
		);
	`)
	return err
}

// -----------------------------------------------------------------------------
// Integrations
// -----------------------------------------------------------------------------

// AddIntegration registers a new OAuth client configuration.
func (s *PostgresOAuthService) AddIntegration(ctx context.Context, accountID string, in Integration) error {
	now := time.Now().UTC()
	_, err := s.db.Exec(ctx, `
		INSERT INTO oauth_integrations
			(account_id, provider, client_id, client_secret, redirect_url, scopes, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		accountID,
		in.Provider,
		in.ClientID,
		in.ClientSecret,
		in.RedirectURL,
		in.Scopes,
		now,
		now,
	)
	return err
}

// UpdateIntegration updates client credentials or settings.
func (s *PostgresOAuthService) UpdateIntegration(ctx context.Context, accountID, provider string, in Integration) error {
	tag, err := s.db.Exec(ctx, `
		UPDATE oauth_integrations
		SET client_id     = $1,
		    client_secret = $2,
		    redirect_url  = $3,
		    scopes        = $4,
		    updated_at    = $5
		WHERE account_id = $6 AND provider = $7`,
		in.ClientID,
		in.ClientSecret,
		in.RedirectURL,
		in.Scopes,
		time.Now().UTC(),
		accountID,
		provider,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return errors.New("integration not found")
	}
	return nil
}

// DeleteIntegration removes the integration and all its associated tokens.
func (s *PostgresOAuthService) DeleteIntegration(ctx context.Context, accountID, provider string) error {
	// Remove tokens first (no FK cascade in schema to keep it simple).
	_, err := s.db.Exec(ctx,
		`DELETE FROM oauth_tokens WHERE account_id = $1 AND provider = $2`,
		accountID, provider)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(ctx,
		`DELETE FROM oauth_integrations WHERE account_id = $1 AND provider = $2`,
		accountID, provider)
	return err
}

// ListIntegrations returns all OAuth configs for an account.
func (s *PostgresOAuthService) ListIntegrations(ctx context.Context, accountID string) ([]Integration, error) {
	rows, err := s.db.Query(ctx, `
		SELECT provider, client_id, client_secret, redirect_url, scopes, created_at, updated_at
		FROM oauth_integrations
		WHERE account_id = $1`, accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Integration
	for rows.Next() {
		var in Integration
		if err := rows.Scan(
			&in.Provider,
			&in.ClientID,
			&in.ClientSecret,
			&in.RedirectURL,
			&in.Scopes,
			&in.CreatedAt,
			&in.UpdatedAt,
		); err != nil {
			return nil, err
		}
		out = append(out, in)
	}
	return out, rows.Err()
}

// GetIntegration fetches one provider's config for an account.
func (s *PostgresOAuthService) GetIntegration(ctx context.Context, accountID, provider string) (Integration, error) {
	var in Integration
	err := s.db.QueryRow(ctx, `
		SELECT provider, client_id, client_secret, redirect_url, scopes, created_at, updated_at
		FROM oauth_integrations
		WHERE account_id = $1 AND provider = $2`,
		accountID, provider).
		Scan(
			&in.Provider,
			&in.ClientID,
			&in.ClientSecret,
			&in.RedirectURL,
			&in.Scopes,
			&in.CreatedAt,
			&in.UpdatedAt,
		)
	if errors.Is(err, pgx.ErrNoRows) {
		return Integration{}, errors.New("integration not found")
	}
	if err != nil {
		return Integration{}, err
	}
	return in, nil
}

// -----------------------------------------------------------------------------
// Tokens
// -----------------------------------------------------------------------------

// StoreTokens upserts a user's token pair.
func (s *PostgresOAuthService) StoreTokens(ctx context.Context, accountID, userID, provider string, t TokenPair) error {
	_, err := s.db.Exec(ctx, `
		INSERT INTO oauth_tokens
			(account_id, user_id, provider, access_token, refresh_token, expires_at, issued_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (account_id, user_id, provider) DO UPDATE
			SET access_token  = EXCLUDED.access_token,
			    refresh_token = EXCLUDED.refresh_token,
			    expires_at    = EXCLUDED.expires_at,
			    issued_at     = EXCLUDED.issued_at`,
		accountID,
		userID,
		provider,
		t.AccessToken,
		t.RefreshToken,
		t.ExpiresAt,
		t.IssuedAt,
	)
	return err
}

// GetTokens retrieves stored tokens, auto-refreshing if expired or expiring soon.
func (s *PostgresOAuthService) GetTokens(ctx context.Context, accountID, userID, provider string) (TokenPair, error) {
	var t TokenPair
	err := s.db.QueryRow(ctx, `
		SELECT access_token, refresh_token, expires_at, issued_at
		FROM oauth_tokens
		WHERE account_id = $1 AND user_id = $2 AND provider = $3`,
		accountID, userID, provider).
		Scan(&t.AccessToken, &t.RefreshToken, &t.ExpiresAt, &t.IssuedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return TokenPair{}, errors.New("tokens not found")
	}
	if err != nil {
		return TokenPair{}, err
	}

	// Refresh if expired or within the 1-minute safety window.
	if time.Now().UTC().Add(time.Minute).After(t.ExpiresAt) {
		return s.RefreshTokens(ctx, accountID, userID, provider)
	}
	return t, nil
}

// RefreshTokens uses OAuth2 to fetch a new access (and maybe refresh) token.
func (s *PostgresOAuthService) RefreshTokens(ctx context.Context, accountID, userID, provider string) (TokenPair, error) {
	cfg, err := s.GetIntegration(ctx, accountID, provider)
	if err != nil {
		return TokenPair{}, err
	}

	old, err := s.getRawTokens(ctx, accountID, userID, provider)
	if err != nil {
		return TokenPair{}, err
	}

	oauthCfg := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  "",
			TokenURL: "",
		},
		RedirectURL: cfg.RedirectURL,
		Scopes:      cfg.Scopes,
	}
	ts := oauthCfg.TokenSource(ctx, &oauth2.Token{
		AccessToken:  old.AccessToken,
		RefreshToken: old.RefreshToken,
		Expiry:       old.ExpiresAt,
	})
	newTok, err := ts.Token()
	if err != nil {
		return TokenPair{}, err
	}

	updated := TokenPair{
		AccessToken:  newTok.AccessToken,
		RefreshToken: newTok.RefreshToken,
		ExpiresAt:    newTok.Expiry,
		IssuedAt:     time.Now().UTC(),
	}
	if err := s.StoreTokens(ctx, accountID, userID, provider, updated); err != nil {
		return TokenPair{}, err
	}
	return updated, nil
}

// RevokeTokens revokes (deletes) a user's stored tokens.
func (s *PostgresOAuthService) RevokeTokens(ctx context.Context, accountID, userID, provider string) error {
	return s.DeleteTokens(ctx, accountID, userID, provider)
}

// DeleteTokens removes stored tokens for a user/provider pair.
func (s *PostgresOAuthService) DeleteTokens(ctx context.Context, accountID, userID, provider string) error {
	_, err := s.db.Exec(ctx, `
		DELETE FROM oauth_tokens
		WHERE account_id = $1 AND user_id = $2 AND provider = $3`,
		accountID, userID, provider)
	return err
}

// -----------------------------------------------------------------------------
// Private helpers
// -----------------------------------------------------------------------------

// getRawTokens fetches tokens without triggering a refresh — used internally
// by RefreshTokens to avoid infinite recursion.
func (s *PostgresOAuthService) getRawTokens(ctx context.Context, accountID, userID, provider string) (TokenPair, error) {
	var t TokenPair
	err := s.db.QueryRow(ctx, `
		SELECT access_token, refresh_token, expires_at, issued_at
		FROM oauth_tokens
		WHERE account_id = $1 AND user_id = $2 AND provider = $3`,
		accountID, userID, provider).
		Scan(&t.AccessToken, &t.RefreshToken, &t.ExpiresAt, &t.IssuedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return TokenPair{}, errors.New("tokens not found")
	}
	return t, err
}
