// file: user/postgres_store.go
package user

import (
	"context"
	"crypto/hmac"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var _ Store = (*PostgresStore)(nil)

// PostgresStore implements the Store interface using PostgreSQL.
// Users are stored in a `users` table; passkeys are stored in a normalized
// `passkeys` table keyed by (user_id, credential_id).
type PostgresStore struct {
	db *pgxpool.Pool
}

// NewPostgresStore creates a new PostgresStore and ensures the schema exists.
func NewPostgresStore(ctx context.Context, db *pgxpool.Pool) (*PostgresStore, error) {
	s := &PostgresStore{db: db}
	if err := s.ensureSchema(ctx); err != nil {
		return nil, fmt.Errorf("postgres_store: ensure schema: %w", err)
	}
	return s, nil
}

// -----------------------------------------------------------------------------
// Schema
// -----------------------------------------------------------------------------

func (s *PostgresStore) ensureSchema(ctx context.Context) error {
	_, err := s.db.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS users (
			id            TEXT     PRIMARY KEY,
			username      TEXT     NOT NULL UNIQUE,
			password_hash BYTEA,
			roles         TEXT[]   NOT NULL DEFAULT '{}',
			totp_secret   TEXT     NOT NULL DEFAULT '',
			totp_enabled  BOOLEAN  NOT NULL DEFAULT FALSE,
			settings      JSONB
		);

		CREATE TABLE IF NOT EXISTS passkeys (
			user_id               TEXT     NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			credential_id         BYTEA    NOT NULL,
			public_key            BYTEA    NOT NULL,
			attestation_type      TEXT     NOT NULL DEFAULT '',
			aaguid                BYTEA    NOT NULL,
			sign_count            BIGINT   NOT NULL DEFAULT 0,
			transports            TEXT[]   NOT NULL DEFAULT '{}',
			credential_flags_byte SMALLINT NOT NULL DEFAULT 0,
			PRIMARY KEY (user_id, credential_id)
		);

		CREATE INDEX IF NOT EXISTS idx_passkeys_credential_id ON passkeys (credential_id);
	`)
	return err
}

// -----------------------------------------------------------------------------
// Users
// -----------------------------------------------------------------------------

// GetUserByID retrieves a user by their ID, including their passkeys.
func (s *PostgresStore) GetUserByID(ctx context.Context, userID string) (*User, error) {
	u, err := s.scanUser(ctx,
		`SELECT id, username, password_hash, roles, totp_secret, totp_enabled, settings
		 FROM users WHERE id = $1`, userID)
	if err != nil {
		return nil, err
	}
	if err := s.loadPasskeys(ctx, u); err != nil {
		return nil, err
	}
	return u, nil
}

// GetUserByUsername retrieves a user by their username, including their passkeys.
func (s *PostgresStore) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	u, err := s.scanUser(ctx,
		`SELECT id, username, password_hash, roles, totp_secret, totp_enabled, settings
		 FROM users WHERE username = $1`, username)
	if err != nil {
		return nil, err
	}
	if err := s.loadPasskeys(ctx, u); err != nil {
		return nil, err
	}
	return u, nil
}

// CreateUser inserts a new user, assigning a fresh UUID.
func (s *PostgresStore) CreateUser(ctx context.Context, user *User) error {
	user.ID = uuid.New().String()

	settingsJSON, err := marshalSettings(user.Settings)
	if err != nil {
		return err
	}

	_, err = s.db.Exec(ctx, `
		INSERT INTO users (id, username, password_hash, roles, totp_secret, totp_enabled, settings)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		user.ID,
		user.Username,
		user.PasswordHash,
		user.Roles,
		user.TOTPSecret,
		user.TOTPEnabled,
		settingsJSON,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return errors.New("user with this username already exists")
		}
		return fmt.Errorf("failed to create user: %w", err)
	}
	return nil
}

// UpdateUser replaces all mutable fields on an existing user.
// Passkeys are managed exclusively through the dedicated passkey methods
// and are not touched here.
func (s *PostgresStore) UpdateUser(ctx context.Context, user *User) error {
	settingsJSON, err := marshalSettings(user.Settings)
	if err != nil {
		return err
	}

	tag, err := s.db.Exec(ctx, `
		UPDATE users
		SET username      = $1,
		    password_hash = $2,
		    roles         = $3,
		    totp_secret   = $4,
		    totp_enabled  = $5,
		    settings      = $6
		WHERE id = $7`,
		user.Username,
		user.PasswordHash,
		user.Roles,
		user.TOTPSecret,
		user.TOTPEnabled,
		settingsJSON,
		user.ID,
	)
	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return errors.New("user not found")
	}
	return nil
}

// DeleteUser removes a user and all their passkeys (via ON DELETE CASCADE).
func (s *PostgresStore) DeleteUser(ctx context.Context, userID string) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM users WHERE id = $1`, userID)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return errors.New("user not found for deletion")
	}
	return nil
}

// -----------------------------------------------------------------------------
// Passkeys
// -----------------------------------------------------------------------------

// AddPasskey inserts a new WebAuthn credential for the given user.
func (s *PostgresStore) AddPasskey(ctx context.Context, userID string, credential webauthn.Credential) error {
	wc := FromWebAuthnCredential(credential)

	_, err := s.db.Exec(ctx, `
		INSERT INTO passkeys
			(user_id, credential_id, public_key, attestation_type, aaguid,
			 sign_count, transports, credential_flags_byte)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		userID,
		wc.ID,
		wc.PublicKey,
		wc.AttestationType,
		wc.AAGUID,
		wc.SignCount,
		wc.Transports,
		wc.CredentialFlagsByte,
	)
	if err != nil {
		return fmt.Errorf("failed to add passkey: %w", err)
	}
	return nil
}

// GetPasskeysByUserID returns all WebAuthn credentials for a user.
func (s *PostgresStore) GetPasskeysByUserID(ctx context.Context, userID string) ([]webauthn.Credential, error) {
	wcs, err := s.queryPasskeys(ctx,
		`SELECT credential_id, public_key, attestation_type, aaguid,
		        sign_count, transports, credential_flags_byte
		 FROM passkeys WHERE user_id = $1`, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get passkeys: %w", err)
	}

	creds := make([]webauthn.Credential, len(wcs))
	for i, wc := range wcs {
		creds[i] = wc.ToWebAuthnCredential()
	}
	return creds, nil
}

// GetPasskeyByCredentialID finds a passkey by its raw credential ID bytes,
// returning both the credential and its owning user.
func (s *PostgresStore) GetPasskeyByCredentialID(ctx context.Context, credentialID []byte) (*webauthn.Credential, *User, error) {
	// 1. Fetch the passkey row(s) matching this credential ID.
	wcs, err := s.queryPasskeys(ctx,
		`SELECT credential_id, public_key, attestation_type, aaguid,
		        sign_count, transports, credential_flags_byte
		 FROM passkeys WHERE credential_id = $1`, credentialID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get passkey by credential ID: %w", err)
	}
	if len(wcs) == 0 {
		return nil, nil, errors.New("passkey not found")
	}

	// 2. Confirm the match with hmac.Equal (mirrors the Mongo implementation).
	var matched *WebAuthnCredential
	for i := range wcs {
		if hmac.Equal(wcs[i].ID, credentialID) {
			matched = &wcs[i]
			break
		}
	}
	if matched == nil {
		return nil, nil, errors.New("passkey not found within results (desync?)")
	}

	// 3. Resolve the owning user ID from the passkeys table.
	var userID string
	err = s.db.QueryRow(ctx,
		`SELECT user_id FROM passkeys WHERE credential_id = $1`, credentialID).
		Scan(&userID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to resolve user for passkey: %w", err)
	}

	// 4. Load the full user (including their passkeys).
	user, err := s.GetUserByID(ctx, userID)
	if err != nil {
		return nil, nil, err
	}

	cred := matched.ToWebAuthnCredential()
	return &cred, user, nil
}

// UpdatePasskey updates the sign count for a specific credential.
func (s *PostgresStore) UpdatePasskey(ctx context.Context, userID string, credential webauthn.Credential) error {
	tag, err := s.db.Exec(ctx, `
		UPDATE passkeys SET sign_count = $1
		WHERE user_id = $2 AND credential_id = $3`,
		credential.Authenticator.SignCount,
		userID,
		credential.ID,
	)
	if err != nil {
		return fmt.Errorf("failed to update passkey: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return errors.New("passkey not found for update")
	}
	return nil
}

// DeletePasskey removes a specific passkey from a user.
func (s *PostgresStore) DeletePasskey(ctx context.Context, userID string, credentialID []byte) error {
	_, err := s.db.Exec(ctx, `
		DELETE FROM passkeys WHERE user_id = $1 AND credential_id = $2`,
		userID, credentialID)
	if err != nil {
		return fmt.Errorf("failed to delete passkey: %w", err)
	}
	return nil
}

// -----------------------------------------------------------------------------
// Private helpers
// -----------------------------------------------------------------------------

// scanUser executes a single-row query against the users table and decodes it.
func (s *PostgresStore) scanUser(ctx context.Context, query string, arg interface{}) (*User, error) {
	var (
		u            User
		settingsJSON []byte
	)
	err := s.db.QueryRow(ctx, query, arg).Scan(
		&u.ID,
		&u.Username,
		&u.PasswordHash,
		&u.Roles,
		&u.TOTPSecret,
		&u.TOTPEnabled,
		&settingsJSON,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errors.New("user not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to scan user: %w", err)
	}

	if len(settingsJSON) > 0 {
		if err := json.Unmarshal(settingsJSON, &u.Settings); err != nil {
			return nil, fmt.Errorf("failed to decode settings: %w", err)
		}
	}
	return &u, nil
}

// loadPasskeys fetches all passkeys for u and populates u.Passkeys.
func (s *PostgresStore) loadPasskeys(ctx context.Context, u *User) error {
	wcs, err := s.queryPasskeys(ctx,
		`SELECT credential_id, public_key, attestation_type, aaguid,
		        sign_count, transports, credential_flags_byte
		 FROM passkeys WHERE user_id = $1`, u.ID)
	if err != nil {
		return err
	}
	u.Passkeys = wcs
	return nil
}

// queryPasskeys runs any SELECT over the passkeys columns and returns a
// []WebAuthnCredential.
func (s *PostgresStore) queryPasskeys(ctx context.Context, query string, arg interface{}) ([]WebAuthnCredential, error) {
	rows, err := s.db.Query(ctx, query, arg)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []WebAuthnCredential
	for rows.Next() {
		var (
			wc        WebAuthnCredential
			flagsByte int16 // SMALLINT scans as int16
		)
		if err := rows.Scan(
			&wc.ID,
			&wc.PublicKey,
			&wc.AttestationType,
			&wc.AAGUID,
			&wc.SignCount,
			&wc.Transports,
			&flagsByte,
		); err != nil {
			return nil, err
		}
		wc.CredentialFlagsByte = byte(flagsByte)
		out = append(out, wc)
	}
	return out, rows.Err()
}

// marshalSettings encodes a settings map to JSON, returning nil for empty maps.
func marshalSettings(settings map[string]interface{}) ([]byte, error) {
	if len(settings) == 0 {
		return nil, nil
	}
	b, err := json.Marshal(settings)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal settings: %w", err)
	}
	return b, nil
}

// isUniqueViolation reports whether err is a Postgres unique-constraint
// violation (SQLSTATE 23505).
func isUniqueViolation(err error) bool {
	var pgErr interface{ SQLState() string }
	if errors.As(err, &pgErr) {
		return pgErr.SQLState() == "23505"
	}
	return false
}
