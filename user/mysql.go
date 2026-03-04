// file: user/mysql_store.go
package user

import (
	"context"
	"crypto/hmac"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	_ "github.com/go-sql-driver/mysql"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
)

var _ Store = (*MySQLStore)(nil)

// MySQLStore implements the Store interface using MySQL.
// Users are stored in a `users` table; passkeys are stored in a normalized
// `passkeys` table keyed by (user_id, credential_id).
type MySQLStore struct {
	db *sql.DB
}

// NewMySQLStore creates a new MySQLStore and ensures the schema exists.
func NewMySQLStore(ctx context.Context, db *sql.DB) (*MySQLStore, error) {
	s := &MySQLStore{db: db}
	if err := s.ensureSchema(ctx); err != nil {
		return nil, fmt.Errorf("mysql_store: ensure schema: %w", err)
	}
	return s, nil
}

// -----------------------------------------------------------------------------
// Schema
// -----------------------------------------------------------------------------

func (s *MySQLStore) ensureSchema(ctx context.Context) error {
	// MySQL requires separate ExecContext calls per statement.
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id            VARCHAR(36)     NOT NULL PRIMARY KEY,
			username      VARCHAR(255)    NOT NULL UNIQUE,
			password_hash BLOB,
			roles         JSON            NOT NULL,
			totp_secret   VARCHAR(512)    NOT NULL DEFAULT '',
			totp_enabled  TINYINT(1)      NOT NULL DEFAULT 0,
			settings      JSON
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,

		// credential_id is arbitrary-length bytes; prefix the key to satisfy
		// MySQL's index key length limit (767 bytes for utf8mb4).
		// The secondary index is declared inline because MySQL does not support
		// CREATE INDEX IF NOT EXISTS.
		`CREATE TABLE IF NOT EXISTS passkeys (
			user_id               VARCHAR(36)      NOT NULL,
			credential_id         VARBINARY(1024)  NOT NULL,
			public_key            BLOB             NOT NULL,
			attestation_type      VARCHAR(64)      NOT NULL DEFAULT '',
			aaguid                VARBINARY(16)    NOT NULL,
			sign_count            BIGINT UNSIGNED  NOT NULL DEFAULT 0,
			transports            JSON             NOT NULL,
			credential_flags_byte TINYINT UNSIGNED NOT NULL DEFAULT 0,
			PRIMARY KEY (user_id, credential_id(255)),
			INDEX idx_passkeys_credential_id (credential_id(255)),
			CONSTRAINT fk_passkeys_user FOREIGN KEY (user_id)
				REFERENCES users(id) ON DELETE CASCADE
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
	}

	for _, stmt := range stmts {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}

// -----------------------------------------------------------------------------
// Users
// -----------------------------------------------------------------------------

// GetUserByID retrieves a user by their ID, including their passkeys.
func (s *MySQLStore) GetUserByID(ctx context.Context, userID string) (*User, error) {
	u, err := s.scanUser(ctx,
		`SELECT id, username, password_hash, roles, totp_secret, totp_enabled, settings
		 FROM users WHERE id = ?`, userID)
	if err != nil {
		return nil, err
	}
	if err := s.loadPasskeys(ctx, u); err != nil {
		return nil, err
	}
	return u, nil
}

// GetUserByUsername retrieves a user by their username, including their passkeys.
func (s *MySQLStore) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	u, err := s.scanUser(ctx,
		`SELECT id, username, password_hash, roles, totp_secret, totp_enabled, settings
		 FROM users WHERE username = ?`, username)
	if err != nil {
		return nil, err
	}
	if err := s.loadPasskeys(ctx, u); err != nil {
		return nil, err
	}
	return u, nil
}

// CreateUser inserts a new user, assigning a fresh UUID.
func (s *MySQLStore) CreateUser(ctx context.Context, user *User) error {
	user.ID = uuid.New().String()

	rolesJSON, err := json.Marshal(user.Roles)
	if err != nil {
		return fmt.Errorf("failed to marshal roles: %w", err)
	}
	settingsJSON, err := marshalSettingsMySQL(user.Settings)
	if err != nil {
		return err
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO users (id, username, password_hash, roles, totp_secret, totp_enabled, settings)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		user.ID,
		user.Username,
		user.PasswordHash,
		rolesJSON,
		user.TOTPSecret,
		user.TOTPEnabled,
		settingsJSON,
	)
	if err != nil {
		if isMySQLUniqueViolation(err) {
			return errors.New("user with this username already exists")
		}
		return fmt.Errorf("failed to create user: %w", err)
	}
	return nil
}

// UpdateUser replaces all mutable fields on an existing user.
// Passkeys are managed exclusively through the dedicated passkey methods.
func (s *MySQLStore) UpdateUser(ctx context.Context, user *User) error {
	rolesJSON, err := json.Marshal(user.Roles)
	if err != nil {
		return fmt.Errorf("failed to marshal roles: %w", err)
	}
	settingsJSON, err := marshalSettingsMySQL(user.Settings)
	if err != nil {
		return err
	}

	res, err := s.db.ExecContext(ctx, `
		UPDATE users
		SET username      = ?,
		    password_hash = ?,
		    roles         = ?,
		    totp_secret   = ?,
		    totp_enabled  = ?,
		    settings      = ?
		WHERE id = ?`,
		user.Username,
		user.PasswordHash,
		rolesJSON,
		user.TOTPSecret,
		user.TOTPEnabled,
		settingsJSON,
		user.ID,
	)
	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return errors.New("user not found")
	}
	return nil
}

// DeleteUser removes a user and all their passkeys (via ON DELETE CASCADE).
func (s *MySQLStore) DeleteUser(ctx context.Context, userID string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, userID)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return errors.New("user not found for deletion")
	}
	return nil
}

// -----------------------------------------------------------------------------
// Passkeys
// -----------------------------------------------------------------------------

// AddPasskey inserts a new WebAuthn credential for the given user.
func (s *MySQLStore) AddPasskey(ctx context.Context, userID string, credential webauthn.Credential) error {
	wc := FromWebAuthnCredential(credential)

	transportsJSON, err := json.Marshal(wc.Transports)
	if err != nil {
		return fmt.Errorf("failed to marshal transports: %w", err)
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO passkeys
			(user_id, credential_id, public_key, attestation_type, aaguid,
			 sign_count, transports, credential_flags_byte)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		userID,
		wc.ID,
		wc.PublicKey,
		wc.AttestationType,
		wc.AAGUID,
		wc.SignCount,
		transportsJSON,
		wc.CredentialFlagsByte,
	)
	if err != nil {
		return fmt.Errorf("failed to add passkey: %w", err)
	}
	return nil
}

// GetPasskeysByUserID returns all WebAuthn credentials for a user.
func (s *MySQLStore) GetPasskeysByUserID(ctx context.Context, userID string) ([]webauthn.Credential, error) {
	wcs, err := s.queryPasskeys(ctx,
		`SELECT credential_id, public_key, attestation_type, aaguid,
		        sign_count, transports, credential_flags_byte
		 FROM passkeys WHERE user_id = ?`, userID)
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
func (s *MySQLStore) GetPasskeyByCredentialID(ctx context.Context, credentialID []byte) (*webauthn.Credential, *User, error) {
	// 1. Fetch passkey row(s) matching this credential ID.
	wcs, err := s.queryPasskeys(ctx,
		`SELECT credential_id, public_key, attestation_type, aaguid,
		        sign_count, transports, credential_flags_byte
		 FROM passkeys WHERE credential_id = ?`, credentialID)
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

	// 3. Resolve the owning user ID.
	var userID string
	err = s.db.QueryRowContext(ctx,
		`SELECT user_id FROM passkeys WHERE credential_id = ?`, credentialID).
		Scan(&userID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, errors.New("passkey not found")
	}
	if err != nil {
		return nil, nil, fmt.Errorf("failed to resolve user for passkey: %w", err)
	}

	// 4. Load the full user including their passkeys.
	user, err := s.GetUserByID(ctx, userID)
	if err != nil {
		return nil, nil, err
	}

	cred := matched.ToWebAuthnCredential()
	return &cred, user, nil
}

// UpdatePasskey updates the sign count for a specific credential.
func (s *MySQLStore) UpdatePasskey(ctx context.Context, userID string, credential webauthn.Credential) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE passkeys SET sign_count = ?
		WHERE user_id = ? AND credential_id = ?`,
		credential.Authenticator.SignCount,
		userID,
		credential.ID,
	)
	if err != nil {
		return fmt.Errorf("failed to update passkey: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return errors.New("passkey not found for update")
	}
	return nil
}

// DeletePasskey removes a specific passkey from a user.
func (s *MySQLStore) DeletePasskey(ctx context.Context, userID string, credentialID []byte) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM passkeys WHERE user_id = ? AND credential_id = ?`,
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
// MySQL's TINYINT(1) for booleans and JSON columns need manual unmarshalling.
func (s *MySQLStore) scanUser(ctx context.Context, query string, arg interface{}) (*User, error) {
	var (
		u            User
		rolesJSON    []byte
		settingsJSON []byte
		totpEnabled  int8 // MySQL TINYINT(1) doesn't auto-scan to bool
	)
	err := s.db.QueryRowContext(ctx, query, arg).Scan(
		&u.ID,
		&u.Username,
		&u.PasswordHash,
		&rolesJSON,
		&u.TOTPSecret,
		&totpEnabled,
		&settingsJSON,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errors.New("user not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to scan user: %w", err)
	}

	u.TOTPEnabled = totpEnabled != 0

	if len(rolesJSON) > 0 {
		if err := json.Unmarshal(rolesJSON, &u.Roles); err != nil {
			return nil, fmt.Errorf("failed to decode roles: %w", err)
		}
	}
	if len(settingsJSON) > 0 {
		if err := json.Unmarshal(settingsJSON, &u.Settings); err != nil {
			return nil, fmt.Errorf("failed to decode settings: %w", err)
		}
	}
	return &u, nil
}

// loadPasskeys fetches all passkeys for u and populates u.Passkeys.
func (s *MySQLStore) loadPasskeys(ctx context.Context, u *User) error {
	wcs, err := s.queryPasskeys(ctx,
		`SELECT credential_id, public_key, attestation_type, aaguid,
		        sign_count, transports, credential_flags_byte
		 FROM passkeys WHERE user_id = ?`, u.ID)
	if err != nil {
		return err
	}
	u.Passkeys = wcs
	return nil
}

// queryPasskeys runs any SELECT over the passkeys columns and returns
// a []WebAuthnCredential. Transports are stored as a JSON array in MySQL.
func (s *MySQLStore) queryPasskeys(ctx context.Context, query string, arg interface{}) ([]WebAuthnCredential, error) {
	rows, err := s.db.QueryContext(ctx, query, arg)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []WebAuthnCredential
	for rows.Next() {
		var (
			wc             WebAuthnCredential
			transportsJSON []byte
		)
		if err := rows.Scan(
			&wc.ID,
			&wc.PublicKey,
			&wc.AttestationType,
			&wc.AAGUID,
			&wc.SignCount,
			&transportsJSON,
			&wc.CredentialFlagsByte,
		); err != nil {
			return nil, err
		}
		if len(transportsJSON) > 0 {
			if err := json.Unmarshal(transportsJSON, &wc.Transports); err != nil {
				return nil, fmt.Errorf("failed to decode transports: %w", err)
			}
		}
		out = append(out, wc)
	}
	return out, rows.Err()
}

// marshalSettingsMySQL encodes a settings map to JSON, returning nil for empty maps.
func marshalSettingsMySQL(settings map[string]interface{}) ([]byte, error) {
	if len(settings) == 0 {
		return nil, nil
	}
	b, err := json.Marshal(settings)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal settings: %w", err)
	}
	return b, nil
}

// isMySQLUniqueViolation reports whether err is a MySQL duplicate-entry error
// (error number 1062).
func isMySQLUniqueViolation(err error) bool {
	type mysqlErr interface {
		Number() uint16
	}
	var myErr mysqlErr
	if errors.As(err, &myErr) {
		return myErr.Number() == 1062
	}
	return false
}
