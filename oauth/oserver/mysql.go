// file: oserver/mysql_server.go
package oserver

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

var _ OServer = &MySQLServer{}

type MySQLServer struct {
	db *sql.DB
}

func NewMySQLServer(ctx context.Context, db *sql.DB) (*MySQLServer, error) {
	s := &MySQLServer{db: db}
	if err := s.ensureSchema(ctx); err != nil {
		return nil, fmt.Errorf("mysql_server: ensure schema: %w", err)
	}
	return s, nil
}

// --------------------------------------------------------------------------
// Schema
// --------------------------------------------------------------------------

func (s *MySQLServer) ensureSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
	CREATE SCHEMA IF NOT EXISTS oserver;
	CREATE TABLE IF NOT EXISTS oserver.oauth_clients (
		client_id VARCHAR(36) PRIMARY KEY,
		account_id TEXT NOT NULL,
		client_secret TEXT NOT NULL,
		name TEXT NOT NULL,
		image_url TEXT,
		redirect_uris JSON NOT NULL,
		scopes JSON NOT NULL,
		grant_types JSON NOT NULL,
		response_types JSON NOT NULL,
		token_endpoint_auth_method TEXT
	);

	CREATE TABLE IF NOT EXISTS oserver.oauth_tokens (
		id BIGINT AUTO_INCREMENT PRIMARY KEY,
		code TEXT UNIQUE,
		access_token TEXT UNIQUE,
		refresh_token TEXT UNIQUE,
		client_id VARCHAR(36) NOT NULL,
		user_id TEXT,
		account_id TEXT,
		redirect_uri TEXT,
		scope TEXT,
		grant_type TEXT,
		code_challenge TEXT,
		code_challenge_method TEXT,
		expires_at BIGINT,
		created_at BIGINT
	);

	CREATE TABLE IF NOT EXISTS oserver.oauth_jwks (
		id BIGINT AUTO_INCREMENT PRIMARY KEY,
		key_data JSON NOT NULL
	);

	CREATE TABLE IF NOT EXISTS oserver.oauth_client_images (
		client_id VARCHAR(36) PRIMARY KEY,
		data LONGBLOB NOT NULL,
		content_type TEXT,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
	);
	`)
	return err
}

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

func generateSecretMySQL(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// --------------------------------------------------------------------------
// Client management
// --------------------------------------------------------------------------

func (s *MySQLServer) RegisterClient(ctx context.Context, client *OAuthClient) (*OAuthClient, error) {
	if len(client.GrantTypes) == 0 {
		client.GrantTypes = []string{"client_credentials"}
	}
	if len(client.RedirectURIs) == 0 {
		return nil, fmt.Errorf("no redirect_uris provided")
	}
	if client.Name == "" {
		return nil, fmt.Errorf("no name provided")
	}

	client.ClientID = uuid.New().String()
	secret, err := generateSecretMySQL(32)
	if err != nil {
		return nil, err
	}
	client.ClientSecret = secret

	redirects, _ := json.Marshal(client.RedirectURIs)
	scopes, _ := json.Marshal(client.Scopes)
	grants, _ := json.Marshal(client.GrantTypes)
	respTypes, _ := json.Marshal(client.ResponseTypes)

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO oserver.oauth_clients
		(client_id, account_id, client_secret, name, image_url,
		 redirect_uris, scopes, grant_types, response_types, token_endpoint_auth_method)
		VALUES (?,?,?,?,?,?,?,?,?,?)`,
		client.ClientID,
		client.AccountID,
		client.ClientSecret,
		client.Name,
		client.ImageURL,
		redirects,
		scopes,
		grants,
		respTypes,
		client.TokenEndpointAuth,
	)
	return client, err
}

func (s *MySQLServer) GetClient(ctx context.Context, clientID string) (*OAuthClient, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT client_id, account_id, client_secret, name, image_url,
		       redirect_uris, scopes, grant_types, response_types, token_endpoint_auth_method
		FROM oserver.oauth_clients WHERE client_id = ?`, clientID)

	var (
		c         OAuthClient
		redirects []byte
		scopes    []byte
		grants    []byte
		respTypes []byte
	)

	err := row.Scan(
		&c.ClientID, &c.AccountID, &c.ClientSecret, &c.Name, &c.ImageURL,
		&redirects, &scopes, &grants, &respTypes, &c.TokenEndpointAuth,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	json.Unmarshal(redirects, &c.RedirectURIs)
	json.Unmarshal(scopes, &c.Scopes)
	json.Unmarshal(grants, &c.GrantTypes)
	json.Unmarshal(respTypes, &c.ResponseTypes)

	return &c, nil
}

func (s *MySQLServer) ListClients(ctx context.Context, accountID string) ([]*OAuthClient, error) {
	var (
		rows *sql.Rows
		err  error
	)

	if accountID != "" {
		rows, err = s.db.QueryContext(ctx, `
			SELECT client_id, account_id, name, redirect_uris, scopes, grant_types, response_types
			FROM oserver.oauth_clients WHERE account_id = ?`, accountID)
	} else {
		rows, err = s.db.QueryContext(ctx, `
			SELECT client_id, account_id, name, redirect_uris, scopes, grant_types, response_types
			FROM oserver.oauth_clients`)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []*OAuthClient
	for rows.Next() {
		var (
			c         OAuthClient
			redirects []byte
			scopes    []byte
			grants    []byte
			respTypes []byte
		)

		if err := rows.Scan(
			&c.ClientID, &c.AccountID, &c.Name,
			&redirects, &scopes, &grants, &respTypes,
		); err != nil {
			return nil, err
		}

		json.Unmarshal(redirects, &c.RedirectURIs)
		json.Unmarshal(scopes, &c.Scopes)
		json.Unmarshal(grants, &c.GrantTypes)
		json.Unmarshal(respTypes, &c.ResponseTypes)

		list = append(list, &c)
	}
	return list, rows.Err()
}

func (s *MySQLServer) UpdateClient(ctx context.Context, client *OAuthClient) (*OAuthClient, error) {
	redirects, _ := json.Marshal(client.RedirectURIs)
	scopes, _ := json.Marshal(client.Scopes)
	grants, _ := json.Marshal(client.GrantTypes)
	respTypes, _ := json.Marshal(client.ResponseTypes)

	_, err := s.db.ExecContext(ctx, `
		UPDATE oserver.oauth_clients SET
			name=?, image_url=?, redirect_uris=?, scopes=?, grant_types=?, response_types=?, token_endpoint_auth_method=?
		WHERE client_id=?`,
		client.Name,
		client.ImageURL,
		redirects,
		scopes,
		grants,
		respTypes,
		client.TokenEndpointAuth,
		client.ClientID,
	)
	return client, err
}

func (s *MySQLServer) DeleteClient(ctx context.Context, clientID string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM oserver.oauth_clients WHERE client_id = ?`, clientID)
	if err != nil {
		return err
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return errors.New("client not found")
	}
	return nil
}

// --------------------------------------------------------------------------
// Token / Auth / Revoke / Introspect / JWKs / Images / HasAccess
// (Same logic as Postgres, just swapped to ? placeholders)
// --------------------------------------------------------------------------

// 👉 To keep this readable, everything below is mechanically identical to your Postgres version.
// Only changes:
// - QueryRow → QueryRowContext
// - Exec → ExecContext
// - $1 → ?
// - pgx.ErrNoRows → sql.ErrNoRows

// You can literally copy your existing functions and:
// 1. Replace `$n` with `?`
// 2. Replace pgx.ErrNoRows with sql.ErrNoRows
// 3. Replace Exec/QueryRow with Context versions
// 4. Handle JSON fields manually if needed
// --------------------------------------------------------------------------
// Authorization code
// --------------------------------------------------------------------------

func (s *MySQLServer) Authorize(ctx context.Context, req AuthRequest) (*AuthResponse, error) {
	meta := make(map[string]string)
	if req.State != "" {
		if d, err := base64.StdEncoding.DecodeString(req.State); err == nil {
			_ = json.Unmarshal(d, &meta)
		}
	}

	userID := meta["user_id"]
	accountID := meta["account_id"]

	code := uuid.New().String()

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO oserver.oauth_tokens
		(code, client_id, user_id, account_id, redirect_uri, scope,
		 code_challenge, code_challenge_method, grant_type, created_at)
		VALUES (?,?,?,?,?,?,?,?,?,?)`,
		code,
		req.ClientID,
		userID,
		accountID,
		req.RedirectURI,
		req.Scope,
		req.CodeChallenge,
		req.CodeChallengeMethod,
		string(GrantTypeAuthorizationCode),
		time.Now().Unix(),
	)
	if err != nil {
		return nil, err
	}

	return &AuthResponse{Code: code, State: req.State}, nil
}

func (s *MySQLServer) Token(ctx context.Context, req TokenRequest) (*TokenResponse, error) {
	now := time.Now()

	switch req.GrantType {
	case string(GrantTypeAuthorizationCode):
		return s.tokenFromCode(ctx, req, now)
	case string(GrantTypeRefreshToken):
		return s.tokenFromRefresh(ctx, req, now)
	case "client_credentials":
		return s.tokenFromClientCredentials(ctx, req, now)
	default:
		return nil, errors.New("unsupported grant_type")
	}
}

func (s *MySQLServer) tokenFromCode(ctx context.Context, req TokenRequest, now time.Time) (*TokenResponse, error) {
	var (
		clientID            string
		redirectURI         string
		scope               string
		codeChallenge       string
		codeChallengeMethod string
	)

	err := s.db.QueryRowContext(ctx, `
		SELECT client_id, redirect_uri, scope, code_challenge, code_challenge_method
		FROM oserver.oauth_tokens WHERE code = ?`, req.Code).
		Scan(&clientID, &redirectURI, &scope, &codeChallenge, &codeChallengeMethod)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, errors.New("invalid authorization code")
	}
	if err != nil {
		return nil, err
	}

	if redirectURI != req.RedirectURI {
		return nil, errors.New("redirect_uri mismatch")
	}

	if codeChallenge != "" {
		switch codeChallengeMethod {
		case "S256":
			if !ValidateCodeChallenge(req.CodeVerifier, codeChallenge) {
				return nil, errors.New("invalid code_verifier")
			}
		case "plain":
			if req.CodeVerifier != codeChallenge {
				return nil, errors.New("invalid code_verifier")
			}
		default:
			return nil, errors.New("unsupported code_challenge_method")
		}
	}

	accessToken := uuid.New().String()
	refreshToken := uuid.New().String()
	expiresAt := now.Add(time.Hour).Unix()

	_, err = s.db.ExecContext(ctx, `
		UPDATE oserver.oauth_tokens
		SET access_token=?, refresh_token=?, expires_at=?
		WHERE code=?`,
		accessToken, refreshToken, expiresAt, req.Code,
	)
	if err != nil {
		return nil, err
	}

	return &TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(time.Hour.Seconds()),
		RefreshToken: refreshToken,
		Scope:        scope,
	}, nil
}

func (s *MySQLServer) tokenFromRefresh(ctx context.Context, req TokenRequest, now time.Time) (*TokenResponse, error) {
	var (
		clientID string
		scope    string
	)

	err := s.db.QueryRowContext(ctx,
		`SELECT client_id, scope FROM oserver.oauth_tokens WHERE refresh_token = ?`, req.RefreshToken).
		Scan(&clientID, &scope)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, errors.New("invalid refresh token")
	}
	if err != nil {
		return nil, err
	}

	accessToken := uuid.New().String()
	expiresAt := now.Add(time.Hour).Unix()

	_, err = s.db.ExecContext(ctx,
		`UPDATE oserver.oauth_tokens SET access_token=?, expires_at=? WHERE refresh_token=?`,
		accessToken, expiresAt, req.RefreshToken,
	)
	if err != nil {
		return nil, err
	}

	return &TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(time.Hour.Seconds()),
		RefreshToken: req.RefreshToken,
		Scope:        scope,
	}, nil
}

func (s *MySQLServer) tokenFromClientCredentials(ctx context.Context, req TokenRequest, now time.Time) (*TokenResponse, error) {
	var (
		clientSecret string
		scopesJSON   []byte
		grantsJSON   []byte
		scopes       []string
		grants       []string
	)

	err := s.db.QueryRowContext(ctx, `
		SELECT client_secret, scopes, grant_types
		FROM oserver.oauth_clients WHERE client_id = ?`, req.ClientID).
		Scan(&clientSecret, &scopesJSON, &grantsJSON)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, errors.New("invalid client credentials")
	}
	if err != nil {
		return nil, err
	}

	json.Unmarshal(scopesJSON, &scopes)
	json.Unmarshal(grantsJSON, &grants)

	if clientSecret != req.ClientSecret {
		return nil, errors.New("invalid client credentials")
	}

	allowed := false
	for _, g := range grants {
		if g == "client_credentials" {
			allowed = true
			break
		}
	}
	if !allowed {
		return nil, errors.New("grant_type not allowed")
	}

	accessToken := uuid.New().String()
	expiresAt := now.Add(time.Hour).Unix()
	scopeStr := strings.Join(scopes, " ")

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO oserver.oauth_tokens
		(access_token, client_id, scope, grant_type, expires_at, created_at)
		VALUES (?,?,?,?,?,?)`,
		accessToken, req.ClientID, scopeStr, "client_credentials", expiresAt, now.Unix(),
	)
	if err != nil {
		return nil, err
	}

	return &TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int64(time.Hour.Seconds()),
		Scope:       scopeStr,
	}, nil
}
func (s *MySQLServer) Revoke(ctx context.Context, req RevocationRequest) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM oauth_tokens WHERE access_token = ? OR refresh_token = ?`,
		req.Token, req.Token,
	)
	return err
}

func (s *MySQLServer) Introspect(ctx context.Context, req IntrospectRequest) (*IntrospectResponse, error) {
	var (
		clientID  string
		userID    string
		accountID string
		scope     string
		expiresAt int64
	)

	err := s.db.QueryRowContext(ctx, `
		SELECT client_id, user_id, account_id, scope, expires_at
		FROM oserver.oauth_tokens WHERE access_token = ?`, req.Token).
		Scan(&clientID, &userID, &accountID, &scope, &expiresAt)

	if errors.Is(err, sql.ErrNoRows) {
		return &IntrospectResponse{Active: false}, nil
	}
	if err != nil {
		return nil, err
	}

	return &IntrospectResponse{
		Active:    time.Now().Unix() < expiresAt,
		ClientID:  clientID,
		UserID:    userID,
		AccountID: accountID,
		Scope:     scope,
		Exp:       expiresAt,
	}, nil
}

func (s *MySQLServer) JWKs(ctx context.Context) (*JWKSet, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT key_data FROM oserver.oauth_jwks`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []json.RawMessage
	for rows.Next() {
		var k json.RawMessage
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return &JWKSet{Keys: keys}, rows.Err()
}
func (s *MySQLServer) SetClientImage(r *http.Request, clientID string) error {
	ctx := r.Context()

	if err := r.ParseMultipartForm(32 << 20); err != nil {
		return err
	}

	file, header, err := r.FormFile("image")
	if err != nil {
		return err
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return err
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO oserver.oauth_client_images (client_id, data, content_type)
		VALUES (?,?,?)
		ON DUPLICATE KEY UPDATE
			data=VALUES(data),
			content_type=VALUES(content_type),
			updated_at=CURRENT_TIMESTAMP`,
		clientID, data, header.Header.Get("Content-Type"),
	)
	return err
}

func (s *MySQLServer) SendClientImage(w http.ResponseWriter, r *http.Request, clientID string) error {
	ctx := r.Context()

	var data []byte
	var contentType string

	err := s.db.QueryRowContext(ctx,
		`SELECT data, content_type FROM oserver.oauth_client_images WHERE client_id = ?`, clientID).
		Scan(&data, &contentType)

	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, r)
		return nil
	}
	if err != nil {
		return err
	}

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "public, max-age=86400")
	_, err = w.Write(data)
	return err
}
func (s *MySQLServer) HasAccess(
	r *http.Request,
	resource string,
	hasRbacAccess func(resource string, userId, accountId string, scopes ...string) bool,
) (bool, error) {

	ctx := r.Context()
	auth := r.Header.Get("Authorization")

	if !strings.HasPrefix(auth, "Bearer ") {
		return hasRbacAccess(resource, "", ""), nil
	}

	token := strings.TrimPrefix(auth, "Bearer ")

	var (
		userID    string
		accountID string
		scope     string
		expiresAt int64
	)

	err := s.db.QueryRowContext(ctx, `
		SELECT user_id, account_id, scope, expires_at
		FROM oserver.oauth_tokens WHERE access_token = ?`, token).
		Scan(&userID, &accountID, &scope, &expiresAt)

	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	if time.Now().Unix() >= expiresAt {
		return false, nil
	}

	var scopes []string
	if scope != "" {
		scopes = strings.Fields(scope)
	}

	return hasRbacAccess(resource, userID, accountID, scopes...), nil
}
