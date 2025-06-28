package oserver

import "encoding/json"

type GrantType string

const GrantTypeAuthorizationCode GrantType = "authorization_code"
const GrantTypeRefreshToken GrantType = "refresh_token"

// stores client metadata (dynamic or admin-registered)
type OAuthClient struct {
	ClientID          string   `json:"client_id" db:"client_id" qc:"primary;charset::utf8"`
	AccountID         string   `json:"account_id" db:"account_id" qc:"primary;charset::utf8"`
	ClientSecret      string   `json:"client_secret,omitempty" db:"client_secret" qc:"update"`
	Name              string   `json:"name" db:"name" qc:"primary;update;charset::utf8"`
	ImageURL          string   `json:"image_url" db:"image_path" qc:"update"`
	RedirectURIs      []string `json:"redirect_uris" db:"redirect_uris" qc:"update;data_type::text"`
	Scopes            []string `json:"scopes" db:"scope" qc:"update;data_type::text"`
	TokenEndpointAuth string   `json:"token_endpoint_auth_method,omitempty" db:"token_endpoint_auth_method" qc:"update"`
	GrantTypes        []string `json:"grant_types" db:"grant_types" qc:"update;data_type::text"`
	ResponseTypes     []string `json:"response_types" db:"response_types" qc:"update;data_type::text"`
	// non-persistent, computed
	ConnectedUserCount int `json:"connected_users,omitempty" db:"-" qc:"-"`
}

// represents an issued grant or token
type TokenRecord struct {
	ClientID      string   `json:"client_id" db:"client_id" qc:"primary;charset::utf8"`
	UserID        string   `json:"user_id,omitempty" db:"user_id" qc:"primary;charset::utf8"`
	AccountID     string   `json:"account_id,omitempty" db:"account_id" qc:"update"`
	Scope         []string `json:"scope" db:"scope" qc:"update;data_type::text"`
	GrantType     string   `json:"grant_type" db:"grant_type" qc:"update"`
	Code          string   `json:"code,omitempty" db:"code" qc:"update"`
	CodeChallenge string   `json:"code_challenge,omitempty" db:"code_challenge" qc:"update"`
	Method        string   `json:"code_challenge_method,omitempty" db:"code_challenge_method" qc:"update"`
	AccessToken   string   `json:"access_token" db:"access_token" qc:"update"`
	RefreshToken  string   `json:"refresh_token,omitempty" db:"refresh_token" qc:"update"`
	ExpiresAt     int64    `json:"expires_at" db:"expires" qc:"update"`
}

// /authorize
type AuthRequest struct {
	ResponseType        string `json:"response_type"` // e.g. "code"
	ClientID            string `json:"client_id"`
	RedirectURI         string `json:"redirect_uri"`
	Decision            string `json:"decision"`
	Scope               string `json:"scope,omitempty"`
	State               string `json:"state,omitempty"`
	CodeChallenge       string `json:"code_challenge,omitempty"`        // PKCE
	CodeChallengeMethod string `json:"code_challenge_method,omitempty"` // "S256" or "plain"
}
type AuthResponse struct {
	Code  string `json:"code"`
	State string `json:"state,omitempty"`
}

// /token
type TokenRequest struct {
	GrantType    string `json:"grant_type"` // "authorization_code", "refresh_token", "client_credentials"
	Code         string `json:"code,omitempty"`
	RedirectURI  string `json:"redirect_uri,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	CodeVerifier string `json:"code_verifier,omitempty"` // PKCE
}
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"` // "Bearer"
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// /revocation
type RevocationRequest struct {
	Token        string `json:"token"`
	TokenType    string `json:"token_type_hint,omitempty"` // "access_token" or "refresh_token"
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

// /introspection
type IntrospectRequest struct {
	Token     string `json:"token"`
	TokenType string `json:"token_type_hint,omitempty"`
}
type IntrospectResponse struct {
	Active    bool   `json:"active"`
	Scope     string `json:"scope,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	Username  string `json:"username,omitempty"`
	UserID    string `json:"user_id,omitempty"`
	AccountID string `json:"account_id,omitempty"`
	Exp       int64  `json:"exp,omitempty"`
	Iat       int64  `json:"iat,omitempty"`
	TokenType string `json:"token_type,omitempty"`
}

// JWK set
type JWKSet struct {
	Keys []json.RawMessage `json:"keys"`
}
