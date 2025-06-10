package oclient

import "time"

// Integration holds the client credentials & provider details
type Integration struct {
	Provider     string // e.g. "google", "github"
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// TokenPair holds an access + refresh token for a given user/account
type TokenPair struct {
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
	IssuedAt     time.Time
}
