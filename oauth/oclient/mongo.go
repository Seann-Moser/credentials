package oclient

import (
	"context"
	"errors"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/oauth2"
)

var _ OAuthService = &MongoOAuthService{}

// MongoOAuthService is a MongoDB-backed implementation of OAuthService.
type MongoOAuthService struct {
	integrations *mongo.Collection
	tokens       *mongo.Collection
}

// NewMongoOAuthService creates a new service backed by the given DB.
func NewMongoOAuthService(db *mongo.Database) *MongoOAuthService {
	return &MongoOAuthService{
		integrations: db.Collection("oauth_integrations"),
		tokens:       db.Collection("oauth_tokens"),
	}
}

// AddIntegration registers a new OAuth client configuration.
func (s *MongoOAuthService) AddIntegration(ctx context.Context, accountID string, in Integration) error {
	in.CreatedAt = time.Now().UTC()
	in.UpdatedAt = in.CreatedAt
	doc := bson.M{
		"account_id":    accountID,
		"provider":      in.Provider,
		"client_id":     in.ClientID,
		"client_secret": in.ClientSecret,
		"redirect_url":  in.RedirectURL,
		"scopes":        in.Scopes,
		"created_at":    in.CreatedAt,
		"updated_at":    in.UpdatedAt,
	}
	_, err := s.integrations.InsertOne(ctx, doc)
	return err
}

// UpdateIntegration updates client credentials or settings.
func (s *MongoOAuthService) UpdateIntegration(ctx context.Context, accountID, provider string, in Integration) error {
	in.UpdatedAt = time.Now().UTC()
	filter := bson.M{"account_id": accountID, "provider": provider}
	update := bson.M{"$set": bson.M{
		"client_id":     in.ClientID,
		"client_secret": in.ClientSecret,
		"redirect_url":  in.RedirectURL,
		"scopes":        in.Scopes,
		"updated_at":    in.UpdatedAt,
	}}
	res, err := s.integrations.UpdateOne(ctx, filter, update)
	if err != nil {
		return err
	}
	if res.MatchedCount == 0 {
		return errors.New("integration not found")
	}
	return nil
}

// DeleteIntegration removes the integration and its tokens.
func (s *MongoOAuthService) DeleteIntegration(ctx context.Context, accountID, provider string) error {
	// Remove integration
	_, err := s.integrations.DeleteOne(ctx, bson.M{"account_id": accountID, "provider": provider})
	if err != nil {
		return err
	}
	// Also remove any stored tokens for that provider
	_, err = s.tokens.DeleteMany(ctx, bson.M{"account_id": accountID, "provider": provider})
	return err
}

// ListIntegrations returns all OAuth configs for an account.
func (s *MongoOAuthService) ListIntegrations(ctx context.Context, accountID string) ([]Integration, error) {
	cursor, err := s.integrations.Find(ctx, bson.M{"account_id": accountID})
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = cursor.Close(ctx)
	}()

	var out []Integration
	for cursor.Next(ctx) {
		var doc struct {
			Provider     string    `bson:"provider"`
			ClientID     string    `bson:"client_id"`
			ClientSecret string    `bson:"client_secret"`
			RedirectURL  string    `bson:"redirect_url"`
			Scopes       []string  `bson:"scopes"`
			CreatedAt    time.Time `bson:"created_at"`
			UpdatedAt    time.Time `bson:"updated_at"`
		}
		if err := cursor.Decode(&doc); err != nil {
			return nil, err
		}
		out = append(out, Integration{
			Provider:     doc.Provider,
			ClientID:     doc.ClientID,
			ClientSecret: doc.ClientSecret,
			RedirectURL:  doc.RedirectURL,
			Scopes:       doc.Scopes,
			CreatedAt:    doc.CreatedAt,
			UpdatedAt:    doc.UpdatedAt,
		})
	}
	return out, cursor.Err()
}

// GetIntegration fetches one provider’s config.
func (s *MongoOAuthService) GetIntegration(ctx context.Context, accountID, provider string) (Integration, error) {
	var doc struct {
		Provider     string    `bson:"provider"`
		ClientID     string    `bson:"client_id"`
		ClientSecret string    `bson:"client_secret"`
		RedirectURL  string    `bson:"redirect_url"`
		Scopes       []string  `bson:"scopes"`
		CreatedAt    time.Time `bson:"created_at"`
		UpdatedAt    time.Time `bson:"updated_at"`
	}
	err := s.integrations.FindOne(ctx, bson.M{"account_id": accountID, "provider": provider}).Decode(&doc)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return Integration{}, errors.New("integration not found")
		}
		return Integration{}, err
	}
	return Integration{
		Provider:     doc.Provider,
		ClientID:     doc.ClientID,
		ClientSecret: doc.ClientSecret,
		RedirectURL:  doc.RedirectURL,
		Scopes:       doc.Scopes,
		CreatedAt:    doc.CreatedAt,
		UpdatedAt:    doc.UpdatedAt,
	}, nil
}

// StoreTokens upserts a user’s token pair.
func (s *MongoOAuthService) StoreTokens(ctx context.Context, accountID, userID, provider string, t TokenPair) error {
	filter := bson.M{"account_id": accountID, "user_id": userID, "provider": provider}
	upd := bson.M{"$set": bson.M{
		"access_token":  t.AccessToken,
		"refresh_token": t.RefreshToken,
		"expires_at":    t.ExpiresAt,
		"issued_at":     t.IssuedAt,
	}}
	opts := options.Update().SetUpsert(true)
	_, err := s.tokens.UpdateOne(ctx, filter, upd, opts)
	return err
}

// GetTokens retrieves stored tokens.
// GetTokens retrieves stored tokens, auto-refreshing if expired.
func (s *MongoOAuthService) GetTokens(ctx context.Context, accountID, userID, provider string) (TokenPair, error) {
	var doc struct {
		AccessToken  string    `bson:"access_token"`
		RefreshToken string    `bson:"refresh_token"`
		ExpiresAt    time.Time `bson:"expires_at"`
		IssuedAt     time.Time `bson:"issued_at"`
	}
	err := s.tokens.FindOne(ctx, bson.M{
		"account_id": accountID,
		"user_id":    userID,
		"provider":   provider,
	}).Decode(&doc)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return TokenPair{}, errors.New("tokens not found")
		}
		return TokenPair{}, err
	}

	// build the current pair
	current := TokenPair{
		AccessToken:  doc.AccessToken,
		RefreshToken: doc.RefreshToken,
		ExpiresAt:    doc.ExpiresAt,
		IssuedAt:     doc.IssuedAt,
	}

	// if expired (or within a small safety window), refresh
	if time.Now().UTC().Add(time.Minute).After(current.ExpiresAt) {
		return s.RefreshTokens(ctx, accountID, userID, provider)
	}

	return current, nil
}

// RefreshTokens uses OAuth2 to fetch a new access (and maybe refresh) token.
func (s *MongoOAuthService) RefreshTokens(ctx context.Context, accountID, userID, provider string) (TokenPair, error) {
	// 1) load integration config
	cfg, err := s.GetIntegration(ctx, accountID, provider)
	if err != nil {
		return TokenPair{}, err
	}
	// 2) load current tokens
	old, err := s.GetTokens(ctx, accountID, userID, provider)
	if err != nil {
		return TokenPair{}, err
	}
	// 3) build oauth2.Config
	oauthCfg := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  "", // fill in provider’s auth URL if needed
			TokenURL: "", // fill in provider’s token URL
		},
		RedirectURL: cfg.RedirectURL,
		Scopes:      cfg.Scopes,
	}
	token := &oauth2.Token{
		AccessToken:  old.AccessToken,
		RefreshToken: old.RefreshToken,
		Expiry:       old.ExpiresAt,
	}
	ts := oauthCfg.TokenSource(ctx, token)
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
	// 4) persist and return
	if err := s.StoreTokens(ctx, accountID, userID, provider, updated); err != nil {
		return TokenPair{}, err
	}
	return updated, nil
}

// RevokeTokens revokes (here: deletes) a user’s tokens.
func (s *MongoOAuthService) RevokeTokens(ctx context.Context, accountID, userID, provider string) error {
	// if you have a revocation endpoint, you could call it here
	return s.DeleteTokens(ctx, accountID, userID, provider)
}

// DeleteTokens removes stored tokens.
func (s *MongoOAuthService) DeleteTokens(ctx context.Context, accountID, userID, provider string) error {
	_, err := s.tokens.DeleteOne(ctx, bson.M{
		"account_id": accountID,
		"user_id":    userID,
		"provider":   provider,
	})
	return err
}
