package oserver

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"go.mongodb.org/mongo-driver/mongo/options"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

var _ OServer = &MongoServer{}

// MongoServer implements the OAuth2 OServer interface backed by MongoDB
type MongoServer struct {
	db          *mongo.Database
	clientsColl *mongo.Collection
	tokensColl  *mongo.Collection
	jwkColl     *mongo.Collection
	imagesColl  *mongo.Collection
}

// NewMongoServer creates a new MongoServer. Expects a connected mongo.Database.
func NewMongoServer(db *mongo.Database) *MongoServer {
	return &MongoServer{
		db:          db,
		clientsColl: db.Collection("oauth_clients"),
		tokensColl:  db.Collection("oauth_tokens"),
		jwkColl:     db.Collection("oauth_jwks"),
		imagesColl:  db.Collection("oauth_client_images"),
	}
}
func ss(i interface{}) string {
	switch v := i.(type) {
	case string:
		return v
	case int64:
		return strconv.FormatInt(v, 10)
	case int:
		return strconv.Itoa(v)
	case int32:
		return strconv.FormatInt(int64(v), 10)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case float32:
		return strconv.FormatFloat(float64(v), 'f', -1, 32)
	default:
		slog.Error("skipping type")
		return ""
	}
}

// RegisterClient inserts a new OAuth client into the store.
func (s *MongoServer) RegisterClient(ctx context.Context, client *OAuthClient) (*OAuthClient, error) {
	clientDoc := bson.M{
		"client_id":                  client.ClientID,
		"client_secret":              client.ClientSecret,
		"name":                       client.Name,
		"image_url":                  client.ImageURL,
		"redirect_uris":              client.RedirectURIs,
		"scopes":                     client.Scopes,
		"grant_types":                client.GrantTypes,
		"response_types":             client.ResponseTypes,
		"token_endpoint_auth_method": client.TokenEndpointAuth,
	}
	_, err := s.clientsColl.InsertOne(ctx, clientDoc)
	if err != nil {
		return nil, err
	}
	return client, nil
}

// GetClient retrieves a client by ID.
func (s *MongoServer) GetClient(ctx context.Context, clientID string) (*OAuthClient, error) {
	var doc bson.M
	err := s.clientsColl.FindOne(ctx, bson.M{"client_id": clientID}).Decode(&doc)
	if err == mongo.ErrNoDocuments {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	client := &OAuthClient{
		ClientID:          ss(doc["client_id"]),
		ClientSecret:      ss(doc["client_secret"]),
		Name:              ss(doc["name"]),
		ImageURL:          ss(doc["image_url"]),
		RedirectURIs:      castStringSlice(doc["redirect_uris"]),
		Scopes:            castStringSlice(doc["scopes"]),
		GrantTypes:        castStringSlice(doc["grant_types"]),
		ResponseTypes:     castStringSlice(doc["response_types"]),
		TokenEndpointAuth: ss(doc["token_endpoint_auth_method"]),
	}
	return client, nil
}

// ListClients returns all clients for a given accountID (if stored) or all clients.
func (s *MongoServer) ListClients(ctx context.Context, accountID string) ([]*OAuthClient, error) {
	filter := bson.M{}
	// if you store accountID in client docs:
	if accountID != "" {
		filter["account_id"] = accountID
	}
	cur, err := s.clientsColl.Find(ctx, filter)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = cur.Close(ctx)
	}()
	var list []*OAuthClient
	for cur.Next(ctx) {
		var doc bson.M
		if err := cur.Decode(&doc); err != nil {
			return nil, err
		}

		list = append(list, &OAuthClient{
			ClientID:      ss(doc["client_id"]),
			Name:          ss(doc["name"]),
			RedirectURIs:  castStringSlice(doc["redirect_uris"]),
			Scopes:        castStringSlice(doc["scopes"]),
			GrantTypes:    castStringSlice(doc["grant_types"]),
			ResponseTypes: castStringSlice(doc["response_types"]),
		})
	}
	return list, nil
}

// UpdateClient updates mutable fields on an existing client.
func (s *MongoServer) UpdateClient(ctx context.Context, client *OAuthClient) (*OAuthClient, error) {
	update := bson.M{"$set": bson.M{
		"name":                       client.Name,
		"image_url":                  client.ImageURL,
		"redirect_uris":              client.RedirectURIs,
		"scopes":                     client.Scopes,
		"grant_types":                client.GrantTypes,
		"response_types":             client.ResponseTypes,
		"token_endpoint_auth_method": client.TokenEndpointAuth,
	}}
	_, err := s.clientsColl.UpdateOne(ctx, bson.M{"client_id": client.ClientID}, update)
	if err != nil {
		return nil, err
	}
	return client, nil
}

// DeleteClient removes a client by ID.
func (s *MongoServer) DeleteClient(ctx context.Context, clientID string) error {
	res, err := s.clientsColl.DeleteOne(ctx, bson.M{"client_id": clientID})
	if err != nil {
		return err
	}
	if res.DeletedCount == 0 {
		return errors.New("client not found")
	}
	return nil
}

// Authorize issues an authorization code and stores it in tokens collection.
func (s *MongoServer) Authorize(ctx context.Context, req AuthRequest) (*AuthResponse, error) {
	// Validate client, redirect URI, scope...
	// generate code
	code := primitive.NewObjectID().Hex()
	rec := bson.M{
		"code":                  code,
		"client_id":             req.ClientID,
		"redirect_uri":          req.RedirectURI,
		"scope":                 req.Scope,
		"code_challenge":        req.CodeChallenge,
		"code_challenge_method": req.CodeChallengeMethod,
		"grant_type":            GrantTypeAuthorizationCode,
		"created_at":            time.Now().Unix(),
	}
	_, err := s.tokensColl.InsertOne(ctx, rec)
	if err != nil {
		return nil, err
	}
	return &AuthResponse{Code: code, State: req.State}, nil
}

// TokenRequest and TokenResponse mirror OAuth2 spec
// ... [other types omitted for brevity] ...

// Token handles all grant types: authorization_code, refresh_token, client_credentials
func (s *MongoServer) Token(ctx context.Context, req TokenRequest) (*TokenResponse, error) {
	now := time.Now()
	switch req.GrantType {
	case string(GrantTypeAuthorizationCode):
		// 1) fetch the code record
		var rec struct {
			Code                string `bson:"code"`
			ClientID            string `bson:"client_id"`
			RedirectURI         string `bson:"redirect_uri"`
			Scope               string `bson:"scope"`
			CodeChallenge       string `bson:"code_challenge"`
			CodeChallengeMethod string `bson:"code_challenge_method"`
		}
		err := s.tokensColl.FindOne(ctx, bson.M{"code": req.Code}).Decode(&rec)
		if err != nil {
			return nil, errors.New("invalid authorization code")
		}
		// 2) validate redirect URI
		if rec.RedirectURI != req.RedirectURI {
			return nil, errors.New("redirect_uri mismatch")
		}
		// 3) validate PKCE if used
		if rec.CodeChallenge != "" {
			switch rec.CodeChallengeMethod {
			case "S256":
				h := sha256.Sum256([]byte(req.CodeVerifier))
				if base64.RawURLEncoding.EncodeToString(h[:]) != rec.CodeChallenge {
					return nil, errors.New("invalid code_verifier")
				}
			case "plain":
				if req.CodeVerifier != rec.CodeChallenge {
					return nil, errors.New("invalid code_verifier")
				}
			default:
				return nil, errors.New("unsupported code_challenge_method")
			}
		}
		// 4) issue tokens
		accessToken := primitive.NewObjectID().Hex()
		refreshToken := primitive.NewObjectID().Hex()
		expiresAt := now.Add(time.Hour).Unix()
		// update record
		_, err = s.tokensColl.UpdateOne(ctx,
			bson.M{"code": req.Code},
			bson.M{"$set": bson.M{"access_token": accessToken, "refresh_token": refreshToken, "expires_at": expiresAt}},
		)
		if err != nil {
			return nil, err
		}
		return &TokenResponse{AccessToken: accessToken, TokenType: "Bearer", ExpiresIn: int64(time.Hour.Seconds()), RefreshToken: refreshToken, Scope: rec.Scope}, nil

	case string(GrantTypeRefreshToken):
		// refresh existing token
		var rec struct {
			RefreshToken string `bson:"refresh_token"`
			ClientID     string `bson:"client_id"`
			Scope        string `bson:"scope"`
		}
		err := s.tokensColl.FindOne(ctx, bson.M{"refresh_token": req.RefreshToken}).Decode(&rec)
		if err != nil {
			return nil, errors.New("invalid refresh token")
		}
		// issue new access token
		accessToken := primitive.NewObjectID().Hex()
		expiresAt := now.Add(time.Hour).Unix()
		_, err = s.tokensColl.UpdateOne(ctx,
			bson.M{"refresh_token": req.RefreshToken},
			bson.M{"$set": bson.M{"access_token": accessToken, "expires_at": expiresAt}},
		)
		if err != nil {
			return nil, err
		}
		return &TokenResponse{AccessToken: accessToken, TokenType: "Bearer", ExpiresIn: int64(time.Hour.Seconds()), RefreshToken: req.RefreshToken, Scope: rec.Scope}, nil

	case "client_credentials":
		// authenticate client
		var cli struct {
			ClientSecret string   `bson:"client_secret"`
			Scopes       []string `bson:"scopes"`
			GrantTypes   []string `bson:"grant_types"`
		}
		err := s.clientsColl.FindOne(ctx, bson.M{"client_id": req.ClientID}).Decode(&cli)
		if err != nil {
			return nil, errors.New("invalid client credentials")
		}
		if cli.ClientSecret != req.ClientSecret {
			return nil, errors.New("invalid client credentials")
		}
		// ensure grant type allowed
		allowed := false
		for _, gt := range cli.GrantTypes {
			if gt == "client_credentials" {
				allowed = true
			}
		}
		if !allowed {
			return nil, errors.New("grant_type not allowed")
		}
		accessToken := primitive.NewObjectID().Hex()
		expiresAt := now.Add(time.Hour).Unix()
		scopeStr := strings.Join(cli.Scopes, " ")
		// insert token record
		_, err = s.tokensColl.InsertOne(ctx, bson.M{
			"access_token": accessToken,
			"client_id":    req.ClientID,
			"scope":        scopeStr,
			"grant_type":   "client_credentials",
			"expires_at":   expiresAt,
		})
		if err != nil {
			return nil, err
		}
		return &TokenResponse{AccessToken: accessToken, TokenType: "Bearer", ExpiresIn: int64(time.Hour.Seconds()), Scope: scopeStr}, nil

	default:
		return nil, errors.New("unsupported grant_type")
	}
}

// Revoke invalidates a token (remove or mark revoked)
func (s *MongoServer) Revoke(ctx context.Context, req RevocationRequest) error {
	_, err := s.tokensColl.DeleteOne(ctx, bson.M{"$or": []bson.M{{"access_token": req.Token}, {"refresh_token": req.Token}}})
	return err
}

// Introspect checks active state of a token
func (s *MongoServer) Introspect(ctx context.Context, req IntrospectRequest) (*IntrospectResponse, error) {
	var doc bson.M
	err := s.tokensColl.FindOne(ctx, bson.M{"access_token": req.Token}).Decode(&doc)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return &IntrospectResponse{Active: false}, nil
		}
		return nil, err
	}
	expires := doc["expires_at"].(int64)
	active := time.Now().Unix() < expires
	return &IntrospectResponse{Active: active, ClientID: ss(doc["client_id"]), Scope: ss(doc["scope"]), Exp: expires}, nil
}

// JWKs returns stored JWK set
// JWKs returns stored JWK set
func (s *MongoServer) JWKs(ctx context.Context) (*JWKSet, error) {
	cur, err := s.jwkColl.Find(ctx, bson.M{})
	if err != nil {
		return nil, err
	}
	var keys []json.RawMessage
	for cur.Next(ctx) {
		var doc bson.M
		if err := cur.Decode(&doc); err != nil {
			return nil, err
		}
		if raw, ok := doc["key"].(json.RawMessage); ok {
			keys = append(keys, raw)
		}
	}
	return &JWKSet{Keys: keys}, nil
}

// SetClientImage uploads or updates an image for a given client.
func (s *MongoServer) SetClientImage(r *http.Request, clientID string) error {
	ctx := r.Context()
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		return err
	}
	file, header, err := r.FormFile("image")
	if err != nil {
		return err
	}
	defer func() {
		_ = file.Close()
	}()
	data, err := io.ReadAll(file)
	if err != nil {
		return err
	}
	// upsert image document
	_, err = s.imagesColl.UpdateOne(ctx, bson.M{"client_id": clientID}, bson.M{
		"$set": bson.M{
			"data":         data,
			"content_type": header.Header.Get("Content-Type"),
			"updated_at":   time.Now(),
		},
	}, options.Update().SetUpsert(true))
	return err
}

// SendClientImage streams the stored image to the HTTP response.
func (s *MongoServer) SendClientImage(w http.ResponseWriter, r *http.Request, clientID string) error {
	ctx := r.Context()
	var doc struct {
		Data        []byte `bson:"data"`
		ContentType string `bson:"content_type"`
	}
	err := s.imagesColl.FindOne(ctx, bson.M{"client_id": clientID}).Decode(&doc)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			http.NotFound(w, r)
			return nil
		}
		return err
	}
	// add caching headers
	w.Header().Set("Content-Type", doc.ContentType)
	w.Header().Set("Cache-Control", "public, max-age=86400")
	_, err = w.Write(doc.Data)
	return err
}

func (s *MongoServer) HasAccess(r *http.Request, resource string, hasRbacAccess func(resource string, userId string, scopes ...string) bool) (bool, error) {
	ctx := r.Context()
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		// no token: empty user and scopes
		return hasRbacAccess(resource, ""), nil
	}
	token := strings.TrimPrefix(auth, "Bearer ")
	var doc bson.M
	err := s.tokensColl.FindOne(ctx, bson.M{"access_token": token}).Decode(&doc)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return hasRbacAccess(resource, ""), nil
		}
		return false, err
	}
	// check expiration
	expires, ok := doc["expires_at"].(int64)
	if !ok || time.Now().Unix() >= expires {
		return hasRbacAccess(resource, ""), nil
	}
	// extract user and scopes
	userId, _ := doc["user_id"].(string)
	scopeStr, _ := doc["scope"].(string)
	var scopes []string
	if scopeStr != "" {
		scopes = strings.Fields(scopeStr)
	}
	allowed := hasRbacAccess(resource, userId, scopes...)
	return allowed, nil
}

// helpers
func castStringSlice(v interface{}) []string {
	if arr, ok := v.(primitive.A); ok {
		out := make([]string, 0, len(arr))
		for _, x := range arr {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}
