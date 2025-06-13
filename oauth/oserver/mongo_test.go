package oserver

import (
	"bytes"
	"context"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/integration/mtest"
)

// Helper function to create a new MongoServer for testing
func newTestMongoServer(mt *mtest.T) *MongoServer {

	db := mt.DB
	return NewMongoServer(db)
}

func TestNewMongoServer(t *testing.T) {
	mt := mtest.New(t, mtest.NewOptions().ClientType(mtest.Mock)) // Using a real mtest for this simple test
	defer mt.ClearCollections()
	mt.Run("success", func(mt *mtest.T) {
		server := newTestMongoServer(mt)
		if server == nil {
			t.Fatal("NewMongoServer returned nil")
		}
		if server.db == nil {
			t.Error("server.db is nil")
		}
		if server.clientsColl == nil {
			t.Error("server.clientsColl is nil")
		}
		if server.tokensColl == nil {
			t.Error("server.tokensColl is nil")
		}
		if server.jwkColl == nil {
			t.Error("server.jwkColl is nil")
		}
		if server.imagesColl == nil {
			t.Error("server.imagesColl is nil")
		}
	})
}

func TestMongoServer_RegisterClient(t *testing.T) {
	mt := mtest.New(t, mtest.NewOptions().ClientType(mtest.Mock))
	defer mt.ClearCollections()

	mt.Run("success", func(mt *mtest.T) {
		server := newTestMongoServer(mt)
		client := &OAuthClient{
			ClientID:          "test_client_id",
			ClientSecret:      "test_client_secret",
			Name:              "Test Client",
			RedirectURIs:      []string{"http://localhost/callback"},
			Scopes:            []string{"read", "write"},
			GrantTypes:        []string{"authorization_code"},
			ResponseTypes:     []string{"code"},
			TokenEndpointAuth: "client_secret_basic",
		}

		mt.AddMockResponses(mtest.CreateSuccessResponse()) // Simulate successful insert

		registeredClient, err := server.RegisterClient(context.Background(), client)
		if err != nil {
			mt.Fatalf("RegisterClient failed: %v", err)
		}
		if registeredClient.ClientID != client.ClientID {
			mt.Errorf("Expected client ID %s, got %s", client.ClientID, registeredClient.ClientID)
		}
	})

	mt.Run("insert error", func(mt *mtest.T) {
		server := newTestMongoServer(mt)
		client := &OAuthClient{ClientID: "error_client"}

		mt.AddMockResponses(mtest.CreateWriteErrorsResponse(mtest.WriteError{Code: 11000, Message: "duplicate key"})) // Simulate duplicate key error

		_, err := server.RegisterClient(context.Background(), client)
		if err == nil {
			mt.Fatal("RegisterClient did not return an error for insert failure")
		}
		if !strings.Contains(err.Error(), "duplicate key") {
			mt.Errorf("Expected duplicate key error, got: %v", err)
		}
	})
}

func TestMongoServer_GetClient(t *testing.T) {
	mt := mtest.New(t, mtest.NewOptions().ClientType(mtest.Mock))
	defer mt.ClearCollections()

	mt.Run("success", func(mt *mtest.T) {
		server := newTestMongoServer(mt)
		expectedClient := &OAuthClient{
			ClientID:          "get_client_id",
			ClientSecret:      "get_client_secret",
			Name:              "Get Client",
			ImageURL:          "http://example.com/image.png",
			RedirectURIs:      []string{"http://localhost/get/callback"},
			Scopes:            []string{"read_get", "write_get"},
			GrantTypes:        []string{"authorization_code_get"},
			ResponseTypes:     []string{"code_get"},
			TokenEndpointAuth: "client_secret_post",
		}
		clientDoc := bson.D{
			{Key: "client_id", Value: expectedClient.ClientID},
			{Key: "client_secret", Value: expectedClient.ClientSecret},
			{Key: "name", Value: expectedClient.Name},
			{Key: "image_url", Value: expectedClient.ImageURL},
			{Key: "redirect_uris", Value: expectedClient.RedirectURIs},
			{Key: "scopes", Value: expectedClient.Scopes},
			{Key: "grant_types", Value: expectedClient.GrantTypes},
			{Key: "response_types", Value: expectedClient.ResponseTypes},
			{Key: "token_endpoint_auth_method", Value: expectedClient.TokenEndpointAuth},
		}

		mt.AddMockResponses(mtest.CreateCursorResponse(1, "foo.bar", mtest.FirstBatch, clientDoc)) // Simulate successful find

		client, err := server.GetClient(context.Background(), expectedClient.ClientID)
		if err != nil {
			mt.Fatalf("GetClient failed: %v", err)
		}
		if client == nil {
			mt.Fatal("GetClient returned nil")
		}
		if client.ClientID != expectedClient.ClientID {
			mt.Errorf("Expected client ID %s, got %s", expectedClient.ClientID, client.ClientID)
		}
		if client.Name != expectedClient.Name {
			mt.Errorf("Expected client name %s, got %s", expectedClient.Name, client.Name)
		}
		if len(client.RedirectURIs) != len(expectedClient.RedirectURIs) || client.RedirectURIs[0] != expectedClient.RedirectURIs[0] {
			mt.Errorf("RedirectURIs mismatch")
		}
	})

	mt.Run("not found", func(mt *mtest.T) {
		server := newTestMongoServer(mt)
		mt.AddMockResponses(mtest.CreateCursorResponse(0, "foo.bar", mtest.FirstBatch)) // Simulate no documents found

		client, err := server.GetClient(context.Background(), "non_existent_client")
		if err != nil {
			mt.Fatalf("GetClient failed for not found case: %v", err)
		}
		if client != nil {
			mt.Error("GetClient returned a client for a non-existent ID")
		}
	})

	mt.Run("find error", func(mt *mtest.T) {
		server := newTestMongoServer(mt)
		mt.AddMockResponses(mtest.CreateCommandErrorResponse(mtest.CommandError{Code: 1, Message: "test error"})) // Simulate find error

		_, err := server.GetClient(context.Background(), "some_client")
		if err == nil {
			mt.Fatal("GetClient did not return an error for find failure")
		}
		if !strings.Contains(err.Error(), "test error") {
			mt.Errorf("Expected 'test error', got: %v", err)
		}
	})
}

func TestMongoServer_ListClients(t *testing.T) {
	mt := mtest.New(t, mtest.NewOptions().ClientType(mtest.Mock))
	defer mt.ClearCollections()

	mt.Run("success_no_account_id", func(mt *mtest.T) {
		server := newTestMongoServer(mt)
		client1 := bson.D{
			{Key: "client_id", Value: "client1"}, {Key: "name", Value: "Client One"},
			{Key: "redirect_uris", Value: primitive.A{"uri1"}}, {Key: "scopes", Value: primitive.A{"s1"}},
			{Key: "grant_types", Value: primitive.A{"gt1"}}, {Key: "response_types", Value: primitive.A{"rt1"}},
		}
		client2 := bson.D{
			{Key: "client_id", Value: "client2"}, {Key: "name", Value: "Client Two"},
			{Key: "redirect_uris", Value: primitive.A{"uri2"}}, {Key: "scopes", Value: primitive.A{"s2"}},
			{Key: "grant_types", Value: primitive.A{"gt2"}}, {Key: "response_types", Value: primitive.A{"rt2"}},
		}
		mt.AddMockResponses(mtest.CreateCursorResponse(1, "foo.bar", mtest.FirstBatch, client1, client2))
		mt.AddMockResponses(mtest.CreateCursorResponse(0, "foo.bar", mtest.NextBatch)) // No more documents

		clients, err := server.ListClients(context.Background(), "")
		if err != nil {
			mt.Fatalf("ListClients failed: %v", err)
		}
		if len(clients) != 2 {
			mt.Fatalf("Expected 2 clients, got %d", len(clients))
		}
		if clients[0].ClientID != "client1" || clients[1].ClientID != "client2" {
			mt.Errorf("Clients mismatch")
		}
	})

	mt.Run("success_with_account_id", func(mt *mtest.T) {
		server := newTestMongoServer(mt)
		client1 := bson.D{
			{Key: "client_id", Value: "client_acc1"}, {Key: "name", Value: "Account Client"},
			{Key: "account_id", Value: "acc1"},
			{Key: "redirect_uris", Value: primitive.A{"uri_acc1"}}, {Key: "scopes", Value: primitive.A{"s_acc1"}},
			{Key: "grant_types", Value: primitive.A{"gt_acc1"}}, {Key: "response_types", Value: primitive.A{"rt_acc1"}},
		}
		mt.AddMockResponses(mtest.CreateCursorResponse(1, "foo.bar", mtest.FirstBatch, client1))
		mt.AddMockResponses(mtest.CreateCursorResponse(0, "foo.bar", mtest.NextBatch))

		clients, err := server.ListClients(context.Background(), "acc1")
		if err != nil {
			mt.Fatalf("ListClients failed: %v", err)
		}
		if len(clients) != 1 {
			mt.Fatalf("Expected 1 client, got %d", len(clients))
		}
		if clients[0].ClientID != "client_acc1" {
			mt.Errorf("Client ID mismatch")
		}
	})

	mt.Run("find error", func(mt *mtest.T) {
		server := newTestMongoServer(mt)
		mt.AddMockResponses(mtest.CreateCommandErrorResponse(mtest.CommandError{Code: 1, Message: "test find error"}))

		_, err := server.ListClients(context.Background(), "")
		if err == nil {
			mt.Fatal("ListClients did not return an error for find failure")
		}
		if !strings.Contains(err.Error(), "test find error") {
			mt.Errorf("Expected 'test find error', got: %v", err)
		}
	})

	mt.Run("decode error", func(mt *mtest.T) {
		server := newTestMongoServer(mt)
		invalidDoc := bson.D{{Key: "client_id", Value: 123}} // Invalid type for client_id
		mt.AddMockResponses(mtest.CreateCursorResponse(1, "foo.bar", mtest.FirstBatch, invalidDoc))
		mt.AddMockResponses(mtest.CreateCursorResponse(0, "foo.bar", mtest.NextBatch))

		_, err := server.ListClients(context.Background(), "")
		if err == nil {
			mt.Fatal("ListClients did not return an error for decode failure")
		}
	})
}

func TestMongoServer_UpdateClient(t *testing.T) {
	mt := mtest.New(t, mtest.NewOptions().ClientType(mtest.Mock))
	defer mt.ClearCollections()

	mt.Run("success", func(mt *mtest.T) {
		server := newTestMongoServer(mt)
		updatedClient := &OAuthClient{
			ClientID:          "update_client_id",
			Name:              "Updated Client Name",
			ImageURL:          "http://new.image.com",
			RedirectURIs:      []string{"http://newuri"},
			Scopes:            []string{"new_scope"},
			GrantTypes:        []string{"new_gt"},
			ResponseTypes:     []string{"new_rt"},
			TokenEndpointAuth: "none",
		}

		mt.AddMockResponses(bson.D{{Key: "ok", Value: 1}, {Key: "n", Value: 1}, {Key: "nModified", Value: 1}}) // Simulate successful update

		client, err := server.UpdateClient(context.Background(), updatedClient)
		if err != nil {
			mt.Fatalf("UpdateClient failed: %v", err)
		}
		if client.Name != updatedClient.Name {
			mt.Errorf("Expected updated name %s, got %s", updatedClient.Name, client.Name)
		}
	})

	mt.Run("update error", func(mt *mtest.T) {
		server := newTestMongoServer(mt)
		client := &OAuthClient{ClientID: "error_client"}

		mt.AddMockResponses(mtest.CreateCommandErrorResponse(mtest.CommandError{Code: 1, Message: "update error"})) // Simulate update error

		_, err := server.UpdateClient(context.Background(), client)
		if err == nil {
			mt.Fatal("UpdateClient did not return an error for update failure")
		}
		if !strings.Contains(err.Error(), "update error") {
			mt.Errorf("Expected 'update error', got: %v", err)
		}
	})
}

func TestMongoServer_DeleteClient(t *testing.T) {
	mt := mtest.New(t, mtest.NewOptions().ClientType(mtest.Mock))
	defer mt.ClearCollections()

	mt.Run("success", func(mt *mtest.T) {
		server := newTestMongoServer(mt)
		mt.AddMockResponses(bson.D{{Key: "ok", Value: 1}, {Key: "n", Value: 1}}) // Simulate successful delete with 1 deleted count

		err := server.DeleteClient(context.Background(), "delete_client_id")
		if err != nil {
			mt.Fatalf("DeleteClient failed: %v", err)
		}
	})

	mt.Run("not found", func(mt *mtest.T) {
		server := newTestMongoServer(mt)
		mt.AddMockResponses(bson.D{{Key: "ok", Value: 1}, {Key: "n", Value: 0}}) // Simulate delete with 0 deleted count

		err := server.DeleteClient(context.Background(), "non_existent_client")
		if err == nil {
			mt.Fatal("DeleteClient did not return an error for not found client")
		}
		if err.Error() != "client not found" {
			mt.Errorf("Expected 'client not found' error, got: %v", err)
		}
	})

	mt.Run("delete error", func(mt *mtest.T) {
		server := newTestMongoServer(mt)
		mt.AddMockResponses(mtest.CreateCommandErrorResponse(mtest.CommandError{Code: 1, Message: "delete error"})) // Simulate delete error

		err := server.DeleteClient(context.Background(), "error_client")
		if err == nil {
			mt.Fatal("DeleteClient did not return an error for delete failure")
		}
		if !strings.Contains(err.Error(), "delete error") {
			mt.Errorf("Expected 'delete error', got: %v", err)
		}
	})
}

func TestMongoServer_Authorize(t *testing.T) {
	mt := mtest.New(t, mtest.NewOptions().ClientType(mtest.Mock))
	defer mt.ClearCollections()

	mt.Run("success", func(mt *mtest.T) {
		server := newTestMongoServer(mt)
		req := AuthRequest{
			ClientID:            "auth_client",
			RedirectURI:         "http://auth.callback",
			Scope:               "profile",
			State:               "xyz",
			CodeChallenge:       "challenge123",
			CodeChallengeMethod: "S256",
		}
		mt.AddMockResponses(mtest.CreateSuccessResponse()) // Simulate successful insert

		res, err := server.Authorize(context.Background(), req)
		if err != nil {
			mt.Fatalf("Authorize failed: %v", err)
		}
		if res.Code == "" {
			mt.Error("Authorization code is empty")
		}
		if res.State != req.State {
			mt.Errorf("Expected state %s, got %s", req.State, res.State)
		}
	})

	mt.Run("insert error", func(mt *mtest.T) {
		server := newTestMongoServer(mt)
		req := AuthRequest{ClientID: "error_auth_client"}
		mt.AddMockResponses(mtest.CreateWriteErrorsResponse(mtest.WriteError{Code: 1, Message: "auth insert error"}))

		_, err := server.Authorize(context.Background(), req)
		if err == nil {
			mt.Fatal("Authorize did not return an error for insert failure")
		}
		if !strings.Contains(err.Error(), "auth insert error") {
			mt.Errorf("Expected 'auth insert error', got: %v", err)
		}
	})
}

func TestMongoServer_Token_AuthorizationCode(t *testing.T) {
	mt := mtest.New(t, mtest.NewOptions().ClientType(mtest.Mock))
	defer mt.ClearCollections()

	mt.Run("success_no_pkce", func(mt *mtest.T) {
		server := newTestMongoServer(mt)
		code := primitive.NewObjectID().Hex()
		authRec := bson.D{
			{Key: "code", Value: code},
			{Key: "client_id", Value: "test_client"},
			{Key: "redirect_uri", Value: "http://callback.com"},
			{Key: "scope", Value: "email profile"},
			{Key: "code_challenge", Value: ""},
			{Key: "code_challenge_method", Value: ""},
		}

		// Mock responses for FindOne and UpdateOne
		mt.AddMockResponses(mtest.CreateCursorResponse(1, "foo.bar", mtest.FirstBatch, authRec))
		mt.AddMockResponses(mtest.CreateSuccessResponse())
		mt.AddMockResponses(
			mtest.CreateSuccessResponse(
				bson.E{Key: "n", Value: int64(1)},         // matched count
				bson.E{Key: "nModified", Value: int64(1)}, // modified count
			),
		)
		req := TokenRequest{
			GrantType:   string(GrantTypeAuthorizationCode),
			Code:        code,
			RedirectURI: "http://callback.com",
		}
		res, err := server.Token(context.Background(), req)
		if err != nil {
			mt.Fatalf("Token (auth code, no PKCE) failed: %v", err)
		}
		if res.AccessToken == "" || res.RefreshToken == "" {
			mt.Error("Access or refresh token is empty")
		}
		if res.Scope != "email profile" {
			mt.Errorf("Expected scope 'email profile', got %s", res.Scope)
		}
	})

	mt.Run("success_pkce_s256", func(mt *mtest.T) {
		server := newTestMongoServer(mt)
		code := primitive.NewObjectID().Hex()
		codeVerifier, err := GenerateCodeVerifier() // Example verifier

		if err != nil {
			mt.Fatalf("GenerateCodeVerifier failed: %v", err)
		}
		sha256Hash := GenerateCodeChallenge(codeVerifier) // Base64RawURLEncoding of SHA256(codeVerifier)
		authRec := bson.D{
			{Key: "code", Value: code},
			{Key: "client_id", Value: "pkce_client"},
			{Key: "redirect_uri", Value: "http://pkce.callback"},
			{Key: "scope", Value: "openid"},
			{Key: "code_challenge", Value: sha256Hash},
			{Key: "code_challenge_method", Value: "S256"},
		}

		mt.AddMockResponses(mtest.CreateCursorResponse(1, "foo.bar", mtest.FirstBatch, authRec))
		mt.AddMockResponses(mtest.CreateSuccessResponse())
		mt.AddMockResponses(
			mtest.CreateSuccessResponse(
				bson.E{Key: "n", Value: int64(1)},         // matched count
				bson.E{Key: "nModified", Value: int64(1)}, // modified count
			),
		)
		req := TokenRequest{
			GrantType:    string(GrantTypeAuthorizationCode),
			Code:         code,
			RedirectURI:  "http://pkce.callback",
			CodeVerifier: codeVerifier,
		}
		res, err := server.Token(context.Background(), req)
		if err != nil {
			mt.Fatalf("Token (auth code, PKCE S256) failed: %v", err)
		}
		if res.AccessToken == "" {
			mt.Error("Access token is empty")
		}
	})

	mt.Run("success_pkce_plain", func(mt *mtest.T) {
		server := newTestMongoServer(mt)
		code := primitive.NewObjectID().Hex()
		codeVerifier := "plain_verifier_string"
		authRec := bson.D{
			{Key: "code", Value: code},
			{Key: "client_id", Value: "pkce_plain_client"},
			{Key: "redirect_uri", Value: "http://pkce.plain.callback"},
			{Key: "scope", Value: "read"},
			{Key: "code_challenge", Value: codeVerifier},
			{Key: "code_challenge_method", Value: "plain"},
		}

		mt.AddMockResponses(mtest.CreateCursorResponse(1, "foo.bar", mtest.FirstBatch, authRec))
		mt.AddMockResponses(mtest.CreateSuccessResponse())
		mt.AddMockResponses(
			mtest.CreateSuccessResponse(
				bson.E{Key: "n", Value: int64(1)},         // matched count
				bson.E{Key: "nModified", Value: int64(1)}, // modified count
			),
		)

		req := TokenRequest{
			GrantType:    string(GrantTypeAuthorizationCode),
			Code:         code,
			RedirectURI:  "http://pkce.plain.callback",
			CodeVerifier: codeVerifier,
		}
		res, err := server.Token(context.Background(), req)
		if err != nil {
			mt.Fatalf("Token (auth code, PKCE plain) failed: %v", err)
		}
		if res.AccessToken == "" {
			mt.Error("Access token is empty")
		}
	})

	mt.Run("invalid code", func(mt *mtest.T) {
		server := newTestMongoServer(mt)
		mt.AddMockResponses(mtest.CreateCursorResponse(0, "foo.bar", mtest.FirstBatch)) // Simulate no documents found

		req := TokenRequest{GrantType: string(GrantTypeAuthorizationCode), Code: "invalid"}
		_, err := server.Token(context.Background(), req)
		if err == nil {
			mt.Fatal("Token did not return an error for invalid code")
		}
		if err.Error() != "invalid authorization code" {
			mt.Errorf("Expected 'invalid authorization code', got: %v", err)
		}
	})

	mt.Run("redirect_uri mismatch", func(mt *mtest.T) {
		server := newTestMongoServer(mt)
		code := primitive.NewObjectID().Hex()
		authRec := bson.D{
			{Key: "code", Value: code},
			{Key: "redirect_uri", Value: "http://correct.callback"},
		}
		mt.AddMockResponses(mtest.CreateCursorResponse(1, "foo.bar", mtest.FirstBatch, authRec))

		req := TokenRequest{
			GrantType:   string(GrantTypeAuthorizationCode),
			Code:        code,
			RedirectURI: "http://wrong.callback",
		}
		_, err := server.Token(context.Background(), req)
		if err == nil {
			mt.Fatal("Token did not return an error for redirect_uri mismatch")
		}
		if err.Error() != "redirect_uri mismatch" {
			mt.Errorf("Expected 'redirect_uri mismatch', got: %v", err)
		}
	})

	mt.Run("invalid code_verifier S256", func(mt *mtest.T) {
		server := newTestMongoServer(mt)
		code := primitive.NewObjectID().Hex()
		authRec := bson.D{
			{Key: "code", Value: code},
			{Key: "redirect_uri", Value: "http://pkce.callback"},
			{Key: "code_challenge", Value: "some_challenge"},
			{Key: "code_challenge_method", Value: "S256"},
		}
		mt.AddMockResponses(mtest.CreateCursorResponse(1, "foo.bar", mtest.FirstBatch, authRec))

		req := TokenRequest{
			GrantType:    string(GrantTypeAuthorizationCode),
			Code:         code,
			RedirectURI:  "http://pkce.callback",
			CodeVerifier: "wrong_verifier",
		}
		_, err := server.Token(context.Background(), req)
		if err == nil {
			mt.Fatal("Token did not return an error for invalid code_verifier S256")
		}
		if err.Error() != "invalid code_verifier" {
			mt.Errorf("Expected 'invalid code_verifier', got: %v", err)
		}
	})

	mt.Run("invalid code_verifier plain", func(mt *mtest.T) {
		server := newTestMongoServer(mt)
		code := primitive.NewObjectID().Hex()
		authRec := bson.D{
			{Key: "code", Value: code},
			{Key: "redirect_uri", Value: "http://pkce.callback"},
			{Key: "code_challenge", Value: "correct_plain_verifier"},
			{Key: "code_challenge_method", Value: "plain"},
		}
		mt.AddMockResponses(mtest.CreateCursorResponse(1, "foo.bar", mtest.FirstBatch, authRec))

		req := TokenRequest{
			GrantType:    string(GrantTypeAuthorizationCode),
			Code:         code,
			RedirectURI:  "http://pkce.callback",
			CodeVerifier: "wrong_plain_verifier",
		}
		_, err := server.Token(context.Background(), req)
		if err == nil {
			mt.Fatal("Token did not return an error for invalid code_verifier plain")
		}
		if err.Error() != "invalid code_verifier" {
			mt.Errorf("Expected 'invalid code_verifier', got: %v", err)
		}
	})

	mt.Run("unsupported code_challenge_method", func(mt *mtest.T) {
		server := newTestMongoServer(mt)
		code := primitive.NewObjectID().Hex()
		authRec := bson.D{
			{Key: "code", Value: code},
			{Key: "redirect_uri", Value: "http://pkce.callback"},
			{Key: "code_challenge", Value: "some_challenge"},
			{Key: "code_challenge_method", Value: "unsupported"},
		}
		mt.AddMockResponses(mtest.CreateCursorResponse(1, "foo.bar", mtest.FirstBatch, authRec))

		req := TokenRequest{
			GrantType:    string(GrantTypeAuthorizationCode),
			Code:         code,
			RedirectURI:  "http://pkce.callback",
			CodeVerifier: "any_verifier",
		}
		_, err := server.Token(context.Background(), req)
		if err == nil {
			mt.Fatal("Token did not return an error for unsupported code_challenge_method")
		}
		if err.Error() != "unsupported code_challenge_method" {
			mt.Errorf("Expected 'unsupported code_challenge_method', got: %v", err)
		}
	})

	mt.Run("update error", func(mt *mtest.T) {
		server := newTestMongoServer(mt)
		code := primitive.NewObjectID().Hex()
		authRec := bson.D{
			{Key: "code", Value: code},
			{Key: "client_id", Value: "test_client"},
			{Key: "redirect_uri", Value: "http://callback.com"},
			{Key: "scope", Value: "email profile"},
		}
		mt.AddMockResponses(mtest.CreateCursorResponse(1, "foo.bar", mtest.FirstBatch, authRec))
		mt.AddMockResponses(mtest.CreateCommandErrorResponse(mtest.CommandError{Code: 1, Message: "token update error"}))
		mt.AddMockResponses(mtest.CreateCommandErrorResponse(mtest.CommandError{Code: 1, Message: "token update error"}))

		req := TokenRequest{
			GrantType:   string(GrantTypeAuthorizationCode),
			Code:        code,
			RedirectURI: "http://callback.com",
		}
		_, err := server.Token(context.Background(), req)
		if err == nil {
			mt.Fatal("Token did not return an error for update failure")
		}
		if !strings.Contains(err.Error(), "token update error") {
			mt.Errorf("Expected 'token update error', got: %v", err)
		}
	})
}

func TestMongoServer_Token_RefreshToken(t *testing.T) {
	mt := mtest.New(t, mtest.NewOptions().ClientType(mtest.Mock))
	defer mt.ClearCollections()

	mt.Run("success", func(mt *mtest.T) {
		server := newTestMongoServer(mt)
		refreshToken := primitive.NewObjectID().Hex()
		tokenRec := bson.D{
			{Key: "refresh_token", Value: refreshToken},
			{Key: "client_id", Value: "refresh_client"},
			{Key: "scope", Value: "offline_access"},
		}

		mt.AddMockResponses(mtest.CreateCursorResponse(1, "foo.bar", mtest.FirstBatch, tokenRec))
		mt.AddMockResponses(mtest.CreateSuccessResponse())
		mt.AddMockResponses(
			mtest.CreateSuccessResponse(
				bson.E{Key: "n", Value: int64(1)},         // matched count
				bson.E{Key: "nModified", Value: int64(1)}, // modified count
			),
		)
		req := TokenRequest{
			GrantType:    string(GrantTypeRefreshToken),
			RefreshToken: refreshToken,
		}
		res, err := server.Token(context.Background(), req)
		if err != nil {
			mt.Fatalf("Token (refresh token) failed: %v", err)
		}
		if res.AccessToken == "" {
			mt.Error("Access token is empty after refresh")
		}
		if res.RefreshToken != refreshToken {
			mt.Errorf("Refresh token changed unexpectedly. Expected %s, got %s", refreshToken, res.RefreshToken)
		}
		if res.Scope != "offline_access" {
			mt.Errorf("Expected scope 'offline_access', got %s", res.Scope)
		}
	})

	mt.Run("invalid refresh token", func(mt *mtest.T) {
		server := newTestMongoServer(mt)
		mt.AddMockResponses(mtest.CreateCursorResponse(0, "foo.bar", mtest.FirstBatch)) // Simulate no documents found

		req := TokenRequest{GrantType: string(GrantTypeRefreshToken), RefreshToken: "invalid_refresh"}
		_, err := server.Token(context.Background(), req)
		if err == nil {
			mt.Fatal("Token did not return an error for invalid refresh token")
		}
		if err.Error() != "invalid refresh token" {
			mt.Errorf("Expected 'invalid refresh token', got: %v", err)
		}
	})

	mt.Run("update error", func(mt *mtest.T) {
		server := newTestMongoServer(mt)
		refreshToken := primitive.NewObjectID().Hex()
		tokenRec := bson.D{
			{Key: "refresh_token", Value: refreshToken},
			{Key: "client_id", Value: "refresh_client"},
			{Key: "scope", Value: "offline_access"},
		}
		mt.AddMockResponses(mtest.CreateCursorResponse(1, "foo.bar", mtest.FirstBatch, tokenRec))
		mt.AddMockResponses(mtest.CreateCommandErrorResponse(mtest.CommandError{Code: 1, Message: "refresh update error"}))
		mt.AddMockResponses(mtest.CreateCommandErrorResponse(mtest.CommandError{Code: 1, Message: "refresh update error"}))

		req := TokenRequest{
			GrantType:    string(GrantTypeRefreshToken),
			RefreshToken: refreshToken,
		}
		_, err := server.Token(context.Background(), req)
		if err == nil {
			mt.Fatal("Token did not return an error for refresh token update failure")
		}
		if !strings.Contains(err.Error(), "refresh update error") {
			mt.Errorf("Expected 'refresh update error', got: %v", err)
		}
	})
}

func TestMongoServer_Token_ClientCredentials(t *testing.T) {
	mt := mtest.New(t, mtest.NewOptions().ClientType(mtest.Mock))
	defer mt.ClearCollections()

	mt.Run("success", func(mt *mtest.T) {
		server := newTestMongoServer(mt)
		clientSecret := "client_secret_cc"
		clientDoc := bson.D{
			{Key: "client_id", Value: "cc_client"},
			{Key: "client_secret", Value: clientSecret},
			{Key: "scopes", Value: primitive.A{"api", "read"}},
			{Key: "grant_types", Value: primitive.A{"client_credentials"}},
		}

		mt.AddMockResponses(mtest.CreateCursorResponse(1, "foo.bar", mtest.FirstBatch, clientDoc)) // For client authentication
		mt.AddMockResponses(mtest.CreateSuccessResponse())                                         // For token insert
		mt.AddMockResponses(mtest.CreateSuccessResponse())                                         // For token insert

		req := TokenRequest{
			GrantType:    "client_credentials",
			ClientID:     "cc_client",
			ClientSecret: clientSecret,
		}
		res, err := server.Token(context.Background(), req)
		if err != nil {
			mt.Fatalf("Token (client credentials) failed: %v", err)
		}
		if res.AccessToken == "" {
			mt.Error("Access token is empty for client credentials")
		}
		if res.Scope != "api read" {
			mt.Errorf("Expected scope 'api read', got %s", res.Scope)
		}
	})

	mt.Run("invalid client credentials (client not found)", func(mt *mtest.T) {
		server := newTestMongoServer(mt)
		mt.AddMockResponses(mtest.CreateCursorResponse(0, "foo.bar", mtest.FirstBatch)) // Client not found

		req := TokenRequest{GrantType: "client_credentials", ClientID: "non_existent_cc", ClientSecret: "any"}
		_, err := server.Token(context.Background(), req)
		if err == nil {
			mt.Fatal("Token did not return error for non-existent client")
		}
		if err.Error() != "invalid client credentials" {
			mt.Errorf("Expected 'invalid client credentials', got: %v", err)
		}
	})

	mt.Run("invalid client credentials (secret mismatch)", func(mt *mtest.T) {
		server := newTestMongoServer(mt)
		clientDoc := bson.D{
			{Key: "client_id", Value: "cc_client"},
			{Key: "client_secret", Value: "correct_secret"},
		}
		mt.AddMockResponses(mtest.CreateCursorResponse(1, "foo.bar", mtest.FirstBatch, clientDoc))

		req := TokenRequest{GrantType: "client_credentials", ClientID: "cc_client", ClientSecret: "wrong_secret"}
		_, err := server.Token(context.Background(), req)
		if err == nil {
			mt.Fatal("Token did not return error for secret mismatch")
		}
		if err.Error() != "invalid client credentials" {
			mt.Errorf("Expected 'invalid client credentials', got: %v", err)
		}
	})

	mt.Run("grant_type not allowed", func(mt *mtest.T) {
		server := newTestMongoServer(mt)
		clientDoc := bson.D{
			{Key: "client_id", Value: "cc_client_no_grant"},
			{Key: "client_secret", Value: "secret"},
			{Key: "grant_types", Value: primitive.A{"authorization_code"}}, // Missing client_credentials
		}
		mt.AddMockResponses(mtest.CreateCursorResponse(1, "foo.bar", mtest.FirstBatch, clientDoc))

		req := TokenRequest{GrantType: "client_credentials", ClientID: "cc_client_no_grant", ClientSecret: "secret"}
		_, err := server.Token(context.Background(), req)
		if err == nil {
			mt.Fatal("Token did not return error for disallowed grant type")
		}
		if err.Error() != "grant_type not allowed" {
			mt.Errorf("Expected 'grant_type not allowed', got: %v", err)
		}
	})

	mt.Run("insert token error", func(mt *mtest.T) {
		server := newTestMongoServer(mt)
		clientSecret := "client_secret_cc_error"
		clientDoc := bson.D{
			{Key: "client_id", Value: "cc_client_error"},
			{Key: "client_secret", Value: clientSecret},
			{Key: "scopes", Value: primitive.A{"api"}},
			{Key: "grant_types", Value: primitive.A{"client_credentials"}},
		}

		mt.AddMockResponses(mtest.CreateCursorResponse(1, "foo.bar", mtest.FirstBatch, clientDoc))
		mt.AddMockResponses(mtest.CreateWriteErrorsResponse(mtest.WriteError{Code: 1, Message: "token insert error"}))
		mt.AddMockResponses(mtest.CreateWriteErrorsResponse(mtest.WriteError{Code: 1, Message: "token insert error"}))

		req := TokenRequest{
			GrantType:    "client_credentials",
			ClientID:     "cc_client_error",
			ClientSecret: clientSecret,
		}
		_, err := server.Token(context.Background(), req)
		if err == nil {
			mt.Fatal("Token did not return an error for token insert failure")
		}
		if !strings.Contains(err.Error(), "token insert error") {
			mt.Errorf("Expected 'token insert error', got: %v", err)
		}
	})
}

func TestMongoServer_Token_UnsupportedGrantType(t *testing.T) {
	mt := mtest.New(t, mtest.NewOptions().ClientType(mtest.Mock))
	defer mt.ClearCollections()
	mt.Run("", func(mt *mtest.T) {
		server := newTestMongoServer(mt)
		req := TokenRequest{GrantType: "unsupported_grant"}
		_, err := server.Token(context.Background(), req)
		if err == nil {
			mt.Fatal("Token did not return an error for unsupported grant type")
		}
		if err.Error() != "unsupported grant_type" {
			mt.Errorf("Expected 'unsupported grant_type', got: %v", err)
		}
	})
}

func TestMongoServer_Revoke(t *testing.T) {
	mt := mtest.New(t, mtest.NewOptions().ClientType(mtest.Mock))
	defer mt.ClearCollections()

	mt.Run("success", func(mt *mtest.T) {
		server := newTestMongoServer(mt)
		mt.AddMockResponses(bson.D{{Key: "ok", Value: 1}, {Key: "n", Value: 1}}) // Simulate successful delete

		req := RevocationRequest{Token: "some_token"}
		err := server.Revoke(context.Background(), req)
		if err != nil {
			mt.Fatalf("Revoke failed: %v", err)
		}
	})

	mt.Run("delete error", func(mt *mtest.T) {
		server := newTestMongoServer(mt)
		mt.AddMockResponses(mtest.CreateCommandErrorResponse(mtest.CommandError{Code: 1, Message: "revoke error"}))

		req := RevocationRequest{Token: "error_token"}
		err := server.Revoke(context.Background(), req)
		if err == nil {
			mt.Fatal("Revoke did not return an error for delete failure")
		}
		if !strings.Contains(err.Error(), "revoke error") {
			mt.Errorf("Expected 'revoke error', got: %v", err)
		}
	})
}

func TestMongoServer_Introspect(t *testing.T) {
	mt := mtest.New(t, mtest.NewOptions().ClientType(mtest.Mock))
	defer mt.ClearCollections()

	mt.Run("active token", func(mt *mtest.T) {
		server := newTestMongoServer(mt)
		expiresAt := time.Now().Add(time.Hour).Unix()
		tokenDoc := bson.D{
			{Key: "access_token", Value: "active_token"},
			{Key: "client_id", Value: "introspect_client"},
			{Key: "scope", Value: "email"},
			{Key: "expires_at", Value: expiresAt},
		}
		mt.AddMockResponses(mtest.CreateCursorResponse(1, "foo.bar", mtest.FirstBatch, tokenDoc))

		req := IntrospectRequest{Token: "active_token"}
		res, err := server.Introspect(context.Background(), req)
		if err != nil {
			mt.Fatalf("Introspect failed: %v", err)
		}
		if !res.Active {
			mt.Error("Expected token to be active")
		}
		if res.ClientID != "introspect_client" {
			mt.Errorf("Expected ClientID 'introspect_client', got %s", res.ClientID)
		}
		if res.Scope != "email" {
			mt.Errorf("Expected Scope 'email', got %s", res.Scope)
		}
		if res.Exp != expiresAt {
			mt.Errorf("Expected Exp %d, got %d", expiresAt, res.Exp)
		}
	})

	mt.Run("inactive token (expired)", func(mt *mtest.T) {
		server := newTestMongoServer(mt)
		expiresAt := time.Now().Add(-time.Hour).Unix() // Token expired an hour ago
		tokenDoc := bson.D{
			{Key: "access_token", Value: "expired_token"},
			{Key: "client_id", Value: "exp_client"},
			{Key: "scope", Value: "read"},
			{Key: "expires_at", Value: expiresAt},
		}
		mt.AddMockResponses(mtest.CreateCursorResponse(1, "foo.bar", mtest.FirstBatch, tokenDoc))

		req := IntrospectRequest{Token: "expired_token"}
		res, err := server.Introspect(context.Background(), req)
		if err != nil {
			mt.Fatalf("Introspect failed: %v", err)
		}
		if res.Active {
			mt.Error("Expected token to be inactive")
		}
		if res.ClientID != "exp_client" {
			mt.Errorf("Expected ClientID 'exp_client', got %s", res.ClientID)
		}
		if res.Scope != "read" {
			mt.Errorf("Expected Scope 'read', got %s", res.Scope)
		}
		if res.Exp != expiresAt {
			mt.Errorf("Expected Exp %d, got %d", expiresAt, res.Exp)
		}
	})

	mt.Run("token not found", func(mt *mtest.T) {
		server := newTestMongoServer(mt)
		mt.AddMockResponses(mtest.CreateCursorResponse(0, "foo.bar", mtest.FirstBatch))

		req := IntrospectRequest{Token: "non_existent_token"}
		res, err := server.Introspect(context.Background(), req)
		if err != nil {
			mt.Fatalf("Introspect failed for not found token: %v", err)
		}
		if res.Active {
			mt.Error("Expected token to be inactive")
		}
	})

	mt.Run("find error", func(mt *mtest.T) {
		server := newTestMongoServer(mt)
		mt.AddMockResponses(mtest.CreateCommandErrorResponse(mtest.CommandError{Code: 1, Message: "introspect find error"}))

		req := IntrospectRequest{Token: "error_token"}
		_, err := server.Introspect(context.Background(), req)
		if err == nil {
			mt.Fatal("Introspect did not return an error for find failure")
		}
		if !strings.Contains(err.Error(), "introspect find error") {
			mt.Errorf("Expected 'introspect find error', got: %v", err)
		}
	})
}

func TestMongoServer_JWKs(t *testing.T) {
	mt := mtest.New(t, mtest.NewOptions().ClientType(mtest.Mock))
	defer mt.ClearCollections()

	mt.Run("success_multiple_keys", func(mt *mtest.T) {
		server := newTestMongoServer(mt)
		key1 := json.RawMessage(`{"kty":"RSA","n":"abc"}`)
		key2 := json.RawMessage(`{"kty":"EC","crv":"P-256"}`)
		jwkDoc1 := bson.D{{Key: "key", Value: key1}}
		jwkDoc2 := bson.D{{Key: "key", Value: key2}}

		mt.AddMockResponses(mtest.CreateCursorResponse(1, "foo.bar", mtest.FirstBatch, jwkDoc1, jwkDoc2))
		mt.AddMockResponses(mtest.CreateCursorResponse(0, "foo.bar", mtest.NextBatch))

		jwkSet, err := server.JWKs(context.Background())
		if err != nil {
			mt.Fatalf("JWKs failed: %v", err)
		}
		if len(jwkSet.Keys) != 2 {
			mt.Fatalf("Expected 2 keys, got %d", len(jwkSet.Keys))
		}
		if !bytes.Equal(jwkSet.Keys[0], key1) || !bytes.Equal(jwkSet.Keys[1], key2) {
			t.Errorf("JWK keys mismatch")
		}
	})

	mt.Run("no keys", func(mt *mtest.T) {
		server := newTestMongoServer(mt)
		mt.AddMockResponses(mtest.CreateCursorResponse(0, "foo.bar", mtest.FirstBatch))

		jwkSet, err := server.JWKs(context.Background())
		if err != nil {
			mt.Fatalf("JWKs failed for no keys: %v", err)
		}
		if len(jwkSet.Keys) != 0 {
			mt.Errorf("Expected 0 keys, got %d", len(jwkSet.Keys))
		}
	})

	mt.Run("find error", func(mt *mtest.T) {
		server := newTestMongoServer(mt)
		mt.AddMockResponses(mtest.CreateCommandErrorResponse(mtest.CommandError{Code: 1, Message: "jwk find error"}))

		_, err := server.JWKs(context.Background())
		if err == nil {
			mt.Fatal("JWKs did not return an error for find failure")
		}
		if !strings.Contains(err.Error(), "jwk find error") {
			mt.Errorf("Expected 'jwk find error', got: %v", err)
		}
	})

	mt.Run("decode error", func(mt *mtest.T) {
		server := newTestMongoServer(mt)
		invalidDoc := bson.D{{Key: "key", Value: 123}} // Invalid type for key
		mt.AddMockResponses(mtest.CreateCursorResponse(0, "foo.bar", mtest.FirstBatch, invalidDoc))
		mt.AddMockResponses(mtest.CreateCursorResponse(0, "foo.bar", mtest.NextBatch))

		_, err := server.JWKs(context.Background())
		if err == nil {
			mt.Fatal("JWKs did not return an error for decode failure")
		}
	})
}

func TestMongoServer_SetClientImage(t *testing.T) {
	mt := mtest.New(t, mtest.NewOptions().ClientType(mtest.Mock))
	defer mt.ClearCollections()

	mt.Run("success_upsert", func(mt *mtest.T) {
		server := newTestMongoServer(mt)
		clientID := "image_client"
		imageData := []byte("fake_image_data")

		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)
		part, err := writer.CreateFormFile("image", "test_image.png")
		if err != nil {
			mt.Fatalf("Failed to create form file: %v", err)
		}
		_, _ = part.Write(imageData)
		_ = writer.Close()

		req := httptest.NewRequest(http.MethodPost, "/upload", body)
		req.Header.Set("Content-Type", writer.FormDataContentType())

		mt.AddMockResponses(mtest.CreateSuccessResponse()) // Simulate successful upsert

		err = server.SetClientImage(req, clientID)
		if err != nil {
			mt.Fatalf("SetClientImage failed: %v", err)
		}
	})

	mt.Run("parse multipart form error", func(mt *mtest.T) {
		server := newTestMongoServer(mt)
		req := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader("invalid_multipart_data"))
		req.Header.Set("Content-Type", "multipart/form-data; boundary=invalid_boundary")

		err := server.SetClientImage(req, "some_client")
		if err == nil {
			mt.Fatal("SetClientImage did not return an error for invalid multipart form")
		}
	})

	mt.Run("no image file", func(mt *mtest.T) {
		server := newTestMongoServer(mt)
		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)
		_ = writer.Close()

		req := httptest.NewRequest(http.MethodPost, "/upload", body)
		req.Header.Set("Content-Type", writer.FormDataContentType())

		err := server.SetClientImage(req, "some_client")
		if err == nil {
			mt.Fatal("SetClientImage did not return an error when no image file is present")
		}
		if !strings.Contains(err.Error(), "no such file") { // Error from FormFile when file not found
			mt.Errorf("Expected 'no such file' error, got: %v", err)
		}
	})

	mt.Run("update error", func(mt *mtest.T) {
		server := newTestMongoServer(mt)
		clientID := "error_image_client"
		imageData := []byte("error_image_data")

		body := &bytes.Buffer{}
		writer := multipart.NewWriter(body)
		part, err := writer.CreateFormFile("image", "error_image.png")
		if err != nil {
			mt.Fatalf("Failed to create form file: %v", err)
		}
		_, _ = part.Write(imageData)
		_ = writer.Close()

		req := httptest.NewRequest(http.MethodPost, "/upload", body)
		req.Header.Set("Content-Type", writer.FormDataContentType())

		mt.AddMockResponses(mtest.CreateCommandErrorResponse(mtest.CommandError{Code: 1, Message: "image upload error"}))

		err = server.SetClientImage(req, clientID)
		if err == nil {
			mt.Fatal("SetClientImage did not return an error for update failure")
		}
		if !strings.Contains(err.Error(), "image upload error") {
			mt.Errorf("Expected 'image upload error', got: %v", err)
		}
	})
}

func TestMongoServer_SendClientImage(t *testing.T) {
	mt := mtest.New(t, mtest.NewOptions().ClientType(mtest.Mock))
	defer mt.ClearCollections()

	mt.Run("success_found", func(mt *mtest.T) {
		server := newTestMongoServer(mt)
		clientID := "send_image_client"
		imageData := []byte("response_image_data")
		contentType := "image/jpeg"
		imageDoc := bson.D{
			{Key: "client_id", Value: clientID},
			{Key: "data", Value: imageData},
			{Key: "content_type", Value: contentType},
		}

		mt.AddMockResponses(mtest.CreateCursorResponse(1, "foo.bar", mtest.FirstBatch, imageDoc))

		recorder := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/image", nil)
		err := server.SendClientImage(recorder, req, clientID)
		if err != nil {
			mt.Fatalf("SendClientImage failed: %v", err)
		}

		if recorder.Code != http.StatusOK {
			mt.Errorf("Expected status %d, got %d", http.StatusOK, recorder.Code)
		}
		if recorder.Header().Get("Content-Type") != contentType {
			mt.Errorf("Expected Content-Type %s, got %s", contentType, recorder.Header().Get("Content-Type"))
		}
		if !bytes.Equal(recorder.Body.Bytes(), imageData) {
			mt.Error("Response body image data mismatch")
		}
		if recorder.Header().Get("Cache-Control") != "public, max-age=86400" {
			mt.Errorf("Expected Cache-Control 'public, max-age=86400', got %s", recorder.Header().Get("Cache-Control"))
		}
	})

	mt.Run("not found", func(mt *mtest.T) {
		server := newTestMongoServer(mt)
		mt.AddMockResponses(mtest.CreateCursorResponse(0, "foo.bar", mtest.FirstBatch))

		recorder := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/image", nil)
		err := server.SendClientImage(recorder, req, "non_existent_image")
		if err != nil {
			mt.Fatalf("SendClientImage failed for not found image: %v", err)
		}
		if recorder.Code != http.StatusNotFound {
			mt.Errorf("Expected status %d, got %d", http.StatusNotFound, recorder.Code)
		}
	})

	mt.Run("find error", func(mt *mtest.T) {
		server := newTestMongoServer(mt)
		mt.AddMockResponses(mtest.CreateCommandErrorResponse(mtest.CommandError{Code: 1, Message: "image find error"}))

		recorder := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/image", nil)
		err := server.SendClientImage(recorder, req, "error_image")
		if err == nil {
			mt.Fatal("SendClientImage did not return an error for find failure")
		}
		if !strings.Contains(err.Error(), "image find error") {
			mt.Errorf("Expected 'image find error', got: %v", err)
		}
	})
}

func TestMongoServer_HasAccess(t *testing.T) {
	mt := mtest.New(t, mtest.NewOptions().ClientType(mtest.Mock))
	defer mt.ClearCollections()

	mockRbacAccess := func(resource string, userId, accountId string, scopes ...string) bool {
		if resource == "protected_resource" {
			if userId == "testuser" && contains(scopes, "api:read") {
				return true
			}
			if userId == "" && len(scopes) == 0 { // No token case
				return true
			}
		}
		return false
	}

	mt.Run("success_has_access", func(mt *mtest.T) {
		server := newTestMongoServer(mt)
		expiresAt := time.Now().Add(time.Hour).Unix()
		tokenDoc := bson.D{
			{Key: "access_token", Value: "valid_token"},
			{Key: "user_id", Value: "testuser"},
			{Key: "scope", Value: "api:read api:write"},
			{Key: "expires_at", Value: expiresAt},
		}
		mt.AddMockResponses(mtest.CreateCursorResponse(1, "foo.bar", mtest.FirstBatch, tokenDoc))

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer valid_token")

		hasAccess, err := server.HasAccess(req, "protected_resource", mockRbacAccess)
		if err != nil {
			mt.Fatalf("HasAccess failed: %v", err)
		}
		if !hasAccess {
			mt.Error("Expected HasAccess to be true")
		}
	})

	mt.Run("no_authorization_header", func(mt *mtest.T) {
		server := newTestMongoServer(mt)
		req := httptest.NewRequest(http.MethodGet, "/", nil) // No Authorization header

		hasAccess, err := server.HasAccess(req, "protected_resource", mockRbacAccess)
		if err != nil {
			mt.Fatalf("HasAccess failed: %v", err)
		}
		if !hasAccess {
			mt.Error("Expected HasAccess to be true for no token case")
		}
	})

	mt.Run("expired_token", func(mt *mtest.T) {
		server := newTestMongoServer(mt)
		expiresAt := time.Now().Add(-time.Hour).Unix() // Expired
		tokenDoc := bson.D{
			{Key: "access_token", Value: "expired_token"},
			{Key: "user_id", Value: "testuser"},
			{Key: "scope", Value: "api:read"},
			{Key: "expires_at", Value: expiresAt},
		}
		mt.AddMockResponses(mtest.CreateCursorResponse(1, "foo.bar", mtest.FirstBatch, tokenDoc))

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer expired_token")

		hasAccess, err := server.HasAccess(req, "protected_resource", mockRbacAccess)
		if err != nil {
			mt.Fatalf("HasAccess failed: %v", err)
		}
		if hasAccess { // Should be false because token is expired
			mt.Error("Expected HasAccess to be false for expired token")
		}
	})

	mt.Run("invalid_token_not_found", func(mt *mtest.T) {
		server := newTestMongoServer(mt)
		mt.AddMockResponses(mtest.CreateCursorResponse(0, "foo.bar", mtest.FirstBatch)) // Token not found

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer non_existent_token")

		hasAccess, err := server.HasAccess(req, "protected_resource", mockRbacAccess)
		if err != nil {
			mt.Fatalf("HasAccess failed: %v", err)
		}
		if hasAccess { // Should be false because token is not found
			mt.Error("Expected HasAccess to be false for non-existent token")
		}
	})

	mt.Run("find error", func(mt *mtest.T) {
		server := newTestMongoServer(mt)
		mt.AddMockResponses(mtest.CreateCommandErrorResponse(mtest.CommandError{Code: 1, Message: "has access find error"}))

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer error_token")

		_, err := server.HasAccess(req, "protected_resource", mockRbacAccess)
		if err == nil {
			mt.Fatal("HasAccess did not return an error for find failure")
		}
		if !strings.Contains(err.Error(), "has access find error") {
			mt.Errorf("Expected 'has access find error', got: %v", err)
		}
	})

	mt.Run("no_access_rbac", func(mt *mtest.T) {
		server := newTestMongoServer(mt)
		expiresAt := time.Now().Add(time.Hour).Unix()
		tokenDoc := bson.D{
			{Key: "access_token", Value: "valid_token"},
			{Key: "user_id", Value: "anotheruser"},
			{Key: "scope", Value: "api:write"}, // Missing api:read
			{Key: "expires_at", Value: expiresAt},
		}
		mt.AddMockResponses(mtest.CreateCursorResponse(1, "foo.bar", mtest.FirstBatch, tokenDoc))

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer valid_token")

		hasAccess, err := server.HasAccess(req, "protected_resource", mockRbacAccess)
		if err != nil {
			mt.Fatalf("HasAccess failed: %v", err)
		}
		if hasAccess { // Should be false because RBAC says no
			mt.Error("Expected HasAccess to be false due to RBAC")
		}
	})
}

// Helper for slices
func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func Test_castStringSlice(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected []string
	}{
		{
			name:     "primitive.A of strings",
			input:    primitive.A{"one", "two", "three"},
			expected: []string{"one", "two", "three"},
		},
		{
			name:     "primitive.A with mixed types",
			input:    primitive.A{"one", 2, "three"},
			expected: []string{"one", "three"}, // 2 should be skipped
		},
		{
			name:     "empty primitive.A",
			input:    primitive.A{},
			expected: []string{},
		},
		{
			name:     "nil input",
			input:    nil,
			expected: nil,
		},
		{
			name:     "non-primitive.A input",
			input:    "a string",
			expected: nil,
		},
		{
			name:     "slice of interface{}",
			input:    []interface{}{"a", "b"}, // Should still result in nil because it's not primitive.A
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := castStringSlice(tt.input)

			if len(result) != len(tt.expected) {
				t.Fatalf("Expected length %d, got %d for input %v", len(tt.expected), len(result), tt.input)
			}
			for i := range result {
				if result[i] != tt.expected[i] {
					t.Errorf("At index %d, expected %s, got %s", i, tt.expected[i], result[i])
				}
			}
			// Handle nil case for nil input / non-primitive.A
			if tt.input == nil || (len(tt.expected) == 0 && result == nil) { // This handles cases like empty slice and actually nil
				if len(result) != 0 {
					t.Errorf("Expected nil or empty slice for nil/non-primitive.A input, got %v", result)
				}
			}
		})
	}
}
