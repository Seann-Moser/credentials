package session

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Seann-Moser/credentials/oauth/oserver"
	"github.com/Seann-Moser/rbac"
)

func TestHMAC(t *testing.T) {
	secret := []byte("mysecret")
	msg := "hello"
	sig := computeHMAC(msg, secret)
	if !validateHMAC(msg, sig, secret) {
		t.Errorf("validateHMAC failed for valid signature")
	}
	if validateHMAC(msg, sig+"bad", secret) {
		t.Errorf("validateHMAC passed for invalid signature")
	}
}

func TestCookieRoundTrip(t *testing.T) {
	secret := []byte("mysessionsecret")
	u := &UserSessionData{
		UserID:    "user123",
		SignedIn:  true,
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
		Roles:     []string{"admin", "user"},
	}
	// Set the cookie on a response recorder
	rr := httptest.NewRecorder()
	err := SetSessionCookie(rr, u, secret)
	if err != nil {
		t.Fatalf("SetSessionCookie error: %v", err)
	}
	// Extract cookie and add to a new request
	res := rr.Result()
	cookies := res.Cookies()
	if len(cookies) == 0 {
		t.Fatal("no cookie set")
	}
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(cookies[0])
	got, err := GetSessionFromCookie(req, secret)
	if err != nil {
		t.Fatalf("GetSessionFromCookie error: %v", err)
	}
	if got.UserID != u.UserID {
		t.Errorf("expected UserID %s, got %s", u.UserID, got.UserID)
	}
	if !got.SignedIn {
		t.Errorf("expected SignedIn true")
	}
}

func TestContextSession(t *testing.T) {
	u := &UserSessionData{UserID: "ctxuser"}
	ctx := u.WithContext(context.Background())
	got, err := GetSession(ctx)
	if err != nil {
		t.Errorf("GetSession error: %v", err)
	}
	if got.UserID != u.UserID {
		t.Errorf("expected %s, got %s", u.UserID, got.UserID)
	}
	// error case
	_, err = GetSession(context.Background())
	if err == nil {
		t.Errorf("expected error for missing session in context")
	}
}

func TestAuthenticate_Cookie(t *testing.T) {
	secret := []byte("secret")
	ttl := time.Hour
	// Create client with no OAuth server (only cookie)
	client := NewClient(&oserver.MockOServer{}, nil, secret, ttl)
	// First request: no cookie => anonymous session
	rr1 := httptest.NewRecorder()
	req1 := httptest.NewRequest("GET", "/", nil)
	u1, _, err := client.Authenticate(rr1, req1)
	if err != nil {
		t.Fatalf("Authenticate error: %v", err)
	}
	if u1.SignedIn {
		t.Errorf("expected SignedIn false for anonymous")
	}
	// Use returned cookie on second request
	cookie := rr1.Result().Cookies()[0]
	rr2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.AddCookie(cookie)
	u2, _, err := client.Authenticate(rr2, req2)
	if err != nil {
		t.Fatalf("Authenticate error: %v", err)
	}
	if u2.UserID != u1.UserID {
		t.Errorf("expected same anon UserID, got %s vs %s", u2.UserID, u1.UserID)
	}
}

func TestAuthenticate_OAuth(t *testing.T) {
	secret := []byte("secret")
	ttl := time.Hour
	//info := &TokenInfo{UserID: "oauth-user", AccountID: "acct123", ExpiresIn: 3600}
	fserver := &oserver.MockOServer{}
	fmanager := &rbac.Manager{}
	client := NewClient(fserver, fmanager, secret, ttl)
	// Request with Bearer header
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer mytoken")
	rr := httptest.NewRecorder()
	_, _, err := client.Authenticate(rr, req)
	if err != nil {
		t.Fatalf("Authenticate error: %v", err)
	}
	//if !u.SignedIn {
	//	t.Errorf("expected SignedIn true for OAuth user")
	//}
	//if u.UserID != info.UserID {
	//	t.Errorf("expected UserID %s, got %s", info.UserID, u.UserID)
	//}
	//if len(u.Roles) != 2 {
	//	t.Errorf("expected 2 roles, got %v", u.Roles)
	//}
}

func TestUserSessionData_WithContext(t *testing.T) {
	c := &http.Cookie{Value: "eyJ1c2VyX2lkIjoiNjkxZjljNDliYThlZGM1YTA1NGYxYjE0Iiwicm9sZXMiOlsidXNlciJdLCJzaWduZWRfaW4iOnRydWUsImV4cGlyZXNfYXQiOjE3NjQyODQxMjksImRvbWFpbiI6ImxvY2FsaG9zdCJ9|-kF7RkmbcKcFiNH94aBisEzRwLe2Gaz3yyT6D8kZdEQ="}

	data, err := decode(c, []byte("default"))
	if err != nil {
		t.Errorf("failed decoding data: %s", err)
		return
	}
	println(data.UserID)
}
