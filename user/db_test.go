// file: user/store_test.go
package user

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	tcmysql "github.com/testcontainers/testcontainers-go/modules/mysql"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

// -----------------------------------------------------------------------
// Container helpers
// -----------------------------------------------------------------------

func newPostgresStore(t *testing.T) Store {
	t.Helper()
	ctx := context.Background()

	ctr, err := tcpostgres.Run(ctx,
		"postgres:16-alpine",
		tcpostgres.WithDatabase("user_test"),
		tcpostgres.WithUsername("testuser"),
		tcpostgres.WithPassword("testpass"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second),
		),
	)
	if err != nil {
		t.Fatalf("start postgres container: %v", err)
	}
	t.Cleanup(func() { _ = ctr.Terminate(ctx) })

	dsn, err := ctr.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("postgres connection string: %v", err)
	}

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	t.Cleanup(pool.Close)

	s, err := NewPostgresStore(ctx, pool)
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}
	return s
}

func newMySQLStore(t *testing.T) Store {
	t.Helper()
	ctx := context.Background()

	ctr, err := tcmysql.Run(ctx,
		"mysql:8",
		tcmysql.WithDatabase("user_test"),
		tcmysql.WithUsername("testuser"),
		tcmysql.WithPassword("testpass"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("port: 3306  MySQL Community Server").
				WithStartupTimeout(60*time.Second),
		),
	)
	if err != nil {
		t.Fatalf("start mysql container: %v", err)
	}
	t.Cleanup(func() { _ = ctr.Terminate(ctx) })

	host, err := ctr.Host(ctx)
	if err != nil {
		t.Fatalf("mysql host: %v", err)
	}
	port, err := ctr.MappedPort(ctx, "3306")
	if err != nil {
		t.Fatalf("mysql port: %v", err)
	}

	dsn := fmt.Sprintf("testuser:testpass@tcp(%s:%s)/user_test?parseTime=true", host, port.Port())
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatalf("sql.Open mysql: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	s, err := NewMySQLStore(ctx, db)
	if err != nil {
		t.Fatalf("NewMySQLStore: %v", err)
	}
	return s
}

// -----------------------------------------------------------------------
// Top-level test functions — one per backend
// -----------------------------------------------------------------------

func TestPostgresStore(t *testing.T) { runSuite(t, newPostgresStore(t)) }
func TestMySQLStore(t *testing.T)    { runSuite(t, newMySQLStore(t)) }

// -----------------------------------------------------------------------
// Shared suite
// -----------------------------------------------------------------------

func runSuite(t *testing.T, s Store) {
	t.Run("User", func(t *testing.T) { testUsers(t, s) })
	t.Run("Passkey", func(t *testing.T) { testPasskeys(t, s) })
}

// -----------------------------------------------------------------------
// User tests
// -----------------------------------------------------------------------

func testUsers(t *testing.T, s Store) {
	ctx := context.Background()

	t.Run("CreateAndGetByID", func(t *testing.T) {
		u := newTestUser("alice")
		if err := s.CreateUser(ctx, u); err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
		if u.ID == "" {
			t.Fatal("expected ID to be populated after create")
		}

		got, err := s.GetUserByID(ctx, u.ID)
		if err != nil {
			t.Fatalf("GetUserByID: %v", err)
		}
		assertUser(t, u, got)
	})

	t.Run("CreateAndGetByUsername", func(t *testing.T) {
		u := newTestUser("bob")
		if err := s.CreateUser(ctx, u); err != nil {
			t.Fatalf("CreateUser: %v", err)
		}

		got, err := s.GetUserByUsername(ctx, "bob")
		if err != nil {
			t.Fatalf("GetUserByUsername: %v", err)
		}
		assertUser(t, u, got)
	})

	t.Run("DuplicateUsernameReturnsError", func(t *testing.T) {
		if err := s.CreateUser(ctx, newTestUser("carol")); err != nil {
			t.Fatalf("first CreateUser: %v", err)
		}
		err := s.CreateUser(ctx, newTestUser("carol"))
		if err == nil {
			t.Fatal("expected error for duplicate username, got nil")
		}
	})

	t.Run("GetByIDNotFound", func(t *testing.T) {
		_, err := s.GetUserByID(ctx, "nonexistent-id")
		if err == nil {
			t.Fatal("expected error for missing user, got nil")
		}
	})

	t.Run("GetByUsernameNotFound", func(t *testing.T) {
		_, err := s.GetUserByUsername(ctx, "nobody")
		if err == nil {
			t.Fatal("expected error for missing user, got nil")
		}
	})

	t.Run("UpdateMutableFields", func(t *testing.T) {
		u := newTestUser("dave")
		if err := s.CreateUser(ctx, u); err != nil {
			t.Fatalf("CreateUser: %v", err)
		}

		u.TOTPEnabled = true
		u.TOTPSecret = "NEWSECRET"
		u.Roles = []string{"admin", "editor"}
		u.Settings = map[string]interface{}{"theme": "dark"}

		if err := s.UpdateUser(ctx, u); err != nil {
			t.Fatalf("UpdateUser: %v", err)
		}

		got, err := s.GetUserByID(ctx, u.ID)
		if err != nil {
			t.Fatalf("GetUserByID after update: %v", err)
		}
		if !got.TOTPEnabled {
			t.Error("expected TOTPEnabled=true after update")
		}
		if got.TOTPSecret != "NEWSECRET" {
			t.Errorf("TOTPSecret: want NEWSECRET, got %q", got.TOTPSecret)
		}
		if len(got.Roles) != 2 {
			t.Errorf("expected 2 roles, got %v", got.Roles)
		}
		if got.Settings["theme"] != "dark" {
			t.Errorf("settings.theme: want dark, got %v", got.Settings["theme"])
		}
	})

	t.Run("UpdateNotFoundReturnsError", func(t *testing.T) {
		err := s.UpdateUser(ctx, &User{ID: "ghost", Username: "ghost"})
		if err == nil {
			t.Fatal("expected error updating nonexistent user, got nil")
		}
	})

	t.Run("DeleteUser", func(t *testing.T) {
		u := newTestUser("eve")
		if err := s.CreateUser(ctx, u); err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
		if err := s.DeleteUser(ctx, u.ID); err != nil {
			t.Fatalf("DeleteUser: %v", err)
		}
		_, err := s.GetUserByID(ctx, u.ID)
		if err == nil {
			t.Fatal("expected error after delete, got nil")
		}
	})

	t.Run("DeleteNotFoundReturnsError", func(t *testing.T) {
		err := s.DeleteUser(ctx, "nonexistent-id")
		if err == nil {
			t.Fatal("expected error deleting nonexistent user, got nil")
		}
	})

	t.Run("PasswordHashRoundtrip", func(t *testing.T) {
		u := newTestUser("frank")
		u.PasswordHash = []byte("hashed-password-bytes")
		if err := s.CreateUser(ctx, u); err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
		got, err := s.GetUserByID(ctx, u.ID)
		if err != nil {
			t.Fatalf("GetUserByID: %v", err)
		}
		if string(got.PasswordHash) != "hashed-password-bytes" {
			t.Errorf("PasswordHash mismatch: got %q", got.PasswordHash)
		}
	})

	t.Run("NilSettingsRoundtrip", func(t *testing.T) {
		u := newTestUser("grace")
		u.Settings = nil
		if err := s.CreateUser(ctx, u); err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
		got, err := s.GetUserByID(ctx, u.ID)
		if err != nil {
			t.Fatalf("GetUserByID: %v", err)
		}
		if len(got.Settings) != 0 {
			t.Errorf("expected empty settings, got %v", got.Settings)
		}
	})

	t.Run("RolesRoundtrip", func(t *testing.T) {
		u := newTestUser("henry")
		u.Roles = []string{"admin", "viewer", "editor"}
		if err := s.CreateUser(ctx, u); err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
		got, err := s.GetUserByID(ctx, u.ID)
		if err != nil {
			t.Fatalf("GetUserByID: %v", err)
		}
		if len(got.Roles) != 3 {
			t.Errorf("expected 3 roles, got %v", got.Roles)
		}
	})
}

// -----------------------------------------------------------------------
// Passkey tests
// -----------------------------------------------------------------------

func testPasskeys(t *testing.T, s Store) {
	ctx := context.Background()

	// Shared owner for most sub-tests.
	owner := newTestUser("passkey-owner")
	if err := s.CreateUser(ctx, owner); err != nil {
		t.Fatalf("setup CreateUser: %v", err)
	}

	t.Run("AddAndGetByUserID", func(t *testing.T) {
		cred := newTestCredential([]byte("cred-id-1"))
		if err := s.AddPasskey(ctx, owner.ID, cred); err != nil {
			t.Fatalf("AddPasskey: %v", err)
		}

		creds, err := s.GetPasskeysByUserID(ctx, owner.ID)
		if err != nil {
			t.Fatalf("GetPasskeysByUserID: %v", err)
		}
		if !containsCredentialID(creds, []byte("cred-id-1")) {
			t.Errorf("credential cred-id-1 not found in %d results", len(creds))
		}
	})

	t.Run("GetByCredentialID", func(t *testing.T) {
		cred := newTestCredential([]byte("cred-id-2"))
		if err := s.AddPasskey(ctx, owner.ID, cred); err != nil {
			t.Fatalf("AddPasskey: %v", err)
		}

		gotCred, gotUser, err := s.GetPasskeyByCredentialID(ctx, []byte("cred-id-2"))
		if err != nil {
			t.Fatalf("GetPasskeyByCredentialID: %v", err)
		}
		if gotCred == nil {
			t.Fatal("expected credential, got nil")
		}
		if gotUser == nil || gotUser.UserID() != owner.ID {
			t.Errorf("expected owner %s, got user %+v", owner.ID, gotUser)
		}
		if string(gotCred.ID) != "cred-id-2" {
			t.Errorf("credential ID mismatch: got %q", gotCred.ID)
		}
	})

	t.Run("GetByCredentialIDNotFound", func(t *testing.T) {
		_, _, err := s.GetPasskeyByCredentialID(ctx, []byte("nonexistent-cred"))
		if err == nil {
			t.Fatal("expected error for missing credential, got nil")
		}
	})

	t.Run("UpdateSignCount", func(t *testing.T) {
		cred := newTestCredential([]byte("cred-id-3"))
		if err := s.AddPasskey(ctx, owner.ID, cred); err != nil {
			t.Fatalf("AddPasskey: %v", err)
		}

		cred.Authenticator.SignCount = 42
		if err := s.UpdatePasskey(ctx, owner.ID, cred); err != nil {
			t.Fatalf("UpdatePasskey: %v", err)
		}

		creds, err := s.GetPasskeysByUserID(ctx, owner.ID)
		if err != nil {
			t.Fatalf("GetPasskeysByUserID after update: %v", err)
		}
		for _, c := range creds {
			if string(c.ID) == "cred-id-3" {
				if c.Authenticator.SignCount != 42 {
					t.Errorf("SignCount: want 42, got %d", c.Authenticator.SignCount)
				}
				return
			}
		}
		t.Error("updated credential not found in results")
	})

	t.Run("UpdatePasskeyNotFound", func(t *testing.T) {
		err := s.UpdatePasskey(ctx, owner.ID, newTestCredential([]byte("no-such-cred")))
		if err == nil {
			t.Fatal("expected error updating nonexistent passkey, got nil")
		}
	})

	t.Run("DeletePasskey", func(t *testing.T) {
		cred := newTestCredential([]byte("cred-id-4"))
		if err := s.AddPasskey(ctx, owner.ID, cred); err != nil {
			t.Fatalf("AddPasskey: %v", err)
		}
		if err := s.DeletePasskey(ctx, owner.ID, []byte("cred-id-4")); err != nil {
			t.Fatalf("DeletePasskey: %v", err)
		}

		creds, err := s.GetPasskeysByUserID(ctx, owner.ID)
		if err != nil {
			t.Fatalf("GetPasskeysByUserID after delete: %v", err)
		}
		if containsCredentialID(creds, []byte("cred-id-4")) {
			t.Error("credential still present after delete")
		}
	})

	t.Run("DeleteUserCascadesPasskeys", func(t *testing.T) {
		u := newTestUser("cascade-user")
		if err := s.CreateUser(ctx, u); err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
		if err := s.AddPasskey(ctx, u.ID, newTestCredential([]byte("cascade-cred"))); err != nil {
			t.Fatalf("AddPasskey: %v", err)
		}
		if err := s.DeleteUser(ctx, u.ID); err != nil {
			t.Fatalf("DeleteUser: %v", err)
		}

		_, _, err := s.GetPasskeyByCredentialID(ctx, []byte("cascade-cred"))
		if err == nil {
			t.Fatal("expected passkey to be gone after user deletion (cascade), got nil error")
		}
	})

	t.Run("CredentialFlagsRoundtrip", func(t *testing.T) {
		flags := protocol.AuthenticatorFlags(
			protocol.FlagUserPresent |
				protocol.FlagUserVerified |
				protocol.FlagBackupEligible |
				protocol.FlagBackupState,
		)
		cred := newTestCredential([]byte("cred-flags"))
		cred.Flags = webauthn.NewCredentialFlags(flags)

		if err := s.AddPasskey(ctx, owner.ID, cred); err != nil {
			t.Fatalf("AddPasskey: %v", err)
		}

		gotCred, _, err := s.GetPasskeyByCredentialID(ctx, []byte("cred-flags"))
		if err != nil {
			t.Fatalf("GetPasskeyByCredentialID: %v", err)
		}
		if gotCred.Flags != cred.Flags {
			t.Errorf("Flags mismatch: want %+v, got %+v", cred.Flags, gotCred.Flags)
		}
	})

	t.Run("TransportsRoundtrip", func(t *testing.T) {
		cred := newTestCredential([]byte("cred-transports"))
		cred.Transport = []protocol.AuthenticatorTransport{
			protocol.USB,
			protocol.NFC,
			protocol.BLE,
		}
		if err := s.AddPasskey(ctx, owner.ID, cred); err != nil {
			t.Fatalf("AddPasskey: %v", err)
		}

		creds, err := s.GetPasskeysByUserID(ctx, owner.ID)
		if err != nil {
			t.Fatalf("GetPasskeysByUserID: %v", err)
		}
		for _, c := range creds {
			if string(c.ID) == "cred-transports" {
				if len(c.Transport) != 3 {
					t.Errorf("expected 3 transports, got %d: %v", len(c.Transport), c.Transport)
				}
				return
			}
		}
		t.Error("credential with transports not found")
	})

	t.Run("MultiplePasskeysPerUser", func(t *testing.T) {
		u := newTestUser("multi-key-user")
		if err := s.CreateUser(ctx, u); err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
		for i := 0; i < 3; i++ {
			id := []byte(fmt.Sprintf("multi-cred-%d", i))
			if err := s.AddPasskey(ctx, u.ID, newTestCredential(id)); err != nil {
				t.Fatalf("AddPasskey %d: %v", i, err)
			}
		}

		creds, err := s.GetPasskeysByUserID(ctx, u.ID)
		if err != nil {
			t.Fatalf("GetPasskeysByUserID: %v", err)
		}
		if len(creds) != 3 {
			t.Errorf("expected 3 credentials, got %d", len(creds))
		}
	})

	t.Run("GetPasskeysForUserWithNone", func(t *testing.T) {
		u := newTestUser("no-passkey-user")
		if err := s.CreateUser(ctx, u); err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
		creds, err := s.GetPasskeysByUserID(ctx, u.ID)
		if err != nil {
			t.Fatalf("GetPasskeysByUserID: %v", err)
		}
		if len(creds) != 0 {
			t.Errorf("expected 0 credentials for new user, got %d", len(creds))
		}
	})
}

// -----------------------------------------------------------------------
// Factories
// -----------------------------------------------------------------------

func newTestUser(username string) *User {
	return &User{
		Username:    username,
		Roles:       []string{"user"},
		TOTPEnabled: false,
		TOTPSecret:  "",
		Settings:    map[string]interface{}{"locale": "en"},
	}
}

func newTestCredential(id []byte) webauthn.Credential {
	return webauthn.Credential{
		ID:              id,
		PublicKey:       []byte("fake-public-key-bytes"),
		AttestationType: "none",
		Transport:       []protocol.AuthenticatorTransport{protocol.Internal},
		Authenticator: webauthn.Authenticator{
			AAGUID:    make([]byte, 16),
			SignCount: 0,
		},
	}
}

// -----------------------------------------------------------------------
// Assertion helpers
// -----------------------------------------------------------------------

func assertUser(t *testing.T, want, got *User) {
	t.Helper()
	if got == nil {
		t.Fatal("expected user, got nil")
	}
	if got.ID != want.ID {
		t.Errorf("ID: want %q, got %q", want.ID, got.ID)
	}
	if got.Username != want.Username {
		t.Errorf("Username: want %q, got %q", want.Username, got.Username)
	}
}

func containsCredentialID(creds []webauthn.Credential, id []byte) bool {
	for _, c := range creds {
		if string(c.ID) == string(id) {
			return true
		}
	}
	return false
}
