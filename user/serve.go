package user

import (
	"bytes"
	"context"
	"crypto/hmac"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Seann-Moser/credentials/session"
	"github.com/Seann-Moser/credentials/utils"
	"github.com/Seann-Moser/rbac"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/pquerna/otp/totp" // For TOTP generation and validation
	redis "github.com/redis/go-redis/v9"
	"log/slog"
	"os"
	"path"
	"regexp"
	"strings"

	"github.com/crazy3lf/colorconv"
	"github.com/yeqown/go-qrcode/v2"
	"github.com/yeqown/go-qrcode/writer/standard"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"net/url"
	"time"
)

const totpChallengeExpiry = 5 * time.Minute // TOTP challenge lasts 5 minutes

type totpChallengeData struct {
	UserID    string
	ExpiresAt time.Time
}
type Server struct {
	Store              Store
	SessionSecret      []byte
	WebAuthn           *webauthn.WebAuthn
	redis              redis.Cmdable
	rbac               *rbac.Manager
	challengeStore     map[string]*webauthn.SessionData // In-memory store for WebAuthn challenges todo make this redis
	totpChallengeStore map[string]totpChallengeData     // In-memory store for TOTP login challenges todo make this redis
	RPName             string                           // Relying Party Name for TOTP provisioning
}

// NewServer creates a new Server instance.
func NewServer(store Store, rbac *rbac.Manager, sessionSecret []byte, rpID, rpDisplayName string, rpOrigin ...string) (*Server, error) {
	wv, err := webauthn.New(&webauthn.Config{
		RPDisplayName: rpDisplayName, // Display Name for your site
		RPID:          rpID,          // The origin for your site
		RPOrigins:     rpOrigin,
		// For development, allow http:
		// AttestationPreference: "none", // Recommended for production
		// Timeout:                60000,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create webauthn instance: %w", err)
	}

	return &Server{
		Store:              store,
		rbac:               rbac,
		SessionSecret:      sessionSecret,
		WebAuthn:           wv,
		challengeStore:     make(map[string]*webauthn.SessionData), // Initialize WebAuthn challenge store
		totpChallengeStore: make(map[string]totpChallengeData),     // Initialize TOTP challenge store
		RPName:             rpDisplayName,                          // Use display name as RPName for TOTP
	}, nil
}
func (s *Server) SetupRedis(cmdable redis.Cmdable) {
	s.redis = cmdable
}

// writeJSON helper sends a JSON response.
func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("Error writing JSON response: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// writeError helper sends a JSON error response.
func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

// =============================================================================
// Middleware
// =============================================================================

// ContextKey is a custom type for context key to avoid collisions.
type ContextKey string

const userCtxKey ContextKey = "user"

// AuthMiddleware checks for a valid session and attaches the User object to the request context.
func (s *Server) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ses, err := session.GetSessionFromCookie(r, s.SessionSecret)
		if err != nil || !ses.SignedIn {
			log.Printf("Authentication failed: %v", err)
			next.ServeHTTP(w, r)
			return
		}

		user, err := s.Store.GetUserByID(r.Context(), ses.UserID)
		if err != nil {
			log.Printf("User not found from session ID %s: %v", ses.UserID, err)
			writeError(w, http.StatusUnauthorized, "User session invalid or user not found")
			session.ClearSessionCookie(w) // Clear potentially stale cookie
			return
		}

		// Attach user to context
		ctx := context.WithValue(r.Context(), userCtxKey, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetUserFromContext retrieves the User from the request context.
func GetUserFromContext(ctx context.Context) (*User, error) {
	user, ok := ctx.Value(userCtxKey).(*User)
	if !ok {
		return nil, errors.New("user not found in context")
	}
	return user, nil
}

// =============================================================================
// Handlers
// =============================================================================

// RegisterRequest represents the request body for user registration.
type RegisterRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Username must:
//   - start with a letter
//   - be 3–20 characters long
//   - contain only letters, digits, or underscores
var usernameRegex = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{1,19}$`)

// Password must:
//   - be 8–64 characters long
//   - include at least one lowercase letter
//   - include at least one uppercase letter
//   - include at least one digit
//   - include at least one special character (non-alphanumeric)
var (
	lowerRegex   = regexp.MustCompile(`[a-z]`)
	upperRegex   = regexp.MustCompile(`[A-Z]`)
	digitRegex   = regexp.MustCompile(`\d`)
	specialRegex = regexp.MustCompile(`[\W_]`)
)

// ValidateUsername returns an error if the username doesn’t meet policy.
func ValidateUsername(u string) error {
	if !usernameRegex.MatchString(u) {
		return errors.New("username must start with a letter, be 3–20 chars long, and contain only letters, digits, or underscores")
	}
	return nil
}

// ValidatePassword returns an error if the password doesn’t meet policy.
func ValidatePassword(pw string) error {
	if len(pw) < 8 || len(pw) > 64 {
		return errors.New("password must be 8–64 characters long")
	}
	if !lowerRegex.MatchString(pw) {
		return errors.New("password must include at least one lowercase letter")
	}
	if !upperRegex.MatchString(pw) {
		return errors.New("password must include at least one uppercase letter")
	}
	if !digitRegex.MatchString(pw) {
		return errors.New("password must include at least one digit")
	}
	if !specialRegex.MatchString(pw) {
		return errors.New("password must include at least one special character")
	}
	return nil
}

// ValidateCredentials checks both username and password in one call.
func ValidateCredentials(username, password string) error {
	if err := ValidateUsername(username); err != nil {
		return err
	}
	if err := ValidatePassword(password); err != nil {
		return err
	}
	return nil
}

// RegisterHandler handles new user registration.
func (s *Server) RegisterHandler(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if err := ValidateCredentials(req.Username, req.Password); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Check if username already exists
	_, err := s.Store.GetUserByUsername(r.Context(), req.Username)
	if err == nil {
		writeError(w, http.StatusConflict, "Username already exists")
		return
	}
	if err.Error() != "user not found" { // Real error, not just not found
		log.Printf("Error checking existing user: %v", err)
		writeError(w, http.StatusInternalServerError, "Failed to check username availability")
		return
	}

	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("Error hashing password: %v", err)
		writeError(w, http.StatusInternalServerError, "Failed to register user")
		return
	}

	// Create new user
	user := &User{
		Username:     req.Username,
		PasswordHash: hashedPassword,
		Roles:        []string{"user"}, // Default role
		Passkeys:     []WebAuthnCredential{},
		TOTPSecret:   "", // No TOTP secret initially
		TOTPEnabled:  false,
	}

	err = s.Store.CreateUser(r.Context(), user)
	if err != nil {
		log.Printf("Error creating user: %v", err)
		writeError(w, http.StatusInternalServerError, "Failed to register user")
		return
	}
	role, err := s.rbac.Roles.GetRoleByName(r.Context(), "user")
	if role == nil || err != nil {
		role = &rbac.Role{Name: "user"}
		err := s.rbac.CreateRole(r.Context(), role)
		if err != nil {
			log.Printf("Error creating role: %v", err)
		}
	}
	if role != nil {
		err = s.rbac.AssignRoleToUser(r.Context(), user.ID.String(), role.ID)
		if err != nil {
			log.Printf("Error assigning role to user: %v", err)
		}
	}

	sessionData := &session.UserSessionData{
		UserID:    user.UserID(),
		Roles:     user.Roles,
		SignedIn:  true,
		ExpiresAt: time.Now().Add(time.Hour * 24 * 7).Unix(),
		Domain:    utils.GetDomain(r),
	}
	if err := session.SetSessionCookie(w, sessionData, s.SessionSecret); err != nil {
		log.Printf("Error setting session cookie after TOTP: %v", err)
		writeError(w, http.StatusInternalServerError, "Failed to set session")
		return
	}
	log.Printf("User registered: %s", user.Username)
	writeJSON(w, http.StatusCreated, map[string]string{"message": "User registered successfully", "userId": user.UserID(), "username": user.Username})
}

// LoginRequest represents the request body for password login.
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LoginPasswordHandler handles user login with username and password.
// If TOTP is enabled, it returns a 202 Accepted status and requires a TOTP challenge.
func (s *Server) LoginPasswordHandler(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	user, err := s.Store.GetUserByUsername(r.Context(), req.Username)
	if err != nil {
		log.Printf("Login failed for %s: %v", req.Username, err)
		writeError(w, http.StatusUnauthorized, "Invalid username or password")
		return
	}

	// Compare hashed password
	if err := bcrypt.CompareHashAndPassword(user.PasswordHash, []byte(req.Password)); err != nil {
		log.Printf("Password mismatch for user %s", req.Username)
		writeError(w, http.StatusUnauthorized, "Invalid username or password")
		return
	}

	// Check for TOTP 2FA
	if user.TOTPEnabled {
		// Initiate TOTP challenge
		sessionID := uuid.New().String()
		s.setTopChallenge(sessionID, totpChallengeData{
			UserID:    user.UserID(),
			ExpiresAt: time.Now().Add(totpChallengeExpiry),
		})
		log.Printf("User %s requires TOTP. Initiating challenge with session ID: %s", user.Username, sessionID)
		writeJSON(w, http.StatusAccepted, map[string]string{
			"message":   "TOTP required",
			"sessionId": sessionID,
			"userId":    user.UserID(),
			"username":  user.Username,
		})
		return
	}

	// If no TOTP, set session cookie
	sessionData := &session.UserSessionData{
		UserID:    user.UserID(),
		Roles:     user.Roles,
		SignedIn:  true,
		ExpiresAt: time.Now().Add(time.Hour * 24 * 7).Unix(),
		Domain:    utils.GetDomain(r),
	}
	if err := session.SetSessionCookie(w, sessionData, s.SessionSecret); err != nil {
		log.Printf("Error setting session cookie: %v", err)
		writeError(w, http.StatusInternalServerError, "Failed to set session")
		return
	}

	log.Printf("User %s logged in via password", user.Username)
	writeJSON(w, http.StatusOK, map[string]string{"message": "Logged in successfully", "userId": user.UserID(), "username": user.Username})
}

func (s *Server) setTopChallenge(key string, t totpChallengeData) {
	if s.redis == nil {
		s.totpChallengeStore[key] = t
		return
	}
	data, _ := json.Marshal(t)
	s.redis.Set(context.Background(), "topt-"+key, string(data), totpChallengeExpiry)
}

func (s *Server) getTopChallenge(key string) *totpChallengeData {
	if s.redis == nil {
		if t, found := s.totpChallengeStore[key]; found {
			return &t
		}
		return nil
	}
	topChallenge, err := s.redis.Get(context.Background(), "topt-"+key).Result()
	if err != nil {
		return nil
	}
	var t totpChallengeData
	err = json.Unmarshal([]byte(topChallenge), &t)
	if err != nil {
		return nil
	}
	return &t
}

func (s *Server) setChallenge(key string, t *webauthn.SessionData) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(t); err != nil {
		log.Printf("gob encode error: %v", err)
	}

	if s.redis != nil {
		s.redis.Set(context.Background(), "webauthn-"+key, buf.Bytes(), totpChallengeExpiry)
	} else {
		s.challengeStore[key] = t
	}
}

func (s *Server) getChallenge(key string) *webauthn.SessionData {
	if s.redis != nil {
		data, err := s.redis.Get(context.Background(), "webauthn-"+key).Bytes()
		if err != nil {
			return nil
		}
		var sd webauthn.SessionData
		buf := bytes.NewBuffer(data)
		if err := gob.NewDecoder(buf).Decode(&sd); err != nil {
			log.Printf("gob decode error: %v", err)
			return nil
		}
		return &sd
	}
	return s.challengeStore[key]
}

// TOTPLoginRequest represents the request body for TOTP verification during login.
type TOTPLoginRequest struct {
	SessionID string `json:"sessionId"`
	TOTPCode  string `json:"totpCode"`
}

// LoginTOTPHandler verifies the TOTP code after initial password login.
func (s *Server) LoginTOTPHandler(w http.ResponseWriter, r *http.Request) {
	var req TOTPLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.SessionID == "" || req.TOTPCode == "" {
		writeError(w, http.StatusBadRequest, "Session ID and TOTP code are required")
		return
	}

	challenge := s.getTopChallenge(req.SessionID)
	if challenge == nil || time.Now().After(challenge.ExpiresAt) {
		writeError(w, http.StatusUnauthorized, "TOTP challenge expired or invalid")
		return
	}
	defer func() {
		delete(s.totpChallengeStore, req.SessionID) // Clear invalid challenge
		if s.redis != nil {
			s.redis.Del(context.Background(), "topt-"+req.SessionID)
		}
	}()

	user, err := s.Store.GetUserByID(r.Context(), challenge.UserID)
	if err != nil {
		log.Printf("User not found for TOTP challenge ID %s: %v", req.SessionID, err)
		writeError(w, http.StatusInternalServerError, "User not found")
		return
	}

	if !user.TOTPEnabled || user.TOTPSecret == "" {
		writeError(w, http.StatusBadRequest, "TOTP is not enabled for this user")
		return
	}

	// Validate the TOTP code
	valid := totp.Validate(req.TOTPCode, user.TOTPSecret)
	if !valid {
		log.Printf("Invalid TOTP code for user %s", user.Username)
		writeError(w, http.StatusUnauthorized, "Invalid TOTP code")
		return
	}

	sessionData := &session.UserSessionData{
		UserID:    user.UserID(),
		Roles:     user.Roles,
		SignedIn:  true,
		ExpiresAt: time.Now().Add(time.Hour * 24 * 7).Unix(),
		Domain:    utils.GetDomain(r),
	}
	if err := session.SetSessionCookie(w, sessionData, s.SessionSecret); err != nil {
		log.Printf("Error setting session cookie after TOTP: %v", err)
		writeError(w, http.StatusInternalServerError, "Failed to set session")
		return
	}

	log.Printf("User %s logged in via TOTP", user.Username)
	writeJSON(w, http.StatusOK, map[string]string{"message": "Logged in successfully (TOTP verified)", "userId": user.UserID(), "username": user.Username})
}

// LogoutHandler handles user logout by clearing the session cookie.
func (s *Server) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	// No need to check auth, just clear the cookie
	session.ClearSessionCookie(w)
	log.Println("User logged out")
	writeJSON(w, http.StatusOK, map[string]string{"message": "Logged out successfully"})
}

// UserIDRequest represents a request body containing a user ID.
type UserIDRequest struct {
	UserID string `json:"userId"`
}

// DeleteUserHandler handles deleting a user account.
// This is an admin-only endpoint.
func (s *Server) DeleteUserHandler(w http.ResponseWriter, r *http.Request) {
	var req UserIDRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.UserID == "" {
		writeError(w, http.StatusBadRequest, "User ID is required")
		return
	}

	// Perform deletion
	err := s.Store.DeleteUser(r.Context(), req.UserID)
	if err != nil {
		log.Printf("Error deleting user %s: %v", req.UserID, err)
		writeError(w, http.StatusInternalServerError, "Failed to delete user")
		return
	}

	log.Printf("User %s deleted by admin", req.UserID)
	writeJSON(w, http.StatusOK, map[string]string{"message": fmt.Sprintf("User %s deleted successfully", req.UserID)})
}

// UpdateUserRolesRequest represents the request body for updating user roles.
type UpdateUserRolesRequest struct {
	UserID string   `json:"userId"`
	Roles  []string `json:"roles"`
}

// ManageUserHandler handles updating user roles (admin-only).
func (s *Server) ManageUserHandler(w http.ResponseWriter, r *http.Request) {
	var req UpdateUserRolesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.UserID == "" || req.Roles == nil {
		writeError(w, http.StatusBadRequest, "User ID and roles are required")
		return
	}

	user, err := s.Store.GetUserByID(r.Context(), req.UserID)
	if err != nil {
		writeError(w, http.StatusNotFound, "User not found")
		return
	}

	user.Roles = req.Roles
	err = s.Store.UpdateUser(r.Context(), user)
	if err != nil {
		log.Printf("Error updating user %s roles: %v", req.UserID, err)
		writeError(w, http.StatusInternalServerError, "Failed to update user roles")
		return
	}

	log.Printf("User %s roles updated to %v by admin", user.Username, user.Roles)
	writeJSON(w, http.StatusOK, map[string]string{"message": "User roles updated successfully", "userId": user.UserID(), "roles": strings.Join(user.Roles, ",")})
}

func (s *Server) GetUser(w http.ResponseWriter, r *http.Request) {
	user, err := GetUserFromContext(r.Context())
	if err != nil {
		writeError(w, http.StatusUnauthorized, "Authentication required")
		return
	}
	writeJSON(w, http.StatusOK, user)

}

// UserSettingsUpdateRequest represents the request body for updating user settings.
type UserSettingsUpdateRequest struct {
	NewUsername *string                `json:"newUsername,omitempty"`
	NewPassword *string                `json:"newPassword,omitempty"`
	Settings    map[string]interface{} `json:"settings,omitempty"`
}

// UserSettingsHandler handles authenticated user setting updates.
func (s *Server) UserSettingsHandler(w http.ResponseWriter, r *http.Request) {
	user, err := GetUserFromContext(r.Context())
	if err != nil {
		writeError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	var req UserSettingsUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	updated := false
	if req.NewUsername != nil && *req.NewUsername != "" {
		// Check if new username already exists
		existingUser, err := s.Store.GetUserByUsername(r.Context(), *req.NewUsername)
		if err == nil && existingUser.ID != user.ID {
			writeError(w, http.StatusConflict, "New username already taken")
			return
		}
		if err != nil && err.Error() != "user not found" {
			log.Printf("Error checking new username: %v", err)
			writeError(w, http.StatusInternalServerError, "Failed to update settings")
			return
		}
		user.Username = *req.NewUsername
		updated = true
	}

	if req.NewPassword != nil && *req.NewPassword != "" {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(*req.NewPassword), bcrypt.DefaultCost)
		if err != nil {
			log.Printf("Error hashing new password: %v", err)
			writeError(w, http.StatusInternalServerError, "Failed to update password")
			return
		}
		user.PasswordHash = hashedPassword
		updated = true
	}
	if req.Settings != nil {
		for k, v := range req.Settings {
			if v == nil {
				delete(user.Settings, k)
			} else {
				user.Settings[k] = v
			}
		}
	}
	if !updated {
		writeError(w, http.StatusBadRequest, "No settings provided for update")
		return
	}

	err = s.Store.UpdateUser(r.Context(), user)
	if err != nil {
		log.Printf("Error updating user settings for %s: %v", user.Username, err)
		writeError(w, http.StatusInternalServerError, "Failed to update settings")
		return
	}

	log.Printf("User %s updated settings", user.Username)
	writeJSON(w, http.StatusOK, map[string]string{"message": "Settings updated successfully", "username": user.Username})
}

// =============================================================================
// Passkey (WebAuthn) Handlers
// =============================================================================

// BeginPasskeyRegistrationRequest represents the request to begin passkey registration.
type BeginPasskeyRegistrationRequest struct {
	Username string `json:"username"`
}

// BeginPasskeyRegistrationHandler initiates the passkey registration process.
func (s *Server) BeginPasskeyRegistrationHandler(w http.ResponseWriter, r *http.Request) {
	user, err := GetUserFromContext(r.Context())
	if err != nil {
		writeError(w, http.StatusUnauthorized, "Authentication required to add passkey")
		return
	}

	// Generate WebAuthn registration options
	options, ses, err := s.WebAuthn.BeginRegistration(user)
	if err != nil {
		log.Printf("Error beginning registration: %v", err)
		writeError(w, http.StatusInternalServerError, "Failed to begin passkey registration")
		return
	}

	// Store the session data (challenge) securely
	// For simplicity, using in-memory map. In production, use Redis/database.
	s.setChallenge(user.UserID(), ses)
	log.Printf("Begin passkey registration for user %s. Challenge stored.", user.Username)

	writeJSON(w, http.StatusOK, options)
}

// FinishPasskeyRegistrationHandler finalizes the passkey registration.
func (s *Server) FinishPasskeyRegistrationHandler(w http.ResponseWriter, r *http.Request) {
	user, err := GetUserFromContext(r.Context())
	if err != nil {
		writeError(w, http.StatusUnauthorized, "Authentication required to finish passkey registration")
		return
	}

	// Retrieve stored challenge

	ses := s.getChallenge(user.UserID())
	if ses == nil {
		writeError(w, http.StatusBadRequest, "No active passkey registration challenge found")
		return
	}
	// Clear the challenge immediately after retrieval
	delete(s.challengeStore, user.UserID())
	if s.redis != nil {
		s.redis.Del(context.Background(), "webauth-"+user.UserID())
	}
	credential, err := s.WebAuthn.FinishRegistration(user, *ses, r)
	if err != nil {
		log.Printf("Error finishing registration: %v", err)
		writeError(w, http.StatusInternalServerError, "Failed to finish passkey registration")
		return
	}

	// Add the new passkey to the user in the database
	err = s.Store.AddPasskey(r.Context(), user.UserID(), *credential)
	if err != nil {
		log.Printf("Error adding passkey to store: %v", err)
		writeError(w, http.StatusInternalServerError, "Failed to save passkey")
		return
	}

	log.Printf("Passkey registered for user %s. Credential ID: %x", user.Username, credential.ID)
	writeJSON(w, http.StatusOK, map[string]string{"message": "Passkey registered successfully"})
}

// BeginPasskeyLoginRequest represents the request to begin passkey login.
type BeginPasskeyLoginRequest struct {
	Username string `json:"username"` // Username is optional, but useful for filtering credentials
}

// BeginPasskeyLoginHandler initiates the passkey authentication process.
func (s *Server) BeginPasskeyLoginHandler(w http.ResponseWriter, r *http.Request) {
	var req BeginPasskeyLoginRequest
	// Username is optional for discoverable credentials, but helpful if provided
	_ = json.NewDecoder(r.Body).Decode(&req)

	var user *User
	var err error
	if req.Username != "" {
		user, err = s.Store.GetUserByUsername(r.Context(), req.Username)
		if err != nil && err.Error() != "user not found" {
			log.Printf("Error finding user for passkey login: %v", err)
			writeError(w, http.StatusInternalServerError, "Failed to begin passkey login")
			return
		}

		// If user not found, `BeginLogin` will handle it by providing options for discoverable creds.
	}
	if user == nil {
		writeError(w, http.StatusForbidden, "invalid user")
		return
	}

	// Generate WebAuthn authentication options
	// If user is nil, it will generate options for discoverable credentials
	options, ses, err := s.WebAuthn.BeginLogin(user)
	if err != nil {
		log.Printf("Error beginning login: %v", err)
		writeError(w, http.StatusInternalServerError, "Failed to begin passkey login")
		return
	}

	// Store the session data (challenge)
	// Use a temporary unique ID for the session challenge, not directly userID for login.
	sessionID := uuid.New().String()
	s.setChallenge(sessionID, ses)
	log.Printf("Begin passkey login. Challenge stored with session ID: %s", sessionID)

	// Attach session ID to the response headers/body for the client to use in finish step
	w.Header().Set("X-WebAuthn-Session-ID", sessionID)
	writeJSON(w, http.StatusOK, options)
}

// FinishPasskeyLoginHandler finalizes the passkey authentication.
func (s *Server) FinishPasskeyLoginHandler(w http.ResponseWriter, r *http.Request) {
	sessionID := r.Header.Get("X-WebAuthn-Session-ID") // Get session ID from client
	if sessionID == "" {
		writeError(w, http.StatusBadRequest, "WebAuthn session ID missing from header")
		return
	}

	// Retrieve stored challenge
	ses := s.getChallenge(sessionID)
	if ses == nil {
		writeError(w, http.StatusBadRequest, "No active passkey login challenge found or session expired")
		return
	}
	// Clear the challenge immediately after retrieval
	delete(s.challengeStore, sessionID)
	if s.redis != nil {
		s.redis.Del(context.Background(), "webauth-"+sessionID)
	}
	// Get the credential from the database based on the ID in the response
	_, user, err := s.Store.GetPasskeyByCredentialID(r.Context(), ses.AllowedCredentialIDs[0])
	if err != nil {
		log.Printf("Error getting passkey by ID: %v", err)
		writeError(w, http.StatusUnauthorized, "Invalid passkey or user not found")
		return
	}
	credential, err := s.WebAuthn.FinishLogin(user, *ses, r)
	if err != nil {
		slog.Error("Error finishing login", "err", err, "ses", ses, "user", user)
		writeError(w, http.StatusInternalServerError, "Failed to finish passkey login")
		return
	}

	// Update the sign count for the credential in the database
	err = s.Store.UpdatePasskey(r.Context(), user.UserID(), *credential)
	if err != nil {
		log.Printf("Error updating passkey sign count: %v", err)
		// This is not a fatal error for login, but log it.
	}

	// Set session cookie
	sessionData := &session.UserSessionData{
		UserID:    user.UserID(),
		Roles:     user.Roles,
		SignedIn:  true,
		ExpiresAt: time.Now().Add(time.Hour * 24 * 7).Unix(),
		Domain:    utils.GetDomain(r),
	}
	if err := session.SetSessionCookie(w, sessionData, s.SessionSecret); err != nil {
		log.Printf("Error setting session cookie: %v", err)
		writeError(w, http.StatusInternalServerError, "Failed to set session")
		return
	}

	log.Printf("User %s logged in via passkey. Credential ID: %x", user.Username, credential.ID)
	writeJSON(w, http.StatusOK, map[string]string{"message": "Logged in successfully via passkey", "userId": user.UserID(), "username": user.Username})
}

// DeletePasskeyRequest represents the request to delete a passkey.
type DeletePasskeyRequest struct {
	CredentialID string `json:"credentialId"` // Base64 URL-encoded credential ID
}

// DeletePasskeyHandler removes a specific passkey for the authenticated user.
func (s *Server) DeletePasskeyHandler(w http.ResponseWriter, r *http.Request) {
	user, err := GetUserFromContext(r.Context())
	if err != nil {
		writeError(w, http.StatusUnauthorized, "Authentication required to delete passkey")
		return
	}

	var req DeletePasskeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.CredentialID == "" {
		writeError(w, http.StatusBadRequest, "Credential ID is required")
		return
	}

	credentialIDBytes, err := base64.URLEncoding.DecodeString(req.CredentialID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid credential ID format")
		return
	}

	// Check if the user actually owns this passkey (optional but good practice)
	found := false
	for _, pk := range user.WebAuthnCredentials() {
		if hmac.Equal(pk.ID, credentialIDBytes) {
			found = true
			break
		}
	}
	if !found {
		writeError(w, http.StatusForbidden, "You do not own this passkey or it does not exist for your account")
		return
	}

	err = s.Store.DeletePasskey(r.Context(), user.UserID(), credentialIDBytes)
	if err != nil {
		log.Printf("Error deleting passkey for user %s, credential %x: %v", user.Username, credentialIDBytes, err)
		writeError(w, http.StatusInternalServerError, "Failed to delete passkey")
		return
	}

	log.Printf("Passkey %x deleted for user %s", credentialIDBytes, user.Username)
	writeJSON(w, http.StatusOK, map[string]string{"message": "Passkey deleted successfully"})
}

// =============================================================================
// TOTP 2FA Handlers
// =============================================================================

// GenerateTOTPResponse represents the response for generating TOTP setup.
type GenerateTOTPResponse struct {
	Secret   string `json:"secret"`
	ImageURL string `json:"imageUrl"` // QR code image URL (Google Charts API)
}

// GenerateTOTPSecretHandler generates a new TOTP secret for the authenticated user.
// The user then scans the QR code with an authenticator app.
func (s *Server) GenerateTOTPSecretHandler(w http.ResponseWriter, r *http.Request) {
	user, err := GetUserFromContext(r.Context())
	if err != nil {
		writeError(w, http.StatusUnauthorized, "Authentication required to generate TOTP secret")
		return
	}

	// If TOTP is already enabled, return an error or prompt to disable first
	if user.TOTPEnabled && user.TOTPSecret != "" {
		writeError(w, http.StatusBadRequest, "TOTP is already enabled for this account. Disable it first to generate a new secret.")
		return
	}

	// Generate a new TOTP secret key
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      s.RPName,
		AccountName: user.Username,
	})
	if err != nil {
		log.Printf("Error generating TOTP key for user %s: %v", user.Username, err)
		writeError(w, http.StatusInternalServerError, "Failed to generate TOTP secret")
		return
	}

	// Store the secret (temporarily, or mark as unverified) in the user's document.
	// We update the user with the new secret but keep TOTPEnabled as false.
	user.TOTPSecret = key.Secret()
	err = s.Store.UpdateUser(r.Context(), user)
	if err != nil {
		log.Printf("Error storing TOTP secret for user %s: %v", user.Username, err)
		writeError(w, http.StatusInternalServerError, "Failed to store TOTP secret")
		return
	}

	log.Printf("TOTP secret generated for user %s. QR URL: %s", user.Username, key.URL())
	writeJSON(w, http.StatusOK, GenerateTOTPResponse{
		Secret:   key.Secret(), // Return the secret to the client (client shouldn't store it long-term)
		ImageURL: key.URL(),
	})
}

func (s *Server) QRCode(w http.ResponseWriter, r *http.Request) {
	c, err := colorconv.HexToColor("#69676e")
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid qrcode")
		return
	}
	list := []standard.ImageOption{
		standard.WithFgColor(c),
		standard.WithLogoSizeMultiplier(2),
		standard.WithQRWidth(24),
		standard.WithBorderWidth(20),
	}

	// Parse the URL
	parsedURL, err := url.Parse(r.URL.Query().Get("u"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "Invalid URL")
		return
	}
	p := uuid.New().String() + ".png"
	err = CreateQRCode(r.Context(), parsedURL.String(), p,
		list...,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to generate QRCode")
		return
	}
	defer func() {
		_ = os.Remove(p)
	}()

	http.ServeFile(w, r, p)
}

func CreateQRCode(ctx context.Context, qrUrl string, downloadPath string, imgOptions ...standard.ImageOption) error {
	endpoint, err := url.Parse(qrUrl)
	if err != nil {
		return err
	}
	ep := endpoint.String()
	qrCode, err := qrcode.NewWith(ep,
		qrcode.WithEncodingMode(qrcode.EncModeByte),
		qrcode.WithErrorCorrectionLevel(qrcode.ErrorCorrectionQuart),
	)
	if err != nil {
		return err
	}

	w, err := standard.New(path.Base(downloadPath), imgOptions...)
	if err != nil {
		return fmt.Errorf("failled adding asset to qr: %w", err)
	}
	err = qrCode.Save(w)
	if err != nil {
		return fmt.Errorf("failled saving qr code: %w", err)
	}

	return nil
}

// VerifyTOTPRequest represents the request body for verifying a TOTP code.
type VerifyTOTPRequest struct {
	TOTPCode string `json:"totpCode"`
}

// VerifyAndEnableTOTPHandler verifies the TOTP code and enables 2FA for the user.
func (s *Server) VerifyAndEnableTOTPHandler(w http.ResponseWriter, r *http.Request) {
	user, err := GetUserFromContext(r.Context())
	if err != nil {
		writeError(w, http.StatusUnauthorized, "Authentication required to verify TOTP")
		return
	}

	var req VerifyTOTPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.TOTPCode == "" {
		writeError(w, http.StatusBadRequest, "TOTP code is required")
		return
	}

	if user.TOTPSecret == "" {
		writeError(w, http.StatusBadRequest, "No TOTP secret found. Generate one first.")
		return
	}
	if user.TOTPEnabled {
		writeError(w, http.StatusBadRequest, "TOTP is already enabled for this account.")
		return
	}

	// Validate the TOTP code against the stored secret
	valid := totp.Validate(req.TOTPCode, user.TOTPSecret)
	if !valid {
		log.Printf("Invalid TOTP code during verification for user %s", user.Username)
		writeError(w, http.StatusUnauthorized, "Invalid TOTP code")
		return
	}

	// If valid, enable TOTP for the user
	user.TOTPEnabled = true
	err = s.Store.UpdateUser(r.Context(), user)
	if err != nil {
		log.Printf("Error enabling TOTP for user %s: %v", user.Username, err)
		writeError(w, http.StatusInternalServerError, "Failed to enable TOTP")
		return
	}

	log.Printf("TOTP successfully enabled for user %s", user.Username)
	writeJSON(w, http.StatusOK, map[string]string{"message": "TOTP successfully enabled"})
}

// DisableTOTPHandler disables TOTP 2FA for the authenticated user.
func (s *Server) DisableTOTPHandler(w http.ResponseWriter, r *http.Request) {
	user, err := GetUserFromContext(r.Context())
	if err != nil {
		writeError(w, http.StatusUnauthorized, "Authentication required to disable TOTP")
		return
	}

	if !user.TOTPEnabled {
		writeError(w, http.StatusBadRequest, "TOTP is not currently enabled for this account.")
		return
	}

	// Disable TOTP and clear the secret
	user.TOTPEnabled = false
	user.TOTPSecret = "" // Clear the secret for security
	err = s.Store.UpdateUser(r.Context(), user)
	if err != nil {
		log.Printf("Error disabling TOTP for user %s: %v", user.Username, err)
		writeError(w, http.StatusInternalServerError, "Failed to disable TOTP")
		return
	}

	log.Printf("TOTP successfully disabled for user %s", user.Username)
	writeJSON(w, http.StatusOK, map[string]string{"message": "TOTP successfully disabled"})
}

//// =============================================================================
//// Main function and setup
//// =============================================================================
//
//func main() {
//	// Load environment variables
//	mongoURI := os.Getenv("MONGO_URI")
//	if mongoURI == "" {
//		mongoURI = "mongodb://localhost:27017"
//		log.Println("MONGO_URI not set, using default:", mongoURI)
//	}
//
//	sessionSecretStr := os.Getenv("SESSION_SECRET")
//	if sessionSecretStr == "" {
//		log.Fatal("SESSION_SECRET environment variable is required")
//	}
//	sessionSecret := []byte(sessionSecretStr)
//
//	// WebAuthn configuration (adjust these for your deployment)
//	rpID := os.Getenv("WEBAUTHN_RP_ID") // e.g., "localhost" or "your-domain.com"
//	if rpID == "" {
//		rpID = "localhost"
//		log.Println("WEBAUTHN_RP_ID not set, using default:", rpID)
//	}
//	rpDisplayName := os.Getenv("WEBAUTHN_RP_DISPLAY_NAME") // e.g., "My Secure App"
//	if rpDisplayName == "" {
//		rpDisplayName = "My Go User Server"
//		log.Println("WEBAUTHN_RP_DISPLAY_NAME not set, using default:", rpDisplayName)
//	}
//	rpOrigin := os.Getenv("WEBAUTHN_RP_ORIGIN") // e.g., "http://localhost:8080" or "https://your-domain.com"
//	if rpOrigin == "" {
//		rpOrigin = "http://localhost:8080" // Adjust based on your client's origin
//		log.Println("WEBAUTHN_RP_ORIGIN not set, using default:", rpOrigin)
//	}
//
//	// 1. Connect to MongoDB
//	client, err := mongo.Connect(context.Background(), options.Client().ApplyURI(mongoURI))
//	if err != nil {
//		log.Fatalf("Failed to connect to MongoDB: %v", err)
//	}
//	defer func() {
//		if err = client.Disconnect(context.Background()); err != nil {
//			log.Fatal(err)
//		}
//	}()
//
//	// Ping the database to verify connection
//	err = client.Ping(context.Background(), nil)
//	if err != nil {
//		log.Fatalf("Failed to ping MongoDB: %v", err)
//	}
//	log.Println("Connected to MongoDB!")
//
//	// Create a MongoDBStore instance
//	store := NewMongoDBStore(client, "user_db", "users")
//
//	// Create server instance
//	srv, err := NewServer(store, sessionSecret, rpID, rpDisplayName, rpOrigin)
//	if err != nil {
//		log.Fatalf("Failed to create server: %v", err)
//	}
//
//	// Define HTTP routes
//	http.HandleFunc("/register", srv.RegisterHandler)
//	http.HandleFunc("/login/password", srv.LoginPasswordHandler)
//	http.HandleFunc("/login/totp", srv.LoginTOTPHandler) // New TOTP login step
//	http.HandleFunc("/logout", srv.LogoutHandler)
//
//	// Passkey related endpoints (require authentication for registration/deletion)
//	http.HandleFunc("/passkey/register/begin", srv.AuthMiddleware(srv.BeginPasskeyRegistrationHandler))
//	http.HandleFunc("/passkey/register/finish", srv.AuthMiddleware(srv.FinishPasskeyRegistrationHandler))
//	http.HandleFunc("/passkey/login/begin", srv.BeginPasskeyLoginHandler)   // No auth needed for begin login
//	http.HandleFunc("/passkey/login/finish", srv.FinishPasskeyLoginHandler) // No auth needed for finish login
//	http.HandleFunc("/passkey/delete", srv.AuthMiddleware(srv.DeletePasskeyHandler))
//
//	// Authenticated user settings
//	http.HandleFunc("/settings", srv.AuthMiddleware(srv.UserSettingsHandler))
//	// New TOTP settings endpoints
//	http.HandleFunc("/settings/2fa/totp/generate", srv.AuthMiddleware(srv.GenerateTOTPSecretHandler))
//	http.HandleFunc("/settings/2fa/totp/verify-and-enable", srv.AuthMiddleware(srv.VerifyAndEnableTOTPHandler))
//	http.HandleFunc("/settings/2fa/totp/disable", srv.AuthMiddleware(srv.DisableTOTPHandler))
//
//	// Admin-only endpoints
//	http.HandleFunc("/admin/user/delete", srv.AdminMiddleware(srv.DeleteUserHandler))
//	http.HandleFunc("/admin/user/manage", srv.AdminMiddleware(srv.ManageUserHandler))
//
//	// Start the HTTP server
//	port := ":8080"
//	log.Printf("Server starting on port %s", port)
//	log.Fatal(http.ListenAndServe(port, nil))
//}
