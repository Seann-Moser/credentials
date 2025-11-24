package user

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/Seann-Moser/credentials/session"
	"github.com/Seann-Moser/credentials/utils"
	"github.com/Seann-Moser/rbac"
	"golang.org/x/crypto/bcrypt"
)

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
		err = s.rbac.AssignRoleToUser(r.Context(), user.ID, role.ID)
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
