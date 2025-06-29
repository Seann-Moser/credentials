package user

import (
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	//"github.com/go-webauthn/webauthn/webauthnweb" // For helper functions like DecodeCredentialCreationResponseBody
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// =============================================================================
// Core Data Structures
// =============================================================================

// WebAuthnCredential is a BSON-friendly wrapper for webauthn.Credential.
// It converts AuthenticatorTransport to string for storage in MongoDB.
type WebAuthnCredential struct {
	ID              []byte   `bson:"id" json:"id"`
	PublicKey       []byte   `bson:"publicKey" json:"publicKey"`
	AttestationType string   `bson:"attestationType" json:"attestationType"`
	AAGUID          []byte   `bson:"aaguid" json:"aaguid"`
	SignCount       uint32   `bson:"signCount" json:"signCount"`
	Transports      []string `bson:"transports,omitempty" json:"transports,omitempty"` // Store as string slice
}

// ToWebAuthnCredential converts WebAuthnCredential to webauthn.Credential.
// ToWebAuthnCredential converts WebAuthnCredential to webauthn.Credential.
func (wc *WebAuthnCredential) ToWebAuthnCredential() webauthn.Credential {
	// Convert []string to []webauthn.AuthenticatorTransport
	transports := make([]protocol.AuthenticatorTransport, len(wc.Transports))
	for i, t := range wc.Transports {
		transports[i] = protocol.AuthenticatorTransport(t)
	}

	return webauthn.Credential{
		ID:              wc.ID,
		PublicKey:       wc.PublicKey,
		AttestationType: wc.AttestationType,
		Transport:       transports,
		Flags:           webauthn.CredentialFlags{},
		Authenticator: webauthn.Authenticator{
			AAGUID:       wc.AAGUID,
			SignCount:    wc.SignCount,
			CloneWarning: false,
			Attachment:   "",
		},
		Attestation: webauthn.CredentialAttestation{
			ClientDataJSON:     nil,
			ClientDataHash:     nil,
			AuthenticatorData:  nil,
			PublicKeyAlgorithm: 0,
			Object:             nil,
		},
	}
}

// FromWebAuthnCredential converts webauthn.Credential to WebAuthnCredential.
// FromWebAuthnCredential converts webauthn.Credential to WebAuthnCredential.
func FromWebAuthnCredential(wc webauthn.Credential) WebAuthnCredential {
	// Convert []webauthn.AuthenticatorTransport to []string
	transports := make([]string, len(wc.Transport))
	for i, t := range wc.Transport {
		transports[i] = string(t)
	}

	return WebAuthnCredential{
		ID:              wc.ID,
		PublicKey:       wc.PublicKey,
		AttestationType: wc.AttestationType,
		AAGUID:          wc.Authenticator.AAGUID,
		SignCount:       wc.Authenticator.SignCount, // Correctly get SignCount
		Transports:      transports,
	}
}

var _ webauthn.User = &User{}

// User represents a user account in the system.
type User struct {
	ID           primitive.ObjectID     `bson:"_id,omitempty" json:"id"`
	Username     string                 `bson:"username" json:"username"`
	PasswordHash []byte                 `bson:"password_hash,omitempty" json:"-"` // Omit from JSON response
	Roles        []string               `bson:"roles" json:"roles"`
	Passkeys     []WebAuthnCredential   `bson:"passkeys" json:"passkeys"`       // Use the BSON-friendly wrapper
	TOTPSecret   string                 `bson:"totp_secret,omitempty" json:"-"` // Base32 encoded secret, omit from JSON
	TOTPEnabled  bool                   `bson:"totp_enabled" json:"totp_enabled"`
	Settings     map[string]interface{} `bson:"settings,omitempty" json:"settings,omitempty"`
}

func (u *User) WebAuthnID() []byte {
	return []byte(u.ID.String())
}

func (u *User) WebAuthnName() string {
	return u.Username
}

func (u *User) WebAuthnDisplayName() string {
	return u.Username
}

func (u *User) WebAuthnCredentials() []webauthn.Credential {
	creds := make([]webauthn.Credential, len(u.Passkeys))
	for i, pc := range u.Passkeys {
		creds[i] = pc.ToWebAuthnCredential()
	}
	return creds
}

// UserID is a helper to get the string representation of the User's ID.
func (u *User) UserID() string {
	return u.ID.Hex()
}
