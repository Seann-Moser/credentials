package user

import (
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
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
	Transports      []string `bson:"transports,omitempty" json:"transports,omitempty"`
	// Store the raw byte for CredentialFlags directly.
	// This byte contains UserPresent, UserVerified, BackupEligible, BackupState flags.
	CredentialFlagsByte byte `bson:"credentialFlagsByte"`
}

// ToWebAuthnCredential converts WebAuthnCredential to webauthn.Credential.
// This is crucial for correctly reconstructing the webauthn.Credential
// for validation by the go-webauthn library, correctly using the raw byte flags.
func (wc *WebAuthnCredential) ToWebAuthnCredential() webauthn.Credential {
	// Convert []string to []protocol.AuthenticatorTransport
	transports := make([]protocol.AuthenticatorTransport, len(wc.Transports))
	for i, t := range wc.Transports {
		transports[i] = protocol.AuthenticatorTransport(t)
	}

	// Reconstruct the protocol.AuthenticatorFlags from the stored byte.
	// We're casting our stored byte back to protocol.AuthenticatorFlags to use its Has...() methods.
	authenticatorFlags := protocol.AuthenticatorFlags(wc.CredentialFlagsByte)

	return webauthn.Credential{
		ID:              wc.ID,
		PublicKey:       wc.PublicKey,
		AttestationType: wc.AttestationType,
		Transport:       transports,
		// Populate the top-level Flags field using the helper.
		Flags: webauthn.NewCredentialFlags(authenticatorFlags), // <--- Correctly populates Flags
		Authenticator: webauthn.Authenticator{
			AAGUID:       wc.AAGUID,
			SignCount:    wc.SignCount,
			CloneWarning: false, // These are usually managed by the library
			Attachment:   "",    // These are usually managed by the library
			// IMPORTANT: In your Authenticator struct, there is no 'Flags' field.
			// So, we do NOT set Authenticator.Flags here.
		},
		Attestation: webauthn.CredentialAttestation{}, // Can be left empty for login
	}
}

// FromWebAuthnCredential converts webauthn.Credential to WebAuthnCredential.
// This is used when storing a new credential after successful registration,
// extracting the raw byte for CredentialFlags.
func FromWebAuthnCredential(wc webauthn.Credential) WebAuthnCredential {
	// Convert []protocol.AuthenticatorTransport to []string
	transports := make([]string, len(wc.Transport))
	for i, t := range wc.Transport {
		transports[i] = string(t)
	}

	return WebAuthnCredential{
		ID:              wc.ID,
		PublicKey:       wc.PublicKey,
		AttestationType: wc.AttestationType,
		AAGUID:          wc.Authenticator.AAGUID,
		SignCount:       wc.Authenticator.SignCount,
		Transports:      transports,
		// Store the raw byte of the top-level Credential.Flags.
		CredentialFlagsByte: byte(wc.Flags.ProtocolValue()), // <--- CRITICAL: Store the raw byte from Credential.Flags
	}
}

var _ webauthn.User = &User{}

// User represents a user account in the system.
type User struct {
	ID           primitive.ObjectID     `bson:"_id,omitempty" json:"id"`
	Username     string                 `bson:"username" json:"username"`
	PasswordHash []byte                 `bson:"password_hash,omitempty" json:"-"`
	Roles        []string               `bson:"roles" json:"roles"`
	Passkeys     []WebAuthnCredential   `bson:"passkeys" json:"passkeys"`
	TOTPSecret   string                 `bson:"totp_secret,omitempty" json:"-"`
	TOTPEnabled  bool                   `bson:"totp_enabled" json:"totp_enabled"`
	Settings     map[string]interface{} `bson:"settings,omitempty" json:"settings,omitempty"`
}

func (u *User) WebAuthnID() []byte {
	return []byte(u.ID.String()) // Corrected to use raw bytes
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

func (u *User) UserID() string {
	return u.ID.Hex()
}
