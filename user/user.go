package user

import (
	"context"
	"crypto/hmac"
	"errors"
	"fmt"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// =============================================================================
// Database Interface
// =============================================================================

// Store defines the interface for user and passkey storage operations.
// This allows for different database backends (e.g., MongoDB, PostgreSQL, Redis).
type Store interface {
	// Users
	GetUserByID(ctx context.Context, userID string) (*User, error)
	GetUserByUsername(ctx context.Context, username string) (*User, error)
	CreateUser(ctx context.Context, user *User) error
	UpdateUser(ctx context.Context, user *User) error
	DeleteUser(ctx context.Context, userID string) error

	// Passkeys (Credentials)
	AddPasskey(ctx context.Context, userID string, credential webauthn.Credential) error
	GetPasskeysByUserID(ctx context.Context, userID string) ([]webauthn.Credential, error)
	GetPasskeyByCredentialID(ctx context.Context, credentialID []byte) (*webauthn.Credential, *User, error)
	UpdatePasskey(ctx context.Context, userID string, credential webauthn.Credential) error
	DeletePasskey(ctx context.Context, userID string, credentialID []byte) error
}

// =============================================================================
// MongoDB Implementation of Store
// =============================================================================

// MongoDBStore implements the Store interface using MongoDB.
type MongoDBStore struct {
	usersCollection *mongo.Collection
	// No separate collection for passkeys; they are embedded in the User document.
}

// NewMongoDBStore creates a new MongoDBStore instance.
func NewMongoDBStore(client *mongo.Client, dbName, usersCollectionName string) *MongoDBStore {
	db := client.Database(dbName)
	return &MongoDBStore{
		usersCollection: db.Collection(usersCollectionName),
	}
}

// GetUserByID retrieves a user by their ID.
func (m *MongoDBStore) GetUserByID(ctx context.Context, userID string) (*User, error) {
	var user User
	err := m.usersCollection.FindOne(ctx, bson.M{"id": userID}).Decode(&user)
	if err == mongo.ErrNoDocuments {
		return nil, errors.New("user not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user by ID: %w", err)
	}
	return &user, nil
}

// GetUserByUsername retrieves a user by their username.
func (m *MongoDBStore) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	var user User
	err := m.usersCollection.FindOne(ctx, bson.M{"username": username}).Decode(&user)
	if err == mongo.ErrNoDocuments {
		return nil, errors.New("user not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user by username: %w", err)
	}
	return &user, nil
}

// CreateUser creates a new user in the database.
func (m *MongoDBStore) CreateUser(ctx context.Context, user *User) error {
	user.ID = uuid.New().String() // Generate new ObjectID for the user
	_, err := m.usersCollection.InsertOne(ctx, user)
	if mongo.IsDuplicateKeyError(err) { // Check for duplicate key error
		return errors.New("user with this username already exists")
	}
	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}
	return nil
}

// UpdateUser updates an existing user in the database.
func (m *MongoDBStore) UpdateUser(ctx context.Context, user *User) error {
	_, err := m.usersCollection.ReplaceOne(ctx, bson.M{"id": user.ID}, user)
	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}
	return nil
}

// DeleteUser deletes a user by their ID.
func (m *MongoDBStore) DeleteUser(ctx context.Context, userID string) error {
	res, err := m.usersCollection.DeleteOne(ctx, bson.M{"id": userID})
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}
	if res.DeletedCount == 0 {
		return errors.New("user not found for deletion")
	}
	return nil
}

// AddPasskey adds a new WebAuthn credential (passkey) to a user.
func (m *MongoDBStore) AddPasskey(ctx context.Context, userID string, credential webauthn.Credential) error {
	wrappedCredential := FromWebAuthnCredential(credential)

	// Add the new passkey to the user's Passkeys array
	update := bson.M{
		"$push": bson.M{"passkeys": wrappedCredential},
	}
	_, err := m.usersCollection.UpdateOne(ctx, bson.M{"id": userID}, update)
	if err != nil {
		return fmt.Errorf("failed to add passkey: %w", err)
	}
	return nil
}

// GetPasskeysByUserID retrieves all passkeys for a given user ID.
func (m *MongoDBStore) GetPasskeysByUserID(ctx context.Context, userID string) ([]webauthn.Credential, error) {
	user, err := m.GetUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	return user.WebAuthnCredentials(), nil
}

// GetPasskeyByCredentialID retrieves a specific passkey by its credential ID
// and returns both the credential and the associated user.
func (m *MongoDBStore) GetPasskeyByCredentialID(ctx context.Context, credentialID []byte) (*webauthn.Credential, *User, error) {
	var user User
	// Find a user who has a passkey with the given credentialID
	err := m.usersCollection.FindOne(ctx, bson.M{"passkeys.id": credentialID}).Decode(&user)
	if err == mongo.ErrNoDocuments {
		return nil, nil, errors.New("passkey not found")
	}
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get passkey by credential ID: %w", err)
	}

	// Iterate through the user's passkeys to find the matching one
	for _, pk := range user.Passkeys {
		if hmac.Equal(pk.ID, credentialID) {
			creds := pk.ToWebAuthnCredential()
			return &creds, &user, nil
		}
	}
	return nil, nil, errors.New("passkey not found within user (desync?)")
}

// UpdatePasskey updates an existing passkey's sign count.
func (m *MongoDBStore) UpdatePasskey(ctx context.Context, userID string, credential webauthn.Credential) error {

	// Access the SignCount from the Authenticator field
	signCount := credential.Authenticator.SignCount

	// Update only the signCount for the specific credential ID
	update := bson.M{
		"$set": bson.M{
			"passkeys.$[elem].signCount": signCount,
		},
	}
	arrayFilters := options.ArrayFilters{
		Filters: bson.A{
			bson.M{"elem.id": credential.ID},
		},
	}
	opts := options.Update().SetArrayFilters(arrayFilters)

	_, err := m.usersCollection.UpdateOne(ctx, bson.M{"id": userID}, update, opts)
	if err != nil {
		return fmt.Errorf("failed to update passkey: %w", err)
	}
	return nil
}

// DeletePasskey removes a specific passkey from a user.
func (m *MongoDBStore) DeletePasskey(ctx context.Context, userID string, credentialID []byte) error {
	// Remove the passkey from the user's Passkeys array
	update := bson.M{
		"$pull": bson.M{
			"passkeys": bson.M{"id": credentialID},
		},
	}
	_, err := m.usersCollection.UpdateOne(ctx, bson.M{"id": userID}, update)
	if err != nil {
		return fmt.Errorf("failed to delete passkey: %w", err)
	}
	return nil
}
