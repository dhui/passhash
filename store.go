package passhash

import (
	"fmt"
)

// CredentialStore is an interfance for customizing Credential storage
type CredentialStore interface {
	Store(*Credential) error
	Load(UserID) (*Credential, error)
}

// DummyCredentialStore is a dummy CredentialStore that doesn't do anything
type DummyCredentialStore struct{}

// Store doesn't store anything
func (d DummyCredentialStore) Store(*Credential) error { return nil }

// Load only returns errors
func (d DummyCredentialStore) Load(UserID) (*Credential, error) {
	return nil, fmt.Errorf("DummyCredentialStore does not support loading credentials")
}
