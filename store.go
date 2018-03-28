package passhash

import (
	"context"
	"errors"
)

// CredentialStore is an interfance for customizing Credential storage
type CredentialStore interface {
	Store(*Credential) error
	StoreContext(context.Context, *Credential) error
	Load(UserID) (*Credential, error)
	LoadContext(context.Context, UserID) (*Credential, error)
}

// DummyCredentialStore is a dummy CredentialStore that doesn't do anything
type DummyCredentialStore struct{}

// Store doesn't store anything
func (d DummyCredentialStore) Store(*Credential) error { return nil }

// StoreContext doesn't store anything
func (d DummyCredentialStore) StoreContext(context.Context, *Credential) error { return nil }

// Load only returns errors
func (d DummyCredentialStore) Load(UserID) (*Credential, error) {
	return nil, errors.New("DummyCredentialStore does not support loading credentials")
}

// LoadContext only returns errors
func (d DummyCredentialStore) LoadContext(context.Context, UserID) (*Credential, error) {
	return nil, errors.New("DummyCredentialStore does not support loading credentials")
}
