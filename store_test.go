package passhash_test

import (
	"context"
	"testing"
)

import (
	"github.com/dhui/passhash"
)

func TestDummyCredentialStoreStore(t *testing.T) {
	store := passhash.DummyCredentialStore{}
	credential := &passhash.Credential{}
	if err := store.Store(credential); err != nil {
		t.Error("Got error storing credential.", err)
	}
}

func TestDummyCredentialStoreStoreContext(t *testing.T) {
	store := passhash.DummyCredentialStore{}
	credential := &passhash.Credential{}
	if err := store.StoreContext(context.Background(), credential); err != nil {
		t.Error("Got error storing credential.", err)
	}
}

func TestDummyCredentialStoreLoad(t *testing.T) {
	store := passhash.DummyCredentialStore{}
	userID := passhash.UserID(0)
	credential, err := store.Load(userID)
	if err == nil {
		t.Error("Got error loading credential.", err)
	}
	if credential != nil {
		t.Error("DummyCredentialStore provided credential.", credential)
	}
}

func TestDummyCredentialStoreLoadContext(t *testing.T) {
	store := passhash.DummyCredentialStore{}
	userID := passhash.UserID(0)
	credential, err := store.LoadContext(context.Background(), userID)
	if err == nil {
		t.Error("Got error loading credential.", err)
	}
	if credential != nil {
		t.Error("DummyCredentialStore provided credential.", credential)
	}
}
