package passhash_test

import (
	"bytes"
	"context"
	"fmt"
	"strconv"
	"strings"
)

import (
	"github.com/dhui/passhash"
)

const (
	storeCredentialFormat string = "%d %s %x %x" // Using space as a separator for Sscanf compatibility
)

// StringCredentialStore is an example CredentialStore that stores the Credential as a string
type StringCredentialStore struct {
	StoredCredential string
}

func (store *StringCredentialStore) Store(credential *passhash.Credential) error {
	cfParams, _ := credential.WorkFactor.Marshal()
	cfStrParams := make([]string, 0, len(cfParams))
	for _, param := range cfParams {
		cfStrParams = append(cfStrParams, strconv.Itoa(param))
	}
	cfStore := strings.Join(cfStrParams, ",")
	store.StoredCredential = fmt.Sprintf(storeCredentialFormat, credential.Kdf, cfStore, string(credential.Salt), string(credential.Hash))
	return nil
}

func (store *StringCredentialStore) StoreContext(ctx context.Context, credential *passhash.Credential) error {
	return store.Store(credential)
}

func (store *StringCredentialStore) Load(passhash.UserID) (*passhash.Credential, error) {
	credential := passhash.Credential{}

	var cfStore string
	fmt.Sscanf(store.StoredCredential, storeCredentialFormat, &credential.Kdf, &cfStore, &credential.Salt, &credential.Hash)

	cfStrParams := strings.Split(cfStore, ",")
	cfParams := make([]int, 0, len(cfStrParams))
	for _, paramStr := range cfStrParams {
		i, err := strconv.Atoi(paramStr)
		if err != nil {
			return nil, err
		}
		cfParams = append(cfParams, i)
	}

	wf, err := passhash.NewWorkFactorForKdf(credential.Kdf)
	if err != nil {
		return nil, err
	}
	if err := wf.Unmarshal(cfParams); err != nil {
		return nil, err
	}
	credential.WorkFactor = wf

	return &credential, nil
}

func (store *StringCredentialStore) LoadContext(ctx context.Context, userID passhash.UserID) (*passhash.Credential,
	error) {
	return store.Load(userID)
}

// nolint: dupl
func ExampleCredentialStore() {
	userID := passhash.UserID(0)
	password := "insecurepassword"
	origCredential, err := passhash.NewCredential(userID, password)
	if err != nil {
		fmt.Println("Error creating credential.", err)
		return
	}

	store := StringCredentialStore{}
	if err := store.Store(origCredential); err != nil {
		fmt.Println("Error storing credential.", err)
		return
	}
	newCredential, err := store.Load(userID)
	if err != nil {
		fmt.Println("Error loading credential.", err)
		return
	}

	credentialEqual := newCredential == origCredential
	kdfEqual := newCredential.Kdf == origCredential.Kdf
	cfEqual := newCredential.WorkFactor == origCredential.WorkFactor // Not equal due to pointer comparison
	saltEqual := bytes.Equal(newCredential.Salt, origCredential.Salt)
	hashEqual := bytes.Equal(newCredential.Hash, origCredential.Hash)
	matched, updated := newCredential.MatchesPassword(password)
	fmt.Println("credentialEqual:", credentialEqual)
	fmt.Println("kdfEqual:", kdfEqual)
	fmt.Println("cfEqual:", cfEqual)
	fmt.Println("saltEqual:", saltEqual)
	fmt.Println("hashEqual:", hashEqual)
	fmt.Println("newCredential.MatchesPassword (matched):", matched)
	fmt.Println("newCredential.MatchesPassword (updated):", updated)

	// Output:
	// credentialEqual: false
	// kdfEqual: true
	// cfEqual: false
	// saltEqual: true
	// hashEqual: true
	// newCredential.MatchesPassword (matched): true
	// newCredential.MatchesPassword (updated): false
}
