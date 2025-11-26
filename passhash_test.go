package passhash_test

import (
	"testing"
)

import (
	"github.com/dhui/passhash"
)

func TestNewCredential(t *testing.T) {
	userID := passhash.UserID(0)
	credential, err := passhash.NewCredential(userID, testPassword)
	if err != nil {
		t.Fatalf("Failed to get password credential. Got error %v", err)
	}
	if matched, _ := credential.MatchesPassword(testPassword); !matched {
		t.Errorf("Password did not match Credential")
	}
	if matched, _ := credential.MatchesPassword(testPassword + "extra"); matched {
		t.Errorf("Password matched Credential")
	}
}

func TestNewWorkFactorForKdfPbkdf2Sha256(t *testing.T) {
	wf, err := passhash.NewWorkFactorForKdf(passhash.Pbkdf2Sha256)
	if err != nil {
		t.Error("Got error getting WorkFactor for Pbkdf2Sha256", err)
	}
	if _, ok := wf.(*passhash.Pbkdf2WorkFactor); !ok {
		t.Error("Expected Pbkdf2Sha256 KDF to have a Pbkdf2WorkFactor WorkFactor")
	}
}

func TestNewWorkFactorForKdfPbkdf2Sha512(t *testing.T) {
	wf, err := passhash.NewWorkFactorForKdf(passhash.Pbkdf2Sha512)
	if err != nil {
		t.Error("Got error getting WorkFactor for Pbkdf2Sha512", err)
	}
	if _, ok := wf.(*passhash.Pbkdf2WorkFactor); !ok {
		t.Error("Expected Pbkdf2Sha512 KDF to have a Pbkdf2WorkFactor WorkFactor")
	}
}

func TestNewWorkFactorForKdfPbkdf2Sha3_256(t *testing.T) {
	wf, err := passhash.NewWorkFactorForKdf(passhash.Pbkdf2Sha3_256)
	if err != nil {
		t.Error("Got error getting WorkFactor for Pbkdf2Sha3_256", err)
	}
	if _, ok := wf.(*passhash.Pbkdf2WorkFactor); !ok {
		t.Error("Expected Pbkdf2Sha3_256 KDF to have a Pbkdf2WorkFactor WorkFactor")
	}
}

func TestNewWorkFactorForKdfPbkdf2Sha3_512(t *testing.T) {
	wf, err := passhash.NewWorkFactorForKdf(passhash.Pbkdf2Sha3_512)
	if err != nil {
		t.Error("Got error getting WorkFactor for Pbkdf2Sha3_512", err)
	}
	if _, ok := wf.(*passhash.Pbkdf2WorkFactor); !ok {
		t.Error("Expected Pbkdf2Sha3_512 KDF to have a Pbkdf2WorkFactor WorkFactor")
	}
}

func TestNewWorkFactorForKdfBcrypt(t *testing.T) {
	wf, err := passhash.NewWorkFactorForKdf(passhash.Bcrypt)
	if err != nil {
		t.Error("Got error getting WorkFactor for Bcrypt", err)
	}
	if _, ok := wf.(*passhash.BcryptWorkFactor); !ok {
		t.Error("Expected Bcrypt KDF to have a BcryptWorkFactor WorkFactor")
	}
}

func TestNewWorkFactorForKdfScrypt(t *testing.T) {
	wf, err := passhash.NewWorkFactorForKdf(passhash.Scrypt)
	if err != nil {
		t.Error("Got error getting WorkFactor for Scrypt", err)
	}
	if _, ok := wf.(*passhash.ScryptWorkFactor); !ok {
		t.Error("Expected Scrypt KDF to have a ScryptWorkFactor WorkFactor")
	}
}

func TestNewWorkFactorForKdfArgon2id(t *testing.T) {
	wf, err := passhash.NewWorkFactorForKdf(passhash.Argon2id)
	if err != nil {
		t.Error("Got error getting WorkFactor for Argon2id", err)
	}
	if _, ok := wf.(*passhash.Argon2WorkFactor); !ok {
		t.Error("Expected Argon2id KDF to have an Argon2WorkFactor WorkFactor")
	}
}

func TestNewWorkFactorError(t *testing.T) {
	_, err := passhash.NewWorkFactorForKdf(passhash.Kdf(999999))
	if err == nil {
		t.Error("Expected error for invalid Kdf")
	}
}

func Example() {
	credential, err := passhash.NewCredential(passhash.UserID(0), testPassword)
	if err != nil {
		// Handle error gettings credential
	}
	matched, updated := credential.MatchesPassword(testPassword)
	if !matched {
		// Handle invalid password
	}
	if updated {
		// store := SomeStorage() // SomeStorage implements the CredentialStore interface
		// store.Marshal(credential)
	}
	newPassword := "newinsecurepassword"
	if err = credential.ChangePassword(testPassword, newPassword); err != nil {
		// Handle PasswordPoliciesNotMet error
	}
	newPassword2 := "newinsecurepassword2"
	if err = credential.Reset(newPassword2); err != nil {
		// Handle PasswordPoliciesNotMet error
	}
}
