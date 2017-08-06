package passhash

import (
	"testing"
)

func TestNewCredential(t *testing.T) {
	userID := UserID(0)
	password := "insecurepassword"
	credential, err := NewCredential(userID, password)
	if err != nil {
		t.Fatalf("Failed to get password credential. Got error %v", err)
	}
	if matched, _ := credential.MatchesPassword(password); !matched {
		t.Errorf("Password did not match Credential")
	}
	if matched, _ := credential.MatchesPassword(password + "extra"); matched {
		t.Errorf("Password matched Credential")
	}
}

func TestNewWorkFactorForKdfPbkdf2Sha256(t *testing.T) {
	wf, err := NewWorkFactorForKdf(Pbkdf2Sha256)
	if err != nil {
		t.Error("Got error getting WorkFactor for Pbkdf2Sha256", err)
	}
	if _, ok := wf.(*Pbkdf2WorkFactor); !ok {
		t.Error("Expected Pbkdf2Sha256 KDF to have a Pbkdf2WorkFactor WorkFactor")
	}
}

func TestNewWorkFactorForKdfPbkdf2Sha512(t *testing.T) {
	wf, err := NewWorkFactorForKdf(Pbkdf2Sha512)
	if err != nil {
		t.Error("Got error getting WorkFactor for Pbkdf2Sha512", err)
	}
	if _, ok := wf.(*Pbkdf2WorkFactor); !ok {
		t.Error("Expected Pbkdf2Sha512 KDF to have a Pbkdf2WorkFactor WorkFactor")
	}
}

func TestNewWorkFactorForKdfPbkdf2Sha3_256(t *testing.T) {
	wf, err := NewWorkFactorForKdf(Pbkdf2Sha3_256)
	if err != nil {
		t.Error("Got error getting WorkFactor for Pbkdf2Sha3_256", err)
	}
	if _, ok := wf.(*Pbkdf2WorkFactor); !ok {
		t.Error("Expected Pbkdf2Sha3_256 KDF to have a Pbkdf2WorkFactor WorkFactor")
	}
}

func TestNewWorkFactorForKdfPbkdf2Sha3_512(t *testing.T) {
	wf, err := NewWorkFactorForKdf(Pbkdf2Sha3_512)
	if err != nil {
		t.Error("Got error getting WorkFactor for Pbkdf2Sha3_512", err)
	}
	if _, ok := wf.(*Pbkdf2WorkFactor); !ok {
		t.Error("Expected Pbkdf2Sha3_512 KDF to have a Pbkdf2WorkFactor WorkFactor")
	}
}

func TestNewWorkFactorForKdfBcrypt(t *testing.T) {
	wf, err := NewWorkFactorForKdf(Bcrypt)
	if err != nil {
		t.Error("Got error getting WorkFactor for Bcrypt", err)
	}
	if _, ok := wf.(*BcryptWorkFactor); !ok {
		t.Error("Expected Bcrypt KDF to have a BcryptWorkFactor WorkFactor")
	}
}

func TestNewWorkFactorForKdfScrypt(t *testing.T) {
	wf, err := NewWorkFactorForKdf(Scrypt)
	if err != nil {
		t.Error("Got error getting WorkFactor for Scrypt", err)
	}
	if _, ok := wf.(*ScryptWorkFactor); !ok {
		t.Error("Expected Scrypt KDF to have a ScryptWorkFactor WorkFactor")
	}
}

func TestNewWorkFactorError(t *testing.T) {
	_, err := NewWorkFactorForKdf(Kdf(999999))
	if err == nil {
		t.Error("Expected error for invalid Kdf")
	}
}

func Example() {
	password := "insecurepassword"
	credential, err := NewCredential(UserID(0), password)
	if err != nil {
		// Handle error gettings credential
	}
	matched, updated := credential.MatchesPassword(password)
	if !matched {
		// Handle invalid password
	}
	if updated {
		// store := SomeStorage() // SomeStorage implements the CredentialStore interface
		// store.Marshal(credential)
	}
	newPassword := "newinsecurepassword"
	updated, err = credential.Reset(password, newPassword)
	if err != nil {
		// Handle PasswordPoliciesNotMet error
	}
	if updated {
		// Update the CredentialStore
	}
}
