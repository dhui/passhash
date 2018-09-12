package passhash

import (
	"testing"
)

type invalidWorkFactor struct {
}

func (wf *invalidWorkFactor) Marshal() ([]int, error) {
	return []int{}, nil
}

func (wf *invalidWorkFactor) Unmarshal(p []int) error {
	return nil
}

func testGetPasswordHashInvalidKdfAndWorkFactorCombo(t *testing.T, kdf Kdf, workFactor WorkFactor) {
	salt := []byte("salt")
	password := "foobar"
	_, err := getPasswordHash(kdf, workFactor, salt, DefaultConfig.KeyLength, password)
	if err == nil {
		t.Errorf("Kdf %v and WorkFactor %T considered valid combo", kdf, workFactor)
	}
}

func TestGetPasswordHashUnsupportedWorkFactor(t *testing.T) {
	testGetPasswordHashInvalidKdfAndWorkFactorCombo(t, Pbkdf2Sha256, &invalidWorkFactor{})
}

func TestGetPasswordHashInvalidPbkdf2WorkFactor(t *testing.T) {
	testGetPasswordHashInvalidKdfAndWorkFactorCombo(t, Pbkdf2Sha256, &ScryptWorkFactor{})
	testGetPasswordHashInvalidKdfAndWorkFactorCombo(t, Pbkdf2Sha256, &BcryptWorkFactor{})
}

func TestGetPasswordHashInvalidBcryptWorkFactor(t *testing.T) {
	testGetPasswordHashInvalidKdfAndWorkFactorCombo(t, Bcrypt, &Pbkdf2WorkFactor{})
	testGetPasswordHashInvalidKdfAndWorkFactorCombo(t, Bcrypt, &ScryptWorkFactor{})
}

func TestGetPasswordHashInvalidScryptWorkFactor(t *testing.T) {
	testGetPasswordHashInvalidKdfAndWorkFactorCombo(t, Scrypt, &Pbkdf2WorkFactor{})
	testGetPasswordHashInvalidKdfAndWorkFactorCombo(t, Scrypt, &BcryptWorkFactor{})
}
