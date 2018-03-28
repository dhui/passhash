package passhash

import (
	_ "crypto/sha256"
	_ "crypto/sha512"
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

func testNew(t *testing.T, kdf Kdf) {
	userID := UserID(0)
	password := "foobar"
	config := Config{Kdf: kdf, WorkFactor: DefaultWorkFactor[kdf], SaltSize: 16, KeyLength: 32, AuditLogger: &DummyAuditLogger{}, Store: DummyCredentialStore{}}
	credential, err := config.NewCredential(userID, password)
	if err != nil {
		t.Errorf("Failed to get password credential for Kdf %v. Got error %v", kdf, err)
	}
	if matched, _ := credential.MatchesPassword(password); !matched {
		t.Errorf("Password did not match Credential for Kdf: %v", kdf)
	}
	if matched, _ := credential.MatchesPassword(password + "extra"); matched {
		t.Errorf("Password matched Credential for Kdf: %v", kdf)
	}
}

func TestNewPbkdf2Sha256(t *testing.T) {
	testNew(t, Pbkdf2Sha256)
}

func TestNewPbkdf2Sha512(t *testing.T) {
	testNew(t, Pbkdf2Sha512)
}

func TestNewPbkdf2Sha3_256(t *testing.T) {
	testNew(t, Pbkdf2Sha3_256)
}

func TestNewPbkdf2Sha3_512(t *testing.T) {
	testNew(t, Pbkdf2Sha3_512)
}

func TestNewBcrypt(t *testing.T) {
	testNew(t, Bcrypt)
}

func TestNewScrypt(t *testing.T) {
	testNew(t, Scrypt)
}

func TestNewInvalidKdf(t *testing.T) {
	userID := UserID(0)
	password := "foobar"
	config := Config{Kdf: Kdf(999999), WorkFactor: &Pbkdf2WorkFactor{}}
	_, err := config.NewCredential(userID, password)
	if err == nil {
		t.Error("Able to generate a Credential with invalid Kdf")
	}
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

func TestMatchesPasswordError(t *testing.T) {
	invalidCredential := Credential{}
	if matched, _ := invalidCredential.MatchesPassword("password"); matched {
		t.Error("Invalid Credential validates incorrect passwords")
	}
}

func TestNeedsUpdate(t *testing.T) {
	origKdf := Pbkdf2Sha256
	origWorkFactor := DefaultWorkFactor[origKdf]
	if origKdf == DefaultConfig.Kdf {
		t.Errorf("Original credential is already the safe recommended Kdf. %v != %v", origKdf, DefaultConfig.Kdf)
	}
	if origWorkFactor == DefaultWorkFactor[DefaultConfig.Kdf] {
		t.Errorf("Original credential WorkFactor are already the safe recommended Kdf WorkFactor. %v != %v", origWorkFactor, DefaultWorkFactor[DefaultConfig.Kdf])
	}

	config := Config{Kdf: origKdf, WorkFactor: origWorkFactor}
	userID := UserID(0)
	password := "insecurepassword"
	credential, err := config.NewCredential(userID, password)
	if err != nil {
		t.Error("Unable to create new Credential")
	}
	if !credential.NeedsUpdate() {
		t.Error("Outdated config should need an update")
	}
}

func TestMeetsConfigSelf(t *testing.T) {
	config := Config{Kdf: Scrypt, WorkFactor: &ScryptWorkFactor{R: 1, P: 2, N: 2}}
	userID := UserID(0)
	password := "insecurepassword"
	credential, err := config.NewCredential(userID, password)
	if err != nil {
		t.Error("Unable to create new Credential")
	}
	if !credential.MeetsConfig(config) {
		t.Error("Config doesn't meet with credential it created")
	}
}

func TestMeetsConfigSame(t *testing.T) {
	configA := Config{Kdf: Scrypt, WorkFactor: &ScryptWorkFactor{R: 1, P: 2, N: 2}}
	configB := Config{Kdf: Scrypt, WorkFactor: &ScryptWorkFactor{R: 1, P: 2, N: 2}}
	userID := UserID(0)
	password := "insecurepassword"
	credential, err := configA.NewCredential(userID, password)
	if err != nil {
		t.Error("Unable to create new Credential")
	}
	if !credential.MeetsConfig(configB) {
		t.Error("Same configs do are not compared equal")
	}
}

func TestMeetsConfigDifferentKdf(t *testing.T) {
	configA := Config{Kdf: Scrypt, WorkFactor: &ScryptWorkFactor{R: 1, P: 2, N: 2}}
	configB := Config{Kdf: Bcrypt, WorkFactor: &BcryptWorkFactor{Cost: 5}}
	userID := UserID(0)
	password := "insecurepassword"
	credential, err := configA.NewCredential(userID, password)
	if err != nil {
		t.Error("Unable to create new Credential")
	}
	if credential.MeetsConfig(configB) {
		t.Error("Configs with different Kdfs considered the same")
	}
}

func TestMeetsConfigDifferentWorkFactor(t *testing.T) {
	configA := Config{Kdf: Scrypt, WorkFactor: &ScryptWorkFactor{R: 1, P: 2, N: 2}}
	configB := Config{Kdf: Scrypt, WorkFactor: &ScryptWorkFactor{R: 1, P: 2, N: 4}}
	userID := UserID(0)
	password := "insecurepassword"
	credential, err := configA.NewCredential(userID, password)
	if err != nil {
		t.Error("Unable to create new Credential")
	}
	if credential.MeetsConfig(configB) {
		t.Error("Configs with different Kdfs considered the same")
	}
}

func TestMatchesPasswordWithIP(t *testing.T) {
	userID := UserID(0)
	password := "insecurepassword"
	credential, err := DefaultConfig.NewCredential(userID, password)
	if err != nil {
		t.Error("Unable to create new Credential")
	}
	matched, updated := credential.MatchesPasswordWithIP(password, emptyIP)
	if !matched {
		t.Error("Password did not match")
	}
	if updated {
		t.Error("Credential updated")
	}
}

func TestMatchesPasswordMatchNoUpdate(t *testing.T) {
	origKdf := Scrypt
	origWorkFactor := DefaultWorkFactor[origKdf]
	if origKdf != DefaultConfig.Kdf {
		t.Errorf("Original credential is not the safe recommended Kdf. %v != %v", origKdf, DefaultConfig.Kdf)
	}
	if origWorkFactor != DefaultWorkFactor[DefaultConfig.Kdf] {
		t.Errorf("Original credential WorkFactor is not the safe recommended Kdf WorkFactor. %v != %v", origWorkFactor, DefaultWorkFactor[DefaultConfig.Kdf])
	}

	config := Config{Kdf: origKdf, WorkFactor: origWorkFactor}
	userID := UserID(0)
	password := "insecurepassword"
	credential, err := config.NewCredential(userID, password)
	if err != nil {
		t.Error("Unable to create new Credential")
	}
	if credential.Kdf != origKdf {
		t.Errorf("Original credential Kdf changed. %v != %v", credential.Kdf, origKdf)
	}
	if credential.WorkFactor != origWorkFactor {
		t.Errorf("Original credential WorkFactor changed. %v != %v", credential.WorkFactor, origWorkFactor)
	}

	matched, updated := credential.MatchesPassword(password)
	if !matched {
		t.Error("Valid password did not match credential")
	}
	if updated {
		t.Error("Up-to-date credentials updated")
	}
	if credential.Kdf != DefaultConfig.Kdf {
		t.Errorf("Credential Kdf unexpectedly updated from safe recommended Kdf. %v != %v", credential.Kdf, DefaultConfig.Kdf)
	}
	if credential.WorkFactor != DefaultWorkFactor[DefaultConfig.Kdf] {
		t.Errorf("Credential WorkFactor unexpected updated from safe recommended Kdf WorkFactor. %v != %v", credential.WorkFactor, DefaultWorkFactor[DefaultConfig.Kdf])
	}
}

func TestMatchesPasswordUpdateKdfAndWorkFactor(t *testing.T) {
	origKdf := Pbkdf2Sha256
	origWorkFactor := DefaultWorkFactor[origKdf]
	if origKdf == DefaultConfig.Kdf {
		t.Errorf("Original credential is already the safe recommended Kdf. %v != %v", origKdf, DefaultConfig.Kdf)
	}
	if origWorkFactor == DefaultWorkFactor[DefaultConfig.Kdf] {
		t.Errorf("Original credential WorkFactor are already the safe recommended Kdf WorkFactor. %v != %v", origWorkFactor, DefaultWorkFactor[DefaultConfig.Kdf])
	}

	config := Config{Kdf: origKdf, WorkFactor: origWorkFactor}
	userID := UserID(0)
	password := "insecurepassword"
	credential, err := config.NewCredential(userID, password)
	if err != nil {
		t.Error("Unable to create new Credential")
	}
	if credential.Kdf != origKdf {
		t.Errorf("Original credential Kdf changed. %v != %v", credential.Kdf, origKdf)
	}
	if credential.WorkFactor != origWorkFactor {
		t.Errorf("Original credential WorkFactor changed. %v != %v", credential.WorkFactor, origWorkFactor)
	}

	matched, updated := credential.MatchesPassword(password)
	if !matched {
		t.Error("Valid password did not match credential")
	}
	if !updated {
		t.Error("Outdated credential not updated")
	}
	if credential.Kdf != DefaultConfig.Kdf {
		t.Errorf("Updated credential Kdf did not update to safe recommended Kdf. %v != %v", credential.Kdf, DefaultConfig.Kdf)
	}
	if credential.WorkFactor != DefaultWorkFactor[DefaultConfig.Kdf] {
		t.Errorf("Updated credential WorkFactor did not update to safe recommended Kdf WorkFactor. %v != %v", credential.WorkFactor, DefaultWorkFactor[DefaultConfig.Kdf])
	}
}

func TestMatchesPasswordUpdateWorkFactor(t *testing.T) {
	kdf := DefaultConfig.Kdf
	origWorkFactor := ScryptWorkFactor{N: 256, R: 16, P: 1}
	defaultScryptWorkFactor := *DefaultWorkFactor[kdf].(*ScryptWorkFactor)
	if origWorkFactor == defaultScryptWorkFactor {
		t.Errorf("Original credential is already the safe recommended Kdf WorkFactor. %v == %v", origWorkFactor, defaultScryptWorkFactor)
	}

	config := Config{Kdf: kdf, WorkFactor: &origWorkFactor}
	userID := UserID(0)
	password := "insecurepassword"
	credential, err := config.NewCredential(userID, password)
	if err != nil {
		t.Error("Unable to create new Credential")
	}
	if credential.Kdf != kdf {
		t.Errorf("Original credential Kdf changed. %v != %v", credential.Kdf, kdf)
	}
	newWorkFactor := *credential.WorkFactor.(*ScryptWorkFactor)
	if newWorkFactor != origWorkFactor {
		t.Errorf("Original credential WorkFactor changed. %v != %v", newWorkFactor, origWorkFactor)
	}

	matched, updated := credential.MatchesPassword(password)
	if !matched {
		t.Error("Valid password did not match credential")
	}
	if !updated {
		t.Error("Outdated credential not updated")
	}
	if credential.Kdf != kdf {
		t.Errorf("Updated credential Kdf changed. %v != %v", credential.Kdf, kdf)
	}
	if credential.WorkFactor != DefaultWorkFactor[DefaultConfig.Kdf] {
		t.Errorf("Updated credential WorkFactor did not update to safe recommended Kdf WorkFactor. %v != %v", credential.WorkFactor, DefaultWorkFactor[DefaultConfig.Kdf])
	}
}

func TestChangePassword(t *testing.T) {
	userID := UserID(0)
	password := "insecurepassword"
	credential, err := NewCredential(userID, password)
	if err != nil {
		t.Error("Unable to create new Credential")
	}
	if err := credential.ChangePassword(password, "newInsecurePassword"); err != nil {
		t.Error("Got error resetting password.", err)
	}
}

func TestChangePasswordSamePassword(t *testing.T) {
	userID := UserID(0)
	password := "insecurepassword"
	credential, err := NewCredential(userID, password)
	if err != nil {
		t.Error("Unable to create new Credential")
	}
	if err := credential.ChangePassword(password, password); err == nil {
		t.Error("Changed password to the same password")
	}
}

func TestChangePasswordNewPasswordDoesNotMeetPasswordPolicy(t *testing.T) {
	userID := UserID(0)
	password := "insecurepassword"
	credential, err := NewCredential(userID, password)
	if err != nil {
		t.Error("Unable to create new Credential")
	}
	if err := credential.ChangePassword(password, "tooshort"); err == nil {
		t.Error("Should have gotten error resetting password")
	}
}

func TestChangePasswordIncorrectOldPassword(t *testing.T) {
	userID := UserID(0)
	password := "insecurepassword"
	credential, err := NewCredential(userID, password)
	if err != nil {
		t.Error("Unable to create new Credential")
	}
	if err := credential.ChangePassword("wrongPassword", "newInsecurePassword"); err == nil {
		t.Error("Should have gotten error resetting password")
	}
}

func TestChangePasswordWithIP(t *testing.T) {
	userID := UserID(0)
	password := "insecurepassword"
	credential, err := NewCredential(userID, password)
	if err != nil {
		t.Error("Unable to create new Credential")
	}
	if err := credential.ChangePasswordWithIP(password, "newInsecurePassword", emptyIP); err != nil {
		t.Error("Got error resetting password.", err)
	}
}

func TestChangePasswordWithIPNewPasswordDoesNotMeetPasswordPolicy(t *testing.T) {
	userID := UserID(0)
	password := "insecurepassword"
	credential, err := NewCredential(userID, password)
	if err != nil {
		t.Error("Unable to create new Credential")
	}
	if err := credential.ChangePasswordWithIP(password, "tooshort", emptyIP); err == nil {
		t.Error("Should have gotten error resetting password")
	}
}

func TestChangePasswordWithIPIncorrectOldPassword(t *testing.T) {
	userID := UserID(0)
	password := "insecurepassword"
	credential, err := NewCredential(userID, password)
	if err != nil {
		t.Error("Unable to create new Credential")
	}
	if err := credential.ChangePasswordWithIP("wrongPassword", "newInsecurePassword", emptyIP); err == nil {
		t.Error("Should have gotten error resetting password")
	}
}

func TestReset(t *testing.T) {
	userID := UserID(0)
	password := "insecurepassword"
	credential, err := NewCredential(userID, password)
	if err != nil {
		t.Error("Unable to create new Credential")
	}
	if err := credential.Reset("newInsecurePassword"); err != nil {
		t.Error("Got error resetting password.", err)
	}
}

func TestResetNewPasswordDoesNotMeetPasswordPolicy(t *testing.T) {
	userID := UserID(0)
	password := "insecurepassword"
	credential, err := NewCredential(userID, password)
	if err != nil {
		t.Error("Unable to create new Credential")
	}
	if err := credential.Reset("tooshort"); err == nil {
		t.Error("Should have gotten error resetting password")
	}
}

func TestResetWithIP(t *testing.T) {
	userID := UserID(0)
	password := "insecurepassword"
	credential, err := NewCredential(userID, password)
	if err != nil {
		t.Error("Unable to create new Credential")
	}
	if err := credential.ResetWithIP("newInsecurePassword", emptyIP); err != nil {
		t.Error("Got error resetting password.", err)
	}
}

func TestResetWithIPNewPasswordDoesNotMeetPasswordPolicy(t *testing.T) {
	userID := UserID(0)
	password := "insecurepassword"
	credential, err := NewCredential(userID, password)
	if err != nil {
		t.Error("Unable to create new Credential")
	}
	if err := credential.ResetWithIP("tooshort", emptyIP); err == nil {
		t.Error("Should have gotten error resetting password")
	}
}
