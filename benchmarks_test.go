package passhash_test

import (
	"testing"
)

import (
	"github.com/dhui/passhash"
)

func BenchmarkDefaultWorkFactorPbkdfSha256(b *testing.B) {
	kdf := passhash.Pbkdf2Sha256
	config := passhash.Config{Kdf: kdf, WorkFactor: passhash.DefaultWorkFactor[kdf],
		SaltSize: 16, KeyLength: 32, AuditLogger: &passhash.DummyAuditLogger{},
		Store: passhash.DummyCredentialStore{}, PasswordPolicies: []passhash.PasswordPolicy{},
	}
	userID := passhash.UserID(0)
	password := "insecurepassword"
	for i := 0; i < b.N; i++ {
		config.NewCredential(userID, password)
	}
}

func BenchmarkDefaultWorkFactorPbkdfSha512(b *testing.B) {
	kdf := passhash.Pbkdf2Sha512
	config := passhash.Config{Kdf: kdf, WorkFactor: passhash.DefaultWorkFactor[kdf],
		SaltSize: 16, KeyLength: 32, AuditLogger: &passhash.DummyAuditLogger{},
		Store: passhash.DummyCredentialStore{}, PasswordPolicies: []passhash.PasswordPolicy{},
	}
	userID := passhash.UserID(0)
	password := "insecurepassword"
	for i := 0; i < b.N; i++ {
		config.NewCredential(userID, password)
	}
}

func BenchmarkDefaultWorkFactorPbkdfSha3_256(b *testing.B) {
	kdf := passhash.Pbkdf2Sha3_256
	config := passhash.Config{Kdf: kdf, WorkFactor: passhash.DefaultWorkFactor[kdf],
		SaltSize: 16, KeyLength: 32, AuditLogger: &passhash.DummyAuditLogger{},
		Store: passhash.DummyCredentialStore{}, PasswordPolicies: []passhash.PasswordPolicy{},
	}
	userID := passhash.UserID(0)
	password := "insecurepassword"
	for i := 0; i < b.N; i++ {
		config.NewCredential(userID, password)
	}
}

func BenchmarkDefaultWorkFactorPbkdfSha3_512(b *testing.B) {
	kdf := passhash.Pbkdf2Sha3_512
	config := passhash.Config{Kdf: kdf, WorkFactor: passhash.DefaultWorkFactor[kdf],
		SaltSize: 16, KeyLength: 32, AuditLogger: &passhash.DummyAuditLogger{},
		Store: passhash.DummyCredentialStore{}, PasswordPolicies: []passhash.PasswordPolicy{},
	}
	userID := passhash.UserID(0)
	password := "insecurepassword"
	for i := 0; i < b.N; i++ {
		config.NewCredential(userID, password)
	}
}

func BenchmarkDefaultWorkFactorBcrypt(b *testing.B) {
	kdf := passhash.Bcrypt
	config := passhash.Config{Kdf: kdf, WorkFactor: passhash.DefaultWorkFactor[kdf],
		SaltSize: 16, KeyLength: 32, AuditLogger: &passhash.DummyAuditLogger{},
		Store: passhash.DummyCredentialStore{}, PasswordPolicies: []passhash.PasswordPolicy{},
	}
	userID := passhash.UserID(0)
	password := "insecurepassword"
	for i := 0; i < b.N; i++ {
		config.NewCredential(userID, password)
	}
}

func BenchmarkDefaultWorkFactorScrypt(b *testing.B) {
	kdf := passhash.Scrypt
	config := passhash.Config{Kdf: kdf, WorkFactor: passhash.DefaultWorkFactor[kdf],
		SaltSize: 16, KeyLength: 32, AuditLogger: &passhash.DummyAuditLogger{},
		Store: passhash.DummyCredentialStore{}, PasswordPolicies: []passhash.PasswordPolicy{},
	}
	userID := passhash.UserID(0)
	password := "insecurepassword"
	for i := 0; i < b.N; i++ {
		config.NewCredential(userID, password)
	}
}
