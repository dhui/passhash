package passhash

import (
	"testing"
)

func BenchmarkDefaultWorkFactorPbkdfSha256(b *testing.B) {
	kdf := Pbkdf2Sha256
	config := Config{Kdf: kdf, WorkFactor: DefaultWorkFactor[kdf],
		SaltSize: 16, KeyLength: 32, AuditLogger: &DummyAuditLogger{}, Store: DummyCredentialStore{},
		PasswordPolicies: []PasswordPolicy{},
	}
	userID := UserID(0)
	password := "insecurepassword"
	for i := 0; i < b.N; i++ {
		config.NewCredential(userID, password)
	}
}

func BenchmarkDefaultWorkFactorPbkdfSha512(b *testing.B) {
	kdf := Pbkdf2Sha512
	config := Config{Kdf: kdf, WorkFactor: DefaultWorkFactor[kdf],
		SaltSize: 16, KeyLength: 32, AuditLogger: &DummyAuditLogger{}, Store: DummyCredentialStore{},
		PasswordPolicies: []PasswordPolicy{},
	}
	userID := UserID(0)
	password := "insecurepassword"
	for i := 0; i < b.N; i++ {
		config.NewCredential(userID, password)
	}
}

func BenchmarkDefaultWorkFactorPbkdfSha3_256(b *testing.B) {
	kdf := Pbkdf2Sha3_256
	config := Config{Kdf: kdf, WorkFactor: DefaultWorkFactor[kdf],
		SaltSize: 16, KeyLength: 32, AuditLogger: &DummyAuditLogger{}, Store: DummyCredentialStore{},
		PasswordPolicies: []PasswordPolicy{},
	}
	userID := UserID(0)
	password := "insecurepassword"
	for i := 0; i < b.N; i++ {
		config.NewCredential(userID, password)
	}
}

func BenchmarkDefaultWorkFactorPbkdfSha3_512(b *testing.B) {
	kdf := Pbkdf2Sha3_512
	config := Config{Kdf: kdf, WorkFactor: DefaultWorkFactor[kdf],
		SaltSize: 16, KeyLength: 32, AuditLogger: &DummyAuditLogger{}, Store: DummyCredentialStore{},
		PasswordPolicies: []PasswordPolicy{},
	}
	userID := UserID(0)
	password := "insecurepassword"
	for i := 0; i < b.N; i++ {
		config.NewCredential(userID, password)
	}
}

func BenchmarkDefaultWorkFactorBcrypt(b *testing.B) {
	kdf := Bcrypt
	config := Config{Kdf: kdf, WorkFactor: DefaultWorkFactor[kdf],
		SaltSize: 16, KeyLength: 32, AuditLogger: &DummyAuditLogger{}, Store: DummyCredentialStore{},
		PasswordPolicies: []PasswordPolicy{},
	}
	userID := UserID(0)
	password := "insecurepassword"
	for i := 0; i < b.N; i++ {
		config.NewCredential(userID, password)
	}
}

func BenchmarkDefaultWorkFactorScrypt(b *testing.B) {
	kdf := Scrypt
	config := Config{Kdf: kdf, WorkFactor: DefaultWorkFactor[kdf],
		SaltSize: 16, KeyLength: 32, AuditLogger: &DummyAuditLogger{}, Store: DummyCredentialStore{},
		PasswordPolicies: []PasswordPolicy{},
	}
	userID := UserID(0)
	password := "insecurepassword"
	for i := 0; i < b.N; i++ {
		config.NewCredential(userID, password)
	}
}
