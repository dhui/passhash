package passhash

import (
	"crypto"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/sha3"
)

// Kdf is a Key Derivation Function
type Kdf uint

const (
	// Pbkdf2Sha256 is the PBKDF2 using SHA-256 as the HMAC. To use this, you'll need to register the sha256 package by importing "crypto/sha256".
	Pbkdf2Sha256 Kdf = iota + 1
	// Pbkdf2Sha512 is the PBKDF2 using SHA-512 as the HMAC. To use this, you'll need to register the sha256 package by importing "crypto/sha256".
	Pbkdf2Sha512
	// Pbkdf2Sha3_256 is the PBKDF2 using SHA-3 256 bit block size as the HMAC
	Pbkdf2Sha3_256
	// Pbkdf2Sha3_512 is the PBKDF2 using SHA-3 512 bit block size as the HMAC
	Pbkdf2Sha3_512
	// Bcrypt is the bcrypt kdf
	Bcrypt
	// Scrypt is the scrypt kdf
	Scrypt
)

// DefaultWorkFactor provides the default WorkFactor for a specific Kdf. Do not modify unless you're an expert.
// Note: DefaultWorkFactor returns a pointer so do not use Unmarshal w/ a WorkFactor from DefaultWorkFactor.
// Use NewWorkFactorForKdf() instead.
// TODO: Determine/tune DefaultWorkFactor (aim for 150+ms hash time on API server hardware)
var DefaultWorkFactor = map[Kdf]WorkFactor{
	Pbkdf2Sha256:   &Pbkdf2WorkFactor{Iter: 100000},
	Pbkdf2Sha512:   &Pbkdf2WorkFactor{Iter: 100000},
	Pbkdf2Sha3_256: &Pbkdf2WorkFactor{Iter: 100000},
	Pbkdf2Sha3_512: &Pbkdf2WorkFactor{Iter: 100000},
	Bcrypt:         &BcryptWorkFactor{Cost: 12}, // bcrypt.DefaultCost is 10 as of 2017-07-26

	// Scrypt - n >= 16384, p = 1, r = 16 (output length = 32)
	// https://crypto.stackexchange.com/questions/35423/appropriate-scrypt-parameters-when-generating-an-scrypt-hash
	// https://download.libsodium.org/doc/password_hashing/scrypt.html
	// Scrypt: ScryptWorkFactor{N: 65536, R: 16, P: 1},
	Scrypt: &ScryptWorkFactor{N: 32768, R: 16, P: 1},
}

// NewWorkFactorForKdf returns an empty new WorkFactor for the given kdf
func NewWorkFactorForKdf(kdf Kdf) (WorkFactor, error) {
	switch kdf {
	case Pbkdf2Sha256, Pbkdf2Sha512, Pbkdf2Sha3_256, Pbkdf2Sha3_512:
		return &Pbkdf2WorkFactor{}, nil
	case Bcrypt:
		return &BcryptWorkFactor{}, nil
	case Scrypt:
		return &ScryptWorkFactor{}, nil
	default:
		return nil, fmt.Errorf("Unsupported kdf: %v", kdf)
	}
}

// DefaultConfig is a safe default configuration for managing credentials
var DefaultConfig = Config{
	Kdf:         Scrypt,
	WorkFactor:  DefaultWorkFactor[Scrypt],
	SaltSize:    16,
	KeyLength:   32,
	AuditLogger: &DummyAuditLogger{},    // It is recommended that you replace the dummy AuditLogger to actually audit your credentials
	Store:       DummyCredentialStore{}, // It is recommended that you rpelace the dummy CredentialStore to actually store credentials
	PasswordPolicies: []PasswordPolicy{
		AtLeastNRunes{N: 10},
	},
}

// NewCredential creates a new Credential with sane/recommended defaults
func NewCredential(userID UserID, password string) (*Credential, error) {
	return DefaultConfig.NewCredential(userID, password)
}

func getPasswordHash(kdf Kdf, workFactor WorkFactor, salt []byte, keyLength int, password string) ([]byte, error) {
	// NB: Do not hash the password before running it through a KDF. Instead, rely on Go's libraries to provide the proper security
	switch wf := workFactor.(type) {
	case *Pbkdf2WorkFactor:
		switch kdf {
		case Pbkdf2Sha256:
			return pbkdf2.Key([]byte(password), salt, wf.Iter, keyLength, crypto.SHA256.New), nil
		case Pbkdf2Sha512:
			return pbkdf2.Key([]byte(password), salt, wf.Iter, keyLength, crypto.SHA512.New), nil
		case Pbkdf2Sha3_256:
			return pbkdf2.Key([]byte(password), salt, wf.Iter, keyLength, sha3.New256), nil
		case Pbkdf2Sha3_512:
			return pbkdf2.Key([]byte(password), salt, wf.Iter, keyLength, sha3.New512), nil
		default:
			return []byte{}, fmt.Errorf("Pbkdf2WorkFactor can only be specified with the Pbkdf2 Kdf")
		}
	case *BcryptWorkFactor:
		if kdf != Bcrypt {
			return []byte{}, fmt.Errorf("BcryptWorkFactor can only be specified with the Bcrypt Kdf")
		}
		return bcrypt.GenerateFromPassword([]byte(password), wf.Cost)
	case *ScryptWorkFactor:
		if kdf != Scrypt {
			return []byte{}, fmt.Errorf("ScryptWorkFactor can only be specified with the Scrypt Kdf")
		}
		return scrypt.Key([]byte(password), salt, wf.N, wf.R, wf.P, keyLength)
	default:
		return []byte{}, fmt.Errorf("Unsupported WorkFactor: %T", wf)
	}
}
