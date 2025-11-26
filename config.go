package passhash

import (
	"crypto/rand"
	"fmt"
	"io"
	"reflect"
	"slices"
)

var randReader = rand.Reader

// GetRandReader gets the io.Reader responsible for generating random bytes used by passhash
func GetRandReader() io.Reader {
	return randReader
}

// SetRandReader sets the io.Reader used by passhash to generate random bytes
func SetRandReader(reader io.Reader) {
	randReader = reader
}

// WorkFactor describes the work/cost for a KDF
// The interface is similar to Go's "encoding" Marshaler/Unmarshalers
type WorkFactor interface {
	Marshal() ([]int, error)
	Unmarshal([]int) error
}

// WorkFactorsEqual determines if 2 WorkFactors are equivalent
func WorkFactorsEqual(a, b WorkFactor) bool {
	if reflect.TypeOf(a) != reflect.TypeOf(b) {
		return false
	}
	aM, err := a.Marshal()
	if err != nil {
		return false
	}
	bM, err := b.Marshal()
	if err != nil {
		return false
	}
	return slices.Equal(aM, bM)
}

// Pbkdf2WorkFactor specifies the work/cost parameters for PBKDF2
type Pbkdf2WorkFactor struct {
	Iter int
}

// Marshal returns the marshaled WorkFactor
func (wf *Pbkdf2WorkFactor) Marshal() ([]int, error) {
	return []int{wf.Iter}, nil
}

// Unmarshal unmarshals the WorkFactor
func (wf *Pbkdf2WorkFactor) Unmarshal(p []int) error {
	if len(p) != 1 {
		return fmt.Errorf("Invalid parameters to unmarshal %T", wf)
	}
	wf.Iter = p[0]
	return nil
}

// BcryptWorkFactor specifies the work/cost parameters for bcrypt
type BcryptWorkFactor struct {
	Cost int
}

// Marshal returns the marshaled WorkFactor
func (wf *BcryptWorkFactor) Marshal() ([]int, error) {
	return []int{wf.Cost}, nil
}

// Unmarshal unmarshals the WorkFactor
func (wf *BcryptWorkFactor) Unmarshal(p []int) error {
	if len(p) != 1 {
		return fmt.Errorf("Invalid parameters to unmarshal %T", wf)
	}
	wf.Cost = p[0]
	return nil
}

// ScryptWorkFactor specifies the work/cost parameters for scrypt
type ScryptWorkFactor struct {
	R int
	P int
	N int
}

// Marshal returns the marshaled WorkFactor
func (wf *ScryptWorkFactor) Marshal() ([]int, error) {
	return []int{wf.R, wf.P, wf.N}, nil
}

// Unmarshal unmarshals the WorkFactor
func (wf *ScryptWorkFactor) Unmarshal(p []int) error {
	if len(p) != 3 {
		return fmt.Errorf("Invalid parameters to unmarshal %T", wf)
	}
	wf.R = p[0]
	wf.P = p[1]
	wf.N = p[2]
	return nil
}

// Argon2WorkFactor specifies the work/cost parameters for scrypt
type Argon2WorkFactor struct {
	T int // time (iterations)
	M int // memory
	P int // parallelism (threads)
}

// Marshal returns the marshaled WorkFactor
func (wf *Argon2WorkFactor) Marshal() ([]int, error) {
	return []int{wf.T, wf.M, wf.P}, nil
}

// Unmarshal unmarshals the WorkFactor
func (wf *Argon2WorkFactor) Unmarshal(p []int) error {
	if len(p) != 3 {
		return fmt.Errorf("Invalid parameters to unmarshal %T", wf)
	}
	wf.T = p[0]
	wf.M = p[1]
	wf.P = p[2]
	return nil
}

// Config provides configuration for managing credentials. e.g. creation, storing, verifying, and auditing
type Config struct {
	Kdf              Kdf              // The key derivation function
	WorkFactor       WorkFactor       // The work factor for the kdf
	SaltSize         int              // The size of the salt in bytes
	KeyLength        int              // The size of the output key (e.g. hash) in bytes
	AuditLogger      AuditLogger      // The AuditLogger to use
	Store            CredentialStore  // The CredentialStore to use
	PasswordPolicies []PasswordPolicy // The password policies to enforce
}

// NewCredential creates a new Credential with the provided Config
func (c Config) NewCredential(userID UserID, password string) (*Credential, error) {
	passwordPolicyFailures := PasswordPoliciesNotMet{}
	for _, pp := range c.PasswordPolicies {
		if err := pp.PasswordAcceptable(password); err != nil {
			passwordPolicyFailures.UnMetPasswordPolicies = append(passwordPolicyFailures.UnMetPasswordPolicies,
				PasswordPolicyError{PasswordPolicy: pp, Err: err})
		}
	}
	if len(passwordPolicyFailures.UnMetPasswordPolicies) > 0 {
		return nil, passwordPolicyFailures
	}
	salt := make([]byte, c.SaltSize)
	if _, err := io.ReadFull(randReader, salt); err != nil {
		return nil, err
	}
	hash, err := getPasswordHash(c.Kdf, c.WorkFactor, salt, c.KeyLength, password)
	if err != nil {
		return nil, err
	}
	return &Credential{UserID: userID, Kdf: c.Kdf, WorkFactor: c.WorkFactor, Salt: salt, Hash: hash}, nil
}
