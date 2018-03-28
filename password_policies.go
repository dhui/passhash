package passhash

import (
	"errors"
	"fmt"
	"unicode/utf8"
)

// PasswordPolicy is an interface used to determine if a password is acceptable. e.g. meets the given policy
type PasswordPolicy interface {
	PasswordAcceptable(string) error
}

// AtLeastNRunes is a PasswordPolicy that ensures that the password is at least N runes in length
type AtLeastNRunes struct {
	N int
}

// PasswordAcceptable accepts passwords that are at least N runes in length
func (pp AtLeastNRunes) PasswordAcceptable(password string) error {
	if utf8.RuneCountInString(password) < pp.N {
		return fmt.Errorf("Password must be at least %d characters in length", pp.N)
	}
	return nil
}

// NotCommonPasswordNaive is a PasswordPolicy that ensures that the password is not a common password.
// The method of checking is naive in that only exact password matches are rejected
type NotCommonPasswordNaive struct {
	CommonPasswords map[string]bool
}

// PasswordAcceptable accepts passwords that are not common passwords
func (pp NotCommonPasswordNaive) PasswordAcceptable(password string) error {
	if pp.CommonPasswords[password] {
		return errors.New("Password is a common password")
	}
	return nil
}
