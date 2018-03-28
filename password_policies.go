package passhash

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// PasswordPolicy is an interface used to determine if a password is acceptable. e.g. meets the given policy
type PasswordPolicy interface {
	PasswordAcceptable(string) error
}

// PasswordPolicyError satisfies the error interface and describes the reason for a PasswordPolicy check failure
type PasswordPolicyError struct {
	PasswordPolicy PasswordPolicy
	Err            error
}

func (e PasswordPolicyError) Error() string {
	return e.Err.Error()
}

// PasswordPoliciesNotMet satisfies the error interface and tracks the unmet password policies
type PasswordPoliciesNotMet struct {
	UnMetPasswordPolicies []PasswordPolicyError
}

func (e PasswordPoliciesNotMet) Error() string {
	errorStrs := make([]string, 0, len(e.UnMetPasswordPolicies))
	for _, ppe := range e.UnMetPasswordPolicies {
		errorStrs = append(errorStrs, ppe.Error())
	}
	return fmt.Sprintf("Password policies not met due to: %s", strings.Join(errorStrs, ", "))
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
