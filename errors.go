package passhash

import (
	"errors"
	"fmt"
	"strings"
)

var (
	// ErrPasswordUnchanged is used when a Credential.ChangePassword*() method is called with the same old and new
	// password
	ErrPasswordUnchanged = errors.New("Password unchanged")
)

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
