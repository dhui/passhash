package passhash

import (
	"errors"
	"testing"
)

func TestPasswordPoliciesNotMetDuplicateErrors(t *testing.T) {
	err := PasswordPoliciesNotMet{UnMetPasswordPolicies: []PasswordPolicyError{
		{AtLeastNRunes{}, errors.New("Dummy error 1")},
		{AtLeastNRunes{}, errors.New("Dummy error 2")},
	}}
	expectedError := "Password policies not met due to: Dummy error 1, Dummy error 2"
	if err.Error() != expectedError {
		t.Errorf("PasswordPoliciesNotMet.Error() did not properly handle duplicate PasswordPolicyErrors. %s != %s", err.Error(), expectedError)
	}
}

func TestAtLeastNRunesTooShort(t *testing.T) {
	pp := AtLeastNRunes{N: 5}
	if err := pp.PasswordAcceptable("1234"); err == nil {
		t.Errorf("Password that's too short was accepted")
	}
}

func TestAtLeastNRunesExact(t *testing.T) {
	pp := AtLeastNRunes{N: 5}
	if err := pp.PasswordAcceptable("12345"); err != nil {
		t.Errorf("Password that's exactly long enough was rejected")
	}
}

func TestAtLeastNRunesEnough(t *testing.T) {
	pp := AtLeastNRunes{N: 5}
	if err := pp.PasswordAcceptable("123456"); err != nil {
		t.Errorf("Password that's long enough was rejected")
	}
}

func TestNotCommonPasswordNaiveAccepted(t *testing.T) {
	pp := NotCommonPasswordNaive{CommonPasswords: map[string]bool{
		"foo": true,
		"bar": true,
	}}
	if err := pp.PasswordAcceptable("rarepassword"); err != nil {
		t.Errorf("Password that's not common was rejected")
	}
}

func TestNotCommonPasswordNaiveRejected(t *testing.T) {
	pp := NotCommonPasswordNaive{CommonPasswords: map[string]bool{
		"foo": true,
		"bar": true,
	}}
	if err := pp.PasswordAcceptable("foo"); err == nil {
		t.Errorf("Password that's common was accepted")
	}
}
