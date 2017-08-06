package passhash

import (
	"errors"
	"testing"
)

type TestingWorkFactor struct {
	Error bool
	Len   int
}

func (wf TestingWorkFactor) Marshal() ([]int, error) {
	if wf.Error {
		return []int{}, errors.New("Test marshaling error")
	}
	return make([]int, wf.Len), nil
}
func (wf TestingWorkFactor) Unmarshal([]int) error {
	return nil
}

func TestWorkFactorsEqualDiffTypes(t *testing.T) {
	a := &Pbkdf2WorkFactor{}
	b := &BcryptWorkFactor{}
	if WorkFactorsEqual(a, b) {
		t.Errorf("WorkFactors with different types are considered equal. %T == %T", a, b)
	}
}

func TestWorkFactorsEqualMarshalError(t *testing.T) {
	a := TestingWorkFactor{Error: true, Len: 10}
	b := TestingWorkFactor{Error: false, Len: 10}
	if WorkFactorsEqual(a, b) {
		t.Errorf("WorkFactors with marshaling error are considered equal. %T == %T", a, b)
	}
	if WorkFactorsEqual(b, a) {
		t.Errorf("WorkFactors with marshaling error are considered equal. %T == %T", b, a)
	}
}

func TestWorkFactorsEqualDiffLen(t *testing.T) {
	a := TestingWorkFactor{Error: false, Len: 10}
	b := TestingWorkFactor{Error: false, Len: 5}
	if WorkFactorsEqual(a, b) {
		t.Errorf("WorkFactors with different \"lengths\" are considered equal. %T == %T", a, b)
	}
}

func TestWorkFactorsEqual(t *testing.T) {
	a := &ScryptWorkFactor{R: 1, P: 2, N: 3}
	b := &ScryptWorkFactor{R: 1, P: 2, N: 3}
	if !WorkFactorsEqual(a, b) {
		t.Errorf("The same WorkFactors are not considered equal. %v != %v", a, b)
	}
}

func TestWorkFactorsEqualDifferent(t *testing.T) {
	a := &ScryptWorkFactor{R: 1, P: 2, N: 3}
	b := &ScryptWorkFactor{R: 1, P: 2, N: 4}
	if WorkFactorsEqual(a, b) {
		t.Errorf("Different WorkFactors are considered equal. %v == %v", a, b)
	}
}

func TestConfigNewCredentialFailsPasswordPolicies(t *testing.T) {
	userID := UserID(0)
	password := "tooshort"
	_, err := DefaultConfig.NewCredential(userID, password)
	if err == nil {
		t.Errorf("Password that didn't meet password policies created new credential. %v", err)
	}
	_, ok := err.(PasswordPoliciesNotMet)
	if !ok {
		t.Errorf("error should be of type PasswordPoliciesNotMet instead of %T", err)
	}
}

type readerError struct{}

func (re readerError) Read(p []byte) (n int, err error) {
	return 0, errors.New("Error reading")
}

func TestNewCredentialRandError(t *testing.T) {
	origRandReader := cryptoRandReader
	defer func() {
		// Very important to reset the global randReader. Otherwise other tests will fail
		cryptoRandReader = origRandReader
	}()
	cryptoRandReader = readerError{}
	userID := UserID(0)
	password := "insecurepassword"
	if _, err := DefaultConfig.NewCredential(userID, password); err == nil {
		t.Error("No error hit when calling random numbers")
	}
}

func testWorkFactorMarshal(t *testing.T, workFactor WorkFactor, expected []int) {
	marshaled, err := workFactor.Marshal()
	if err != nil {
		t.Fatalf("Error marshaling workFactor: %T. %v", workFactor, err)
	}
	if len(marshaled) != len(expected) {
		t.Fatalf("Marshaled length (%d) != expected length (%d) for workFactor %T", len(marshaled), len(expected), workFactor)
	}
	for i, v := range marshaled {
		if v != expected[i] {
			t.Errorf("marshaled value (%d) != expected value (%d) at index %d for workFactor %T", v, expected[i], i, workFactor)
		}
	}
}

func testWorkFactorUnmarshal(t *testing.T, data []int, tester WorkFactor, expected WorkFactor) {
	if err := tester.Unmarshal(data); err != nil {
		t.Fatalf("Error unmarshaling workFactor: %T. %v", tester, err)
	}
	expectedMarshaled, err := expected.Marshal()
	if err != nil {
		t.Fatalf("Unable to marshal expected WorkFactor %v", expected)
	}
	testWorkFactorMarshal(t, tester, expectedMarshaled)
}

func testWorkFactorUnmarshalError(t *testing.T, data []int, tester WorkFactor) {
	if err := tester.Unmarshal(data); err == nil {
		t.Errorf("Successfully unmarshaling workFactor: %T with data: %v", tester, data)
	}
}

func TestPdkdf2WorkFactorMarshal(t *testing.T) {
	testWorkFactorMarshal(t, &Pbkdf2WorkFactor{Iter: 1}, []int{1})
}

func TestPdkdf2WorkFactorUnmarshal(t *testing.T) {
	testWorkFactorUnmarshal(t, []int{1}, &Pbkdf2WorkFactor{}, &Pbkdf2WorkFactor{Iter: 1})
}

func TestPdkdf2WorkFactorUnmarshalError(t *testing.T) {
	testWorkFactorUnmarshalError(t, []int{}, &Pbkdf2WorkFactor{})
	testWorkFactorUnmarshalError(t, []int{1, 2}, &Pbkdf2WorkFactor{})
}

func TestBcryptWorkFactorMarshal(t *testing.T) {
	testWorkFactorMarshal(t, &BcryptWorkFactor{Cost: 1}, []int{1})
}

func TestBcryptWorkFactorUnmarshal(t *testing.T) {
	testWorkFactorUnmarshal(t, []int{1}, &BcryptWorkFactor{}, &BcryptWorkFactor{Cost: 1})
}

func TestBcryptWorkFactorUnmarshalError(t *testing.T) {
	testWorkFactorUnmarshalError(t, []int{}, &BcryptWorkFactor{})
	testWorkFactorUnmarshalError(t, []int{1, 2}, &BcryptWorkFactor{})
}

func TestScryptWorkFactorMarshal(t *testing.T) {
	testWorkFactorMarshal(t, &ScryptWorkFactor{R: 1, P: 2, N: 3}, []int{1, 2, 3})
}

func TestScryptWorkFactorUnmarshal(t *testing.T) {
	testWorkFactorUnmarshal(t, []int{1, 2, 3}, &ScryptWorkFactor{}, &ScryptWorkFactor{R: 1, P: 2, N: 3})
}

func TestScryptWorkFactorUnmarshalError(t *testing.T) {
	testWorkFactorUnmarshalError(t, []int{}, &ScryptWorkFactor{})
	testWorkFactorUnmarshalError(t, []int{1, 2}, &BcryptWorkFactor{})
	testWorkFactorUnmarshalError(t, []int{1, 2, 3, 4}, &BcryptWorkFactor{})
}
