package passhash

import (
	"errors"
)

var (
	// ErrPasswordUnchanged is used when a Credential.ChangePassword*() method is called with the same old and new
	// password
	ErrPasswordUnchanged = errors.New("Password unchanged")
)
