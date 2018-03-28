package passhash

import (
	"crypto/subtle"
	"errors"
	"golang.org/x/crypto/bcrypt"
	"net"
)

var emptyIP = net.IP{}

// Credential is a password specification.
// It contains all of the parameters necessary to generate and verify a password for a user
type Credential struct {
	UserID     UserID
	Kdf        Kdf
	WorkFactor WorkFactor
	Salt       []byte
	Hash       []byte
}

func (c *Credential) matchPassword(password string, auditLogger AuditLogger, ip net.IP) bool {
	if c.Kdf == Bcrypt {
		// Bcrypt's API is and compares the password and hash for you
		match := bcrypt.CompareHashAndPassword(c.Hash, []byte(password)) == nil
		if match {
			auditLogger.Log(c.UserID, AuthnSucceeded, ip)
		} else {
			auditLogger.Log(c.UserID, AuthnFailed, ip)
		}
		return match
	}
	hash, err := getPasswordHash(c.Kdf, c.WorkFactor, c.Salt, len(c.Hash), password)
	if err != nil {
		return false
	}
	match := subtle.ConstantTimeCompare(c.Hash, hash) == 1
	if match {
		auditLogger.Log(c.UserID, AuthnSucceeded, ip)
	} else {
		auditLogger.Log(c.UserID, AuthnFailed, ip)
	}
	return match
}

// NeedsUpdate determines if the Credential meets the recommended safe key derivation function and parameters
func (c *Credential) NeedsUpdate() bool {
	return !c.MeetsConfig(DefaultConfig)
}

// MeetsConfig returns true if the Credential meets the parameters specified in the given Config and returns false otherwise
func (c *Credential) MeetsConfig(config Config) bool {
	// FML, workfactors are pointers and won't compare using ==
	return c.Kdf == config.Kdf && WorkFactorsEqual(c.WorkFactor, config.WorkFactor)
}

func (c *Credential) ensureUpdated(config Config, password string, ip net.IP) bool {
	if !c.MeetsConfig(config) {
		newCredential, err := config.NewCredential(c.UserID, password)
		if err != nil {
			return false
		}
		*c = *newCredential
		config.AuditLogger.Log(c.UserID, UpgradedKdf, ip)
		return true
	}
	return false
}

// MatchesPassword checks if the provided password matches the Credential
// and updates the Credential to use the recommended safe key derivation function and parameters
func (c *Credential) MatchesPassword(password string) (matched, updated bool) {
	return c.MatchesPasswordWithConfig(DefaultConfig, password)
}

// MatchesPasswordWithIP checks if the provided password matches the Credential
// and updates the Credential to use the recommended safe key derivation function and parameters
func (c *Credential) MatchesPasswordWithIP(password string, ip net.IP) (matched, updated bool) {
	return c.MatchesPasswordWithConfigAndIP(DefaultConfig, password, ip)
}

// MatchesPasswordWithConfig checks if the provided password matches the Credential
// and updates the Credential to meet the Config parameters if necessary
func (c *Credential) MatchesPasswordWithConfig(config Config, password string) (matched, updated bool) {
	return c.MatchesPasswordWithConfigAndIP(config, password, emptyIP)
}

// MatchesPasswordWithConfigAndIP checks if the provided password matches the Credential
// and updates the Credential to meet the Config parameters if necessary
func (c *Credential) MatchesPasswordWithConfigAndIP(config Config, password string, ip net.IP) (matched, updated bool) {
	updated = false
	matched = c.matchPassword(password, config.AuditLogger, ip)
	if !matched {
		return
	}
	updated = c.ensureUpdated(config, password, ip)
	return
}

// ChangePassword changes the password for the given Credential and updates the Credential to use the recommended safe key derivation function and parameters
func (c *Credential) ChangePassword(oldPassword, newPassword string) error {
	return c.ChangePasswordWithConfig(DefaultConfig, oldPassword, newPassword)
}

// ChangePasswordWithIP changes the password for the given Credential and updates the Credential to use the recommended safe key derivation function and parameters
func (c *Credential) ChangePasswordWithIP(oldPassword, newPassword string, ip net.IP) error {
	return c.ChangePasswordWithConfigAndIP(DefaultConfig, oldPassword, newPassword, ip)
}

// ChangePasswordWithConfig changes the password for the given Credential and updates the Credential to meet the Config parameters if necessary
func (c *Credential) ChangePasswordWithConfig(config Config, oldPassword, newPassword string) error {
	return c.ChangePasswordWithConfigAndIP(config, oldPassword, newPassword, emptyIP)
}

// ChangePasswordWithConfigAndIP changes the password for the given Credential and updates the Credential to meet the Config parameters if necessary
func (c *Credential) ChangePasswordWithConfigAndIP(config Config, oldPassword, newPassword string, ip net.IP) error {
	if !c.matchPassword(oldPassword, config.AuditLogger, ip) {
		return errors.New("Old password does not match existing password")
	}
	return c.ResetWithConfigAndIP(config, newPassword, ip)
}

// Reset resets the password for the given Credential and updates the Credential to use the recommended safe key derivation function and parameters
func (c *Credential) Reset(newPassword string) error {
	return c.ResetWithConfig(DefaultConfig, newPassword)
}

// ResetWithIP resets the password for the given Credential and updates the Credential to use the recommended safe key derivation function and parameters
func (c *Credential) ResetWithIP(newPassword string, ip net.IP) error {
	return c.ResetWithConfigAndIP(DefaultConfig, newPassword, ip)
}

// ResetWithConfig resets the password for the given Credential and updates the Credential to meet the Config parameters if necessary
func (c *Credential) ResetWithConfig(config Config, newPassword string) error {
	return c.ResetWithConfigAndIP(config, newPassword, emptyIP)
}

// ResetWithConfigAndIP resets the password for the given Credential and updates the Credential to meet the Config parameters if necessary
func (c *Credential) ResetWithConfigAndIP(config Config, newPassword string, ip net.IP) error {
	newCredential, err := config.NewCredential(c.UserID, newPassword)
	if err != nil {
		return err
	}
	*c = *newCredential
	return nil
}
