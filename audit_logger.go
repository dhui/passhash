package passhash

import (
	"net"
	"time"
)

// AuditType represents the type of Audit that's logged
type AuditType uint

// UserID is the ID of the user being authenticated
type UserID uint64

const (
	// AuthnSucceeded means authorization succeeded
	AuthnSucceeded AuditType = iota + 1
	// AuthnFailed means authorization failed
	AuthnFailed
	// UpgradedKdf means the key derivation function was updated
	UpgradedKdf
)

// Log is an audit log entry
type Log struct {
	UserID UserID
	Time   time.Time
	Type   AuditType
	IP     net.IP
}

// AuditLogger is an interface for storing Specs with an audit trail
type AuditLogger interface {
	// Log logs an authorization action/result
	Log(UserID, AuditType, net.IP)
	// LastN gets the last N logs for a user
	LastN(userID UserID, n int) []Log
	// LastNWithTypes gets the last N logs for a user with the specified types
	LastNWithTypes(userID UserID, n int, auditTypes ...AuditType) []Log
}

// DummyAuditLogger is a dummy AuditLogger. e.g. it doesn't track any audit logs
type DummyAuditLogger struct{}

// Log doesn't actually do anything
func (al *DummyAuditLogger) Log(UserID, AuditType, net.IP) {}

// LastN doesn't actually do anything
func (al *DummyAuditLogger) LastN(userID UserID, n int) []Log {
	return []Log{}
}

// LastNWithTypes doesn't actually do anything
func (al *DummyAuditLogger) LastNWithTypes(userID UserID, n int, auditTypes ...AuditType) []Log {
	return []Log{}
}

// MemoryAuditLogger is an AuditLogger that stores all of it's logs in memory
// It is not recommended that you use this AuditLogger in production since the logs are not persisted and concurrent access is not supported
type MemoryAuditLogger struct {
	allLogs map[UserID][]Log
}

// Log will log the AuditLog in memory
func (al *MemoryAuditLogger) Log(userID UserID, at AuditType, ip net.IP) {
	if al.allLogs == nil {
		al.allLogs = make(map[UserID][]Log)
	}
	entry := al.allLogs[userID]
	if entry == nil {
		entry = []Log{}
	}
	al.allLogs[userID] = append(entry, Log{UserID: userID, Time: time.Now(), Type: at, IP: ip})
}

// LastN gets the last N logs for a user
func (al *MemoryAuditLogger) LastN(userID UserID, n int) []Log {
	origLogs := al.allLogs[userID]
	logs := make([]Log, 0, n)
	if n >= len(origLogs) {
		return origLogs
	}
	return append(logs, origLogs[len(origLogs)-n:]...)
}

// LastNWithTypes gets the last N logs for a user with the specified types
func (al *MemoryAuditLogger) LastNWithTypes(userID UserID, n int, auditTypes ...AuditType) (logs []Log) {
	origLogs := al.allLogs[userID]
	logs = make([]Log, 0, n)
	for i := len(origLogs) - 1; i >= 0; i-- {
		log := al.allLogs[userID][i]
		for _, auditType := range auditTypes {
			if log.Type == auditType {
				logs = append(logs, log)
				continue
			}
		}
		if len(logs) >= n {
			return
		}
	}
	return
}
