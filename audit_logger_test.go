package passhash_test

import (
	"testing"
)

import (
	"github.com/dhui/passhash"
)

// setupAuditLoggerTestData logs test data to the given AuditLogger
func setupAuditLoggerTestData(userID passhash.UserID, al passhash.AuditLogger) int { // nolint: unparam
	numIters := 5
	for i := 0; i < numIters; i++ {
		al.Log(userID, passhash.AuthnSucceeded, passhash.EmptyIP)
		al.Log(userID, passhash.AuthnFailed, passhash.EmptyIP)
		al.Log(userID, passhash.UpgradedKdf, passhash.EmptyIP)
	}
	return numIters * 3
}

func TestDummyAuditLoggerLog(t *testing.T) {
	al := passhash.DummyAuditLogger{}
	userID := passhash.UserID(0)
	al.Log(userID, passhash.AuthnSucceeded, passhash.EmptyIP)
}

func TestDummyAuditLoggerLastN(t *testing.T) {
	al := &passhash.DummyAuditLogger{}
	userID := passhash.UserID(0)
	n := setupAuditLoggerTestData(userID, al)
	if l := len(al.LastN(userID, n)); l != 0 {
		t.Errorf("DummyAuditLogger has data! Has %d elements", l)
	}
}

func TestDummyAuditLoggerLastNWithTypes(t *testing.T) {
	al := &passhash.DummyAuditLogger{}
	userID := passhash.UserID(0)
	n := setupAuditLoggerTestData(userID, al)
	if l := len(al.LastNWithTypes(userID, n, passhash.AuthnSucceeded)); l != 0 {
		t.Errorf("DummyAuditLogger has data! Has %d elements", l)
	}
}

func TestMemoryAuditLoggerLog(t *testing.T) {
	al := passhash.MemoryAuditLogger{}
	userID := passhash.UserID(0)
	al.Log(userID, passhash.AuthnSucceeded, passhash.EmptyIP)
	if l := len(al.LastN(userID, 10)); l != 1 {
		t.Errorf("Unexpected number of logs. Have %d instead of 1", l)
	}
}

func TestMemoryAuditLoggerLastNLess(t *testing.T) {
	al := &passhash.MemoryAuditLogger{}
	userID := passhash.UserID(0)
	n := setupAuditLoggerTestData(userID, al)
	lastN := al.LastN(userID, n/2)
	if l := len(lastN); l != n/2 {
		t.Errorf("Did not retrieve expected number of logs. Have %d logs instead of %d", l, n/2)
	}
}

func TestMemoryAuditLoggerLastNEqual(t *testing.T) {
	al := &passhash.MemoryAuditLogger{}
	userID := passhash.UserID(0)
	n := setupAuditLoggerTestData(userID, al)
	lastN := al.LastN(userID, n)
	if l := len(lastN); l != n {
		t.Errorf("Did not retrieve expected number of logs. Have %d logs instead of %d", l, n)
	}
}

func TestMemoryAuditLoggerLastNMore(t *testing.T) {
	al := &passhash.MemoryAuditLogger{}
	userID := passhash.UserID(0)
	n := setupAuditLoggerTestData(userID, al)
	lastN := al.LastN(userID, n*2)
	if l := len(lastN); l != n {
		t.Errorf("Did not retrieve expected number of logs. Have %d logs instead of %d", l, n)
	}
}

func TestMemoryAuditLoggerLastNWithTypesNone(t *testing.T) {
	al := &passhash.MemoryAuditLogger{}
	userID := passhash.UserID(0)
	n := setupAuditLoggerTestData(userID, al)
	lastN := al.LastNWithTypes(userID, n)
	if len(lastN) != 0 {
		t.Errorf("Got %d log entries when no types were specified", len(lastN))
	}
}

func TestMemoryAuditLoggerLastNWithTypesLess(t *testing.T) {
	al := &passhash.MemoryAuditLogger{}
	userID := passhash.UserID(0)
	n := setupAuditLoggerTestData(userID, al)
	lastN := al.LastNWithTypes(userID, (n/3)-3, passhash.AuthnSucceeded)
	if l := len(lastN); l != (n/3)-3 {
		t.Errorf("Did not retrieve expected number of logs. Have %d logs instead of %d", l, (n/3)-3)
		t.Log(lastN)
	}
}

func TestMemoryAuditLoggerLastNWithTypesEqual(t *testing.T) {
	al := &passhash.MemoryAuditLogger{}
	userID := passhash.UserID(0)
	n := setupAuditLoggerTestData(userID, al)
	lastN := al.LastNWithTypes(userID, (n / 3), passhash.AuthnSucceeded)
	if l := len(lastN); l != n/3 {
		t.Errorf("Did not retrieve expected number of logs. Have %d logs instead of %d", l, n/3)
		t.Log(lastN)
	}
}

func TestMemoryAuditLoggerLastNWithTypesMore(t *testing.T) {
	al := &passhash.MemoryAuditLogger{}
	userID := passhash.UserID(0)
	n := setupAuditLoggerTestData(userID, al)
	lastN := al.LastNWithTypes(userID, n, passhash.AuthnSucceeded)
	if l := len(lastN); l != n/3 {
		t.Errorf("Did not retrieve expected number of logs. Have %d logs instead of %d", l, n/3)
		t.Log(lastN)
	}
}
