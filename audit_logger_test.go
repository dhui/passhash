package passhash

import (
	"testing"
)

func setupAuditLoggerData(userID UserID, al AuditLogger) int {
	numIters := 5
	for i := 0; i < numIters; i++ {
		al.Log(userID, AuthnSucceeded, emptyIP)
		al.Log(userID, AuthnFailed, emptyIP)
		al.Log(userID, UpgradedKdf, emptyIP)
	}
	return numIters * 3
}

func TestDummyAuditLoggerLog(t *testing.T) {
	al := DummyAuditLogger{}
	userID := UserID(0)
	al.Log(userID, AuthnSucceeded, emptyIP)
}

func TestDummyAuditLoggerLastN(t *testing.T) {
	al := &DummyAuditLogger{}
	userID := UserID(0)
	n := setupAuditLoggerData(userID, al)
	if l := len(al.LastN(userID, n)); l != 0 {
		t.Errorf("DummyAuditLogger has data! Has %d elements", l)
	}
}

func TestDummyAuditLoggerLastNWithTypes(t *testing.T) {
	al := &DummyAuditLogger{}
	userID := UserID(0)
	n := setupAuditLoggerData(userID, al)
	if l := len(al.LastNWithTypes(userID, n, AuthnSucceeded)); l != 0 {
		t.Errorf("DummyAuditLogger has data! Has %d elements", l)
	}
}

func TestMemoryAuditLoggerLog(t *testing.T) {
	al := MemoryAuditLogger{}
	userID := UserID(0)
	al.Log(userID, AuthnSucceeded, emptyIP)
	if l := len(al.allLogs); l != 1 {
		t.Errorf("Have logs for unexpected number of users. Have %d users instead of 1", l)
	}
	if l := len(al.allLogs[userID]); l != 1 {
		t.Errorf("Unexpected number of logs. Have %d instead of 1", l)
	}
}

func TestMemoryAuditLoggerLastNLess(t *testing.T) {
	al := &MemoryAuditLogger{}
	userID := UserID(0)
	n := setupAuditLoggerData(userID, al)
	if l := len(al.allLogs); l != 1 {
		t.Errorf("Have logs for unexpected number of users. Have %d users instead of 1", l)
	}
	lastN := al.LastN(userID, n/2)
	if l := len(lastN); l != n/2 {
		t.Errorf("Did not retrieve expected number of logs. Have %d logs instead of %d", l, n/2)
	}
}

func TestMemoryAuditLoggerLastNEqual(t *testing.T) {
	al := &MemoryAuditLogger{}
	userID := UserID(0)
	n := setupAuditLoggerData(userID, al)
	if l := len(al.allLogs); l != 1 {
		t.Errorf("Have logs for unexpected number of users. Have %d users instead of 1", l)
	}
	lastN := al.LastN(userID, n)
	if l := len(lastN); l != n {
		t.Errorf("Did not retrieve expected number of logs. Have %d logs instead of %d", l, n)
	}
}

func TestMemoryAuditLoggerLastNMore(t *testing.T) {
	al := &MemoryAuditLogger{}
	userID := UserID(0)
	n := setupAuditLoggerData(userID, al)
	if l := len(al.allLogs); l != 1 {
		t.Errorf("Have logs for unexpected number of users. Have %d users instead of 1", l)
	}
	lastN := al.LastN(userID, n*2)
	if l := len(lastN); l != n {
		t.Errorf("Did not retrieve expected number of logs. Have %d logs instead of %d", l, n)
	}
}

func TestMemoryAuditLoggerLastNWithTypesNone(t *testing.T) {
	al := &MemoryAuditLogger{}
	userID := UserID(0)
	n := setupAuditLoggerData(userID, al)
	if l := len(al.allLogs); l != 1 {
		t.Errorf("Have logs for unexpected number of users. Have %d users instead of 1", l)
	}
	lastN := al.LastNWithTypes(userID, n)
	if len(lastN) != 0 {
		t.Errorf("Got %d log entries when no types were specified", len(lastN))
	}
}

func TestMemoryAuditLoggerLastNWithTypesLess(t *testing.T) {
	al := &MemoryAuditLogger{}
	userID := UserID(0)
	n := setupAuditLoggerData(userID, al)
	if l := len(al.allLogs); l != 1 {
		t.Errorf("Have logs for unexpected number of users. Have %d users instead of 1", l)
	}
	lastN := al.LastNWithTypes(userID, (n/3)-3, AuthnSucceeded)
	if l := len(lastN); l != (n/3)-3 {
		t.Errorf("Did not retrieve expected number of logs. Have %d logs instead of %d", l, (n/3)-3)
		t.Log(lastN)
	}
}

func TestMemoryAuditLoggerLastNWithTypesEqual(t *testing.T) {
	al := &MemoryAuditLogger{}
	userID := UserID(0)
	n := setupAuditLoggerData(userID, al)
	if l := len(al.allLogs); l != 1 {
		t.Errorf("Have logs for unexpected number of users. Have %d users instead of 1", l)
	}
	lastN := al.LastNWithTypes(userID, (n / 3), AuthnSucceeded)
	if l := len(lastN); l != n/3 {
		t.Errorf("Did not retrieve expected number of logs. Have %d logs instead of %d", l, n/3)
		t.Log(lastN)
	}
}

func TestMemoryAuditLoggerLastNWithTypesMore(t *testing.T) {
	al := &MemoryAuditLogger{}
	userID := UserID(0)
	n := setupAuditLoggerData(userID, al)
	if l := len(al.allLogs); l != 1 {
		t.Errorf("Have logs for unexpected number of users. Have %d users instead of 1", l)
	}
	lastN := al.LastNWithTypes(userID, n, AuthnSucceeded)
	if l := len(lastN); l != n/3 {
		t.Errorf("Did not retrieve expected number of logs. Have %d logs instead of %d", l, n/3)
		t.Log(lastN)
	}
}
