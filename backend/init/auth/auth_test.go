package auth

import (
	"testing"
	"time"
)

// TestRecordFailureThreshold guards the fail-count threshold: the IP must not
// be flagged until MaxFailCount consecutive failures have been recorded, and
// the MaxFailCount-th failure flags it.
func TestRecordFailureThreshold(t *testing.T) {
	tracker := NewIPTracker()
	const ip = "192.0.2.10"

	for i := 1; i < MaxFailCount; i++ {
		tracker.RecordFailure(ip)
		if tracker.NeedCaptcha(ip) {
			t.Fatalf("NeedCaptcha() = true after %d failures, want false until %d", i, MaxFailCount)
		}
	}

	tracker.RecordFailure(ip)
	if !tracker.NeedCaptcha(ip) {
		t.Fatalf("NeedCaptcha() = false after %d failures, want true", MaxFailCount)
	}
}

// TestRecordFailureClearRestarts guards that Clear() resets the counter so a
// later failure starts counting from one again.
func TestRecordFailureClearRestarts(t *testing.T) {
	tracker := NewIPTracker()
	const ip = "192.0.2.10"

	tracker.RecordFailure(ip)
	tracker.RecordFailure(ip)
	tracker.Clear(ip)

	tracker.RecordFailure(ip)
	if tracker.NeedCaptcha(ip) {
		t.Fatal("NeedCaptcha() = true after 1 failure following Clear(), want false")
	}

	// The fresh record must still hit the threshold after MaxFailCount failures.
	for i := 1; i < MaxFailCount; i++ {
		tracker.RecordFailure(ip)
	}
	if !tracker.NeedCaptcha(ip) {
		t.Fatalf("NeedCaptcha() = false after %d failures following Clear(), want true", MaxFailCount)
	}
}

// TestRecordFailureExpiry guards that an expired record is dropped: a flagged
// IP regains access once the record expires, and the next failure restarts the
// counter instead of reusing the stale one.
func TestRecordFailureExpiry(t *testing.T) {
	tracker := NewIPTracker()
	const ip = "192.0.2.10"

	for i := 0; i < MaxFailCount; i++ {
		tracker.RecordFailure(ip)
	}
	if !tracker.NeedCaptcha(ip) {
		t.Fatalf("NeedCaptcha() = false after %d failures, want true", MaxFailCount)
	}

	// Age the record past ExpireDuration.
	tracker.mu.Lock()
	tracker.records[ip].LastUpdate = time.Now().Add(-ExpireDuration - time.Minute)
	tracker.mu.Unlock()

	if tracker.NeedCaptcha(ip) {
		t.Fatal("NeedCaptcha() = true for an expired record, want false")
	}

	// The next failure must restart counting from one.
	tracker.RecordFailure(ip)
	if tracker.NeedCaptcha(ip) {
		t.Fatal("NeedCaptcha() = true after 1 failure on an expired record, want false")
	}
	for i := 1; i < MaxFailCount; i++ {
		tracker.RecordFailure(ip)
	}
	if !tracker.NeedCaptcha(ip) {
		t.Fatalf("NeedCaptcha() = false after %d failures on a fresh record, want true", MaxFailCount)
	}
}

// TestSetNeedCaptcha guards the immediate-lock helper: it flags the IP right
// away regardless of the fail count.
func TestSetNeedCaptcha(t *testing.T) {
	tracker := NewIPTracker()
	const ip = "192.0.2.10"

	tracker.RecordFailure(ip)
	if tracker.NeedCaptcha(ip) {
		t.Fatal("NeedCaptcha() = true after 1 failure, want false")
	}

	tracker.SetNeedCaptcha(ip)
	if !tracker.NeedCaptcha(ip) {
		t.Fatal("NeedCaptcha() = false after SetNeedCaptcha(), want true")
	}

	tracker.Clear(ip)
	if tracker.NeedCaptcha(ip) {
		t.Fatal("NeedCaptcha() = true after Clear(), want false")
	}
}
