package v1

import (
	"testing"

	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/1Panel-dev/1Panel/backend/init/auth"
)

// TestMFALoginAllowed guards MFA brute-force rate limiting: once an IP
// accumulates enough failures in the shared IPTracker (the same counter the
// normal login path uses), further MFA attempts must be refused until the
// flag is cleared or expires.
func TestMFALoginAllowed(t *testing.T) {
	original := global.IPTracker
	global.IPTracker = auth.NewIPTracker()
	defer func() { global.IPTracker = original }()

	const ip = "192.0.2.10"

	if !mfaLoginAllowed(ip) {
		t.Fatal("mfaLoginAllowed() = false for an unknown IP, want true")
	}

	for i := 0; i < auth.MaxFailCount; i++ {
		global.IPTracker.RecordFailure(ip)
	}
	if mfaLoginAllowed(ip) {
		t.Fatal("mfaLoginAllowed() = true for a flagged IP, want false")
	}

	// A different, unflagged IP must still be allowed.
	const otherIP = "192.0.2.11"
	if !mfaLoginAllowed(otherIP) {
		t.Fatal("mfaLoginAllowed() = false for an unflagged IP, want true")
	}

	// Clearing the flag must restore access.
	global.IPTracker.Clear(ip)
	if !mfaLoginAllowed(ip) {
		t.Fatal("mfaLoginAllowed() = false after Clear(), want true")
	}
}
