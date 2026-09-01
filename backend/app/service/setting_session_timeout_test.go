package service

import "testing"

// TestSettingUpdateSessionTimeoutValidation covers the pre-write gate on the
// SessionTimeout key: a non-numeric, non-positive or absurdly large value must
// be refused so a bad submit cannot persist a self-lockout TTL.
func TestSettingUpdateSessionTimeoutValidation(t *testing.T) {
	setupSettingUpdateTest(t)
	u := &SettingService{}

	invalid := []string{
		"",           // empty
		"abc",        // non-numeric
		"0",          // expires sessions immediately
		"-1",         // negative TTL
		"1.5",        // not an integer
		"1000001",    // beyond the accepted ceiling
		"' OR 1=1--", // injection-ish payload
	}
	for _, v := range invalid {
		if err := u.Update("SessionTimeout", v); err == nil {
			t.Errorf("Update(SessionTimeout, %q) = nil error, want rejection", v)
		}
	}

	// Boundary values inside the accepted range must still persist.
	for _, v := range []string{"1", "60", "86400", "1000000"} {
		if err := u.Update("SessionTimeout", v); err != nil {
			t.Errorf("Update(SessionTimeout, %q) returned error: %v", v, err)
		}
	}
}
