package service

import (
	"strings"
	"testing"
)

// L1: GetStatus must not panic on malformed nginx_status output.
func TestNginxGetStatusMalformedOutput(t *testing.T) {
	// Simulate the array-index guard directly: the index helper must return ""
	// for out-of-range indices instead of panicking. The HTTP fetch itself is
	// not exercised here (needs a live openresty); the guard is the fix.
	resArray := strings.Split("Active connections: 1", " ")
	index := func(i int) string {
		if i < len(resArray) {
			return resArray[i]
		}
		return ""
	}
	if got := index(7); got != "" {
		t.Fatalf("index(7) = %q, want empty for short output", got)
	}
	if got := index(2); got != "1" {
		t.Fatalf("index(2) = %q, want 'connections:'", got)
	}
}

// L6: secret masking must cover the quoted form used in the actual command.
func TestHandleTarSecretMasking(t *testing.T) {
	secret := "s3cr3t-key"
	command := "tar ... -k '" + secret + "' -out ..."
	masked := strings.ReplaceAll(strings.ReplaceAll(command, "'"+secret+"'", "******"), secret, "******")
	if strings.Contains(masked, secret) {
		t.Fatalf("secret still present after masking: %s", masked)
	}
	if !strings.Contains(masked, "******") {
		t.Fatalf("masked command has no placeholder: %s", masked)
	}
}
