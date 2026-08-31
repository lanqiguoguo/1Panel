package common

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// TestRandStrSecure verifies length and alphabet guarantees of the
// crypto/rand-backed generator used for security material (EncryptKey,
// JWTSigningKey, ApiKey, initial credentials, security entrance).
func TestRandStrSecure(t *testing.T) {
	for _, n := range []int{0, 1, 16, 32, 128} {
		got := RandStrSecure(n)
		if utf8.RuneCountInString(got) != n {
			t.Fatalf("RandStrSecure(%d) length = %d, want %d", n, utf8.RuneCountInString(got), n)
		}
		for _, r := range got {
			if !strings.ContainsRune(string(letters), r) {
				t.Fatalf("RandStrSecure(%d) produced character %q outside the RandStr alphabet", n, r)
			}
		}
	}

	// EncryptKey/JWTSigningKey are consumed as raw 16-byte AES-128 / HMAC
	// material: the output must be pure ASCII so byte length equals rune
	// length (16 chars == 16 bytes).
	if len(RandStrSecure(16)) != 16 {
		t.Fatal("RandStrSecure(16) byte length != 16")
	}

	// two independent 32-character draws must differ; the collision
	// probability (62^-32) is negligible
	if RandStrSecure(32) == RandStrSecure(32) {
		t.Fatal("RandStrSecure produced identical 32-char outputs, source is not random")
	}
}

func TestComparePanelVersion(t *testing.T) {
	tests := []struct {
		name     string
		version1 string
		version2 string
		want     bool
	}{
		{"equal with different segment count", "1.10", "1.10.0", false},
		{"equal with lts suffix variant", "v1.10.36-lts", "v1.10.36-lts.0", false},
		{"greater", "v1.10.37", "v1.10.36", true},
		{"less", "v1.10.36", "v1.10.37", false},
		{"equal", "v1.10.36", "v1.10.36", false},
		{"lts vs zero segment", "v1.10.36-lts", "v1.10.36", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ComparePanelVersion(tt.version1, tt.version2); got != tt.want {
				t.Errorf("ComparePanelVersion(%q, %q) = %v, want %v", tt.version1, tt.version2, got, tt.want)
			}
		})
	}
}

func TestCompareVersion(t *testing.T) {
	tests := []struct {
		name     string
		version1 string
		version2 string
		want     bool
	}{
		{"equal with different segment count", "1.10", "1.10.0", false},
		{"greater", "1.10.37", "1.10.36", true},
		{"less", "1.10.36", "1.10.37", false},
		{"equal", "1.10.36", "1.10.36", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CompareVersion(tt.version1, tt.version2); got != tt.want {
				t.Errorf("CompareVersion(%q, %q) = %v, want %v", tt.version1, tt.version2, got, tt.want)
			}
		})
	}
}
