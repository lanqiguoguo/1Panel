package http

import (
	"net"
	"testing"
)

// TestIsPublicIP pins the verdict table shared by ValidatePublicURL (entry
// check) and the download dialer's per-connection re-check: loopback, private,
// link-local (incl. the 169.254.169.254 cloud-metadata address) and reserved
// ranges are refused, public addresses are allowed.
func TestIsPublicIP(t *testing.T) {
	rejected := []string{
		"127.0.0.1",       // loopback
		"10.0.0.1",        // private
		"172.16.0.1",      // private
		"192.168.1.1",     // private
		"169.254.1.1",     // link-local
		"169.254.169.254", // cloud metadata
		"0.0.0.0",         // unspecified
		"224.0.0.1",       // multicast
		"::1",             // loopback
		"fc00::1",         // unique local
		"fe80::1",         // link-local
		"ff02::1",         // multicast
	}
	for _, s := range rejected {
		if IsPublicIP(net.ParseIP(s)) {
			t.Errorf("IsPublicIP(%s) = true, want false", s)
		}
	}

	allowed := []string{
		"8.8.8.8",
		"1.1.1.1",
		"2001:4860::8888",
	}
	for _, s := range allowed {
		if !IsPublicIP(net.ParseIP(s)) {
			t.Errorf("IsPublicIP(%s) = false, want true", s)
		}
	}

	if IsPublicIP(nil) {
		t.Error("IsPublicIP(nil) = true, want false")
	}
}
