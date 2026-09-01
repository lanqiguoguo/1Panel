package service

import "testing"

// TestValidHostEntry covers the /etc/hosts entry whitelist applied by
// UpdateHosts: both parts must stay a single un-commented token so a crafted
// value cannot inject new lines or fields into /etc/hosts.
func TestValidHostEntry(t *testing.T) {
	valid := []struct{ ip, host string }{
		{"192.168.1.10", "myhost"},
		{"127.0.0.1", "localhost"},
		{"::1", "ip6-localhost"},
		{"fe80::1", "router.lan"},
		{"10.0.0.1", "a_b-c.d"},          // hostname charset incl. separators
		{"10.0.0.2", "host.alias.local"}, // multi-label style name
	}
	invalid := []struct{ ip, host string }{
		{"", "host"},                          // empty ip
		{"192.168.1.1", ""},                   // empty host
		{"192.168.1.1\n0.0.0.0 evil", "host"}, // newline injection in ip
		{"192.168.1.1", "host\n0.0.0.0 evil"}, // newline injection in host
		{"192.168.1.1\r", "host"},             // carriage return
		{"192.168.1.1", "host\tx"},            // tab (extra field)
		{"192.168.1.1", "host x"},             // space (extra alias injection)
		{"192.168.1.1", "host#comment"},       // comment-out via '#'
		{"#192.168.1.1", "host"},              // commented ip
		{"192.168.1.1; rm -rf /", "host"},     // shell-ish payload
		{"not an ip at all!", "host"},         // non-address ip
		{"192.168.1.1", "host\n#another"},     // newline + comment
	}

	for _, tt := range valid {
		if !validHostEntry(tt.ip, tt.host) {
			t.Errorf("validHostEntry(%q, %q) = false, want true", tt.ip, tt.host)
		}
	}
	for _, tt := range invalid {
		if validHostEntry(tt.ip, tt.host) {
			t.Errorf("validHostEntry(%q, %q) = true, want false", tt.ip, tt.host)
		}
	}
}

// TestValidDNSServer covers the resolv.conf nameserver whitelist applied by
// updateDNS: a nameserver value must remain a single address token so a
// newline cannot append attacker-controlled resolv.conf directives.
func TestValidDNSServer(t *testing.T) {
	valid := []string{
		"8.8.8.8",
		"114.114.114.114",
		"2001:4860:4860::8888",
		"fe80::1",
	}
	invalid := []string{
		"",                            // empty
		"8.8.8.8\nnameserver 0.0.0.0", // newline directive injection
		"8.8.8.8\rrotate",             // carriage return injection
		"8.8.8.8 options timeout:1",   // space (extra directive)
		"8.8.8.8#comment",             // comment
		"$(id)",                       // command substitution payload
		"1.2.3.4; rm -rf /",           // shell-ish payload
		"not-an-address",              // hostname-like garbage
	}

	for _, s := range valid {
		if !validDNSServer(s) {
			t.Errorf("validDNSServer(%q) = false, want true", s)
		}
	}
	for _, s := range invalid {
		if validDNSServer(s) {
			t.Errorf("validDNSServer(%q) = true, want false", s)
		}
	}
}
