package middleware

import (
	"testing"
	"time"
)

func TestCheckIpInCidr(t *testing.T) {
	tests := []struct {
		name    string
		cidr    string
		checkIP string
		want    bool
	}{
		{
			name:    "ipv4 in /24",
			cidr:    "192.168.1.0/24",
			checkIP: "192.168.1.5",
			want:    true,
		},
		{
			name:    "ipv4 outside /24",
			cidr:    "192.168.1.0/24",
			checkIP: "192.168.2.5",
			want:    false,
		},
		{
			name:    "ipv4 in large /8",
			cidr:    "10.0.0.0/8",
			checkIP: "10.0.0.1",
			want:    true,
		},
		{
			name:    "invalid cidr",
			cidr:    "not-a-cidr",
			checkIP: "192.168.1.5",
			want:    false,
		},
		{
			name:    "invalid ip",
			cidr:    "192.168.1.0/24",
			checkIP: "not-an-ip",
			want:    false,
		},
		{
			name:    "ipv6 in /32",
			cidr:    "2001:db8::/32",
			checkIP: "2001:db8::1",
			want:    true,
		},
		{
			name:    "ipv6 outside /32",
			cidr:    "2001:db8::/32",
			checkIP: "2001:db9::1",
			want:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := checkIpInCidr(tt.cidr, tt.checkIP); got != tt.want {
				t.Fatalf("checkIpInCidr(%q, %q) = %v, want %v", tt.cidr, tt.checkIP, got, tt.want)
			}
		})
	}
}

func TestCheckIpInCidrLargeCidrFast(t *testing.T) {
	// Regression test: the old implementation iterated over every IP in the
	// network (16M iterations for a /8), a CPU DoS vector. This must be O(1).
	start := time.Now()
	got := checkIpInCidr("10.0.0.0/8", "10.255.255.255")
	elapsed := time.Since(start)
	if !got {
		t.Fatalf("checkIpInCidr(10.0.0.0/8, 10.255.255.255) = false, want true")
	}
	if elapsed >= time.Millisecond {
		t.Fatalf("checkIpInCidr on /8 took %v, want < 1ms (O(1) lookup)", elapsed)
	}
}
