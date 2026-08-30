package toolbox

import (
	"strings"
	"testing"
)

// TestValidateBanIPs is the regression test for the fail2ban command
// injection: each entry is interpolated into
// `fail2ban-client set sshd banip <ips>` and executed through a shell, so
// only strict IP literals may pass. A payload like `1.2.3.4; id` must be
// rejected before it can reach the command line.
func TestValidateBanIPs(t *testing.T) {
	cases := []struct {
		name    string
		ips     []string
		wantErr bool
	}{
		{name: "single ipv4", ips: []string{"1.2.3.4"}, wantErr: false},
		{name: "single ipv6", ips: []string{"::1"}, wantErr: false},
		{name: "expanded ipv6", ips: []string{"2001:db8::1"}, wantErr: false},
		{name: "multiple legal", ips: []string{"1.2.3.4", "2001:db8::1"}, wantErr: false},
		{name: "semicolon injection", ips: []string{"1.2.3.4; id"}, wantErr: true},
		{name: "shell metachar", ips: []string{"1.2.3.4$(id)"}, wantErr: true},
		{name: "backtick injection", ips: []string{"1.2.3.4`id`"}, wantErr: true},
		{name: "pipe injection", ips: []string{"1.2.3.4 | id"}, wantErr: true},
		{name: "ampersand injection", ips: []string{"1.2.3.4 && id"}, wantErr: true},
		{name: "not an ip", ips: []string{"localhost"}, wantErr: true},
		{name: "cidr not allowed", ips: []string{"1.2.3.0/24"}, wantErr: true},
		{name: "mixed legal and malicious", ips: []string{"1.2.3.4", "1.2.3.5;id"}, wantErr: true},
		{name: "empty list", ips: nil, wantErr: false},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateBanIPs(tt.ips)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ValidateBanIPs(%v) = nil error, want rejection", tt.ips)
				}
				if !strings.Contains(err.Error(), "invalid ip address") {
					t.Fatalf("ValidateBanIPs(%v) error = %v, want invalid-ip message", tt.ips, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ValidateBanIPs(%v) rejected legal IPs: %v", tt.ips, err)
			}
		})
	}
}
