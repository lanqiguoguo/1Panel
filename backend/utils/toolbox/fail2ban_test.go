package toolbox

import (
	"strings"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/sirupsen/logrus"
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

// TestReBanRollbackFiltersIllegalIPs is the regression test for the rollback
// path of ReBanIPs: the re-ban list comes from ListBanned() output and used to
// reach `fail2ban-client set sshd banip <ips>` unvalidated. The rollback is
// best-effort, so every legal IP must be kept (order preserved) and every
// illegal entry filtered out instead of failing the whole rollback.
func TestReBanRollbackFiltersIllegalIPs(t *testing.T) {
	// filterBanIPs logs skipped entries through the global logger, which is
	// only wired up in the server main; use a plain logger for the test.
	origLog := global.LOG
	global.LOG = logrus.New()
	t.Cleanup(func() { global.LOG = origLog })

	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{
			name: "legal list fully kept",
			in:   []string{"1.2.3.4", "5.6.7.8", "2001:db8::1", "::1"},
			want: []string{"1.2.3.4", "5.6.7.8", "2001:db8::1", "::1"},
		},
		{
			name: "illegal entries filtered",
			in:   []string{"1.2.3.4", "1.2.3.5;id", "localhost", "5.6.7.8", "1.2.3.0/24", "1.2.3.6$(id)", "1.2.3.7`id`", "1.2.3.8 | id", "1.2.3.9 && id"},
			want: []string{"1.2.3.4", "5.6.7.8"},
		},
		{
			name: "only illegal entries left empty",
			in:   []string{"1.2.3.4;id", "not-an-ip", "10.0.0.0/8"},
			want: []string{},
		},
		{
			name: "empty list stays empty",
			in:   nil,
			want: []string{},
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got := filterBanIPs(tt.in)
			if len(got) != len(tt.want) {
				t.Fatalf("filterBanIPs(%v) = %v, want %v", tt.in, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("filterBanIPs(%v) = %v, want %v (order/content mismatch at %d)", tt.in, got, tt.want, i)
				}
			}
			for _, item := range got {
				if strings.ContainsAny(item, ";|&`$ ") {
					t.Fatalf("filterBanIPs kept a dangerous entry: %q", item)
				}
			}
		})
	}
}
