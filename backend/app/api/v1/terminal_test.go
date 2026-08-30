package v1

import "testing"

// TestKillablePid guards killBash's pid gate: the pid value reaching
// kill -9 comes from `docker top` output. It must be a plain positive
// integer so it can only be passed to kill(1) as a parameter; anything
// else (shell metacharacters, negative values, garbage) is refused and
// can never be interpolated into a shell command line.
func TestKillablePid(t *testing.T) {
	cases := []struct {
		name string
		pid  string
		want bool
	}{
		{"normal pid", "1234", true},
		{"zero is not a process", "0", false},
		{"negative pid", "-5", false},
		{"plus sign", "+5", false},
		{"leading zero", "0123", true},
		{"semicolon injection", "1; id", false},
		{"command substitution", "1$(id)", false},
		{"pipe injection", "1 | id", false},
		{"ampersand injection", "1 & id", false},
		{"backtick injection", "1`id`", false},
		{"whitespace padding", " 123", false},
		{"non numeric", "abc", false},
		{"decimal point", "1.5", false},
		{"empty", "", false},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if got := killablePid(tt.pid); got != tt.want {
				t.Errorf("killablePid(%q) = %v, want %v", tt.pid, got, tt.want)
			}
		})
	}
}
