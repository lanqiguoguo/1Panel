package compose

import "testing"

func TestCommandCaching(t *testing.T) {
	// simulate a host where the v2 plugin probe succeeded
	mu.Lock()
	composeCmdV2, resolved = true, true
	mu.Unlock()
	if got := command(); got != "docker compose" {
		t.Fatalf("v2 host: got %q", got)
	}
	// simulate legacy-only host
	mu.Lock()
	composeCmdV2, resolved = false, true
	mu.Unlock()
	if got := command(); got != "docker-compose" {
		t.Fatalf("legacy host: got %q", got)
	}
}

func TestCommandFormat(t *testing.T) {
	mu.Lock()
	composeCmdV2, resolved = true, true
	mu.Unlock()
	// spot-check the composed command strings via the exported funcs is not
	// possible without executing docker; instead verify command() wiring used
	// by every op stays consistent
	c := command()
	for _, want := range []string{"docker", "compose"} {
		if !containsAll(c, want) {
			t.Fatalf("command %q missing %q", c, want)
		}
	}
}

func containsAll(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
