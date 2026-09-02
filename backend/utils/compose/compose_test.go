package compose

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

// TestExecAppliesTimeout verifies that compose invocations are bounded: a
// command that hangs past the (shrunk) timeout is killed and reported, so a
// wedged docker daemon can never hang a panel API request forever.
func TestExecAppliesTimeout(t *testing.T) {
	old := composeOpTimeout
	composeOpTimeout = 300 * time.Millisecond
	defer func() { composeOpTimeout = old }()

	start := time.Now()
	_, err := exec("sleep 5")
	if err == nil {
		t.Fatal("exec of a hanging command should time out")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("timeout took %v, expected ~300ms", elapsed)
	}
	if !strings.Contains(err.Error(), "timeout") && !strings.Contains(strings.ToLower(err.Error()), "time") {
		t.Logf("timeout error: %v", err)
	}
}

func TestCommandCaching(t *testing.T) {
	// simulate a host where the v2 plugin probe succeeded
	mu.Lock()
	composeCmdV2, resolved = true, true
	mu.Unlock()
	if got := Command(); got != "docker compose" {
		t.Fatalf("v2 host: got %q", got)
	}
	// simulate legacy-only host
	mu.Lock()
	composeCmdV2, resolved = false, true
	mu.Unlock()
	if got := Command(); got != "docker-compose" {
		t.Fatalf("legacy host: got %q", got)
	}
}

func TestCommandFormat(t *testing.T) {
	mu.Lock()
	composeCmdV2, resolved = true, true
	mu.Unlock()
	// spot-check the composed command strings via the exported funcs is not
	// possible without executing docker; instead verify Command() wiring used
	// by every op stays consistent
	c := Command()
	for _, want := range []string{"docker", "compose"} {
		if !containsAll(c, want) {
			t.Fatalf("command %q missing %q", c, want)
		}
	}
}

func TestCommandArgsCaching(t *testing.T) {
	// v2 plugin: base binary "docker" + ["compose", ...] args
	mu.Lock()
	composeCmdV2, resolved = true, true
	mu.Unlock()
	if got := CommandBase(); got != "docker" {
		t.Fatalf("v2 host: got base %q", got)
	}
	if got := CommandArgs(); !reflect.DeepEqual(got, []string{"compose"}) {
		t.Fatalf("v2 host: got args %v", got)
	}
	// legacy binary: base "docker-compose", no extra args
	mu.Lock()
	composeCmdV2, resolved = false, true
	mu.Unlock()
	if got := CommandBase(); got != "docker-compose" {
		t.Fatalf("legacy host: got base %q", got)
	}
	if got := CommandArgs(); len(got) != 0 {
		t.Fatalf("legacy host: got args %v", got)
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
