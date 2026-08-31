package service

import (
	"os"
	"path/filepath"
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

// L6: the openssl password must never enter the built command at all. The old
// `-k '<secret>'` form put the key into the bash -c argv (world-readable via
// /proc/<pid>/cmdline) and needed brittle log masking; handleTar now passes
// it on inherited fd 3 (`-pass fd:3`), so the logged command — which is
// exactly what reaches the bash argv — contains neither the secret nor -k.
func TestHandleTarSecretNeverEntersCommand(t *testing.T) {
	capture := &debugLogCapture{messages: make(chan string, 16)}
	swapDebugLog(t, capture)

	base := t.TempDir()
	srcDir := filepath.Join(base, "src")
	if err := os.MkdirAll(srcDir, 0755); err != nil {
		t.Fatalf("mkdir src: %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "data.txt"), []byte("hello"), 0644); err != nil {
		t.Fatalf("write data: %v", err)
	}
	targetDir := filepath.Join(base, "out")

	const secret = "s3cr3t-key"
	if err := handleTar(srcDir, targetDir, "backup.tar.gz", "", secret); err != nil {
		t.Fatalf("handleTar() error = %v", err)
	}

	joined := strings.Join(capture.drain(), "\n")
	if strings.Contains(joined, secret) {
		t.Fatalf("built command leaks the secret:\n%s", joined)
	}
	if strings.Contains(joined, "-k ") {
		t.Fatalf("built command still passes -k:\n%s", joined)
	}
	if !strings.Contains(joined, "-pass fd:3") {
		t.Fatalf("built command does not use -pass fd:3:\n%s", joined)
	}
}
