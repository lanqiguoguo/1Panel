package db

import (
	"os"
	"path/filepath"
	"testing"
)

// TestSecureDBFileTightensPermissions is the regression test for the
// world-readable 1Panel.db: the sqlite database holds credentials in the
// settings table, so it must be root-only 0600, and the tightening must be
// idempotent across restarts.
func TestSecureDBFileTightensPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "1Panel.db")
	if err := os.WriteFile(path, []byte("sqlite"), 0644); err != nil {
		t.Fatalf("seed db file: %v", err)
	}

	if err := secureDBFile(path); err != nil {
		t.Fatalf("secureDBFile failed: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat db file: %v", err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("db file mode = %v, want 0600", got)
	}

	// Idempotent: re-running on an already private file must succeed.
	if err := secureDBFile(path); err != nil {
		t.Fatalf("second secureDBFile failed: %v", err)
	}
	info, err = os.Stat(path)
	if err != nil {
		t.Fatalf("stat db file after second run: %v", err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("db file mode after second run = %v, want 0600", got)
	}
}
