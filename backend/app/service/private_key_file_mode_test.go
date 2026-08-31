package service

import (
	"os"
	"path/filepath"
	"testing"
)

// TestWritePrivateKeyFilePermission verifies that every private key file the
// panel writes lands with 0600 — including the overwrite case, because
// OpenFile ignores the perm argument for existing files and pre-existing
// 0644 keys must be tightened too (real temp dir write).
func TestWritePrivateKeyFilePermission(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "privkey.pem")

	if err := writePrivateKeyFile(dst, "TEST-PRIVATE-KEY"); err != nil {
		t.Fatalf("writePrivateKeyFile failed: %v", err)
	}
	info, err := os.Stat(dst)
	if err != nil {
		t.Fatalf("stat %s failed: %v", dst, err)
	}
	if got := info.Mode().Perm(); got != privateKeyFileMode {
		t.Fatalf("fresh private key mode = %04o, want %04o", got, privateKeyFileMode)
	}
	content, err := os.ReadFile(dst)
	if err != nil || string(content) != "TEST-PRIVATE-KEY" {
		t.Fatalf("private key content wrong: %q err=%v", content, err)
	}

	// overwrite an existing world-readable key: the wider mode must be fixed
	if err := os.WriteFile(dst, []byte("OLD-OPEN-KEY"), 0644); err != nil {
		t.Fatalf("seed wide-open key failed: %v", err)
	}
	if err := writePrivateKeyFile(dst, "NEW-PRIVATE-KEY"); err != nil {
		t.Fatalf("rewrite private key failed: %v", err)
	}
	info, err = os.Stat(dst)
	if err != nil {
		t.Fatalf("stat after rewrite failed: %v", err)
	}
	if got := info.Mode().Perm(); got != privateKeyFileMode {
		t.Fatalf("pre-existing private key mode = %04o, want %04o (OpenFile ignores perm on existing files)", got, privateKeyFileMode)
	}
	content, err = os.ReadFile(dst)
	if err != nil || string(content) != "NEW-PRIVATE-KEY" {
		t.Fatalf("rewritten content wrong: %q err=%v", content, err)
	}
}

// TestWritePrivateKeyFileCreatesParentWithRestrictedMode checks that a
// missing parent directory is created 0700 instead of a world-readable mode.
func TestWritePrivateKeyFileCreatesParentWithRestrictedMode(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "ssl", "ca.key")

	if err := writePrivateKeyFile(dst, "CA-KEY-SECRET"); err != nil {
		t.Fatalf("writePrivateKeyFile failed: %v", err)
	}
	info, err := os.Stat(filepath.Dir(dst))
	if err != nil {
		t.Fatalf("stat parent dir failed: %v", err)
	}
	if got := info.Mode().Perm(); got != 0700 {
		t.Fatalf("auto-created parent dir mode = %04o, want 0700", got)
	}
	keyInfo, err := os.Stat(dst)
	if err != nil {
		t.Fatalf("stat key failed: %v", err)
	}
	if got := keyInfo.Mode().Perm(); got != privateKeyFileMode {
		t.Fatalf("ca.key mode = %04o, want %04o", got, privateKeyFileMode)
	}
}
