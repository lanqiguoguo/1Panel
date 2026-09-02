package service

import (
	"os"
	"path/filepath"
	"testing"
)

// TestWriteFileAtomicWithBackup checks the atomic persist helper: content and
// 0640 permissions land on the target path, the previous bytes come back, and
// a pre-existing missing file (nil old content) is a valid state.
func TestWriteFileAtomicWithBackup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "jail.local")

	// fresh file: old state is nil, new content lands
	old, err := writeFileAtomicWithBackup(path, []byte("bantime = 100\n"))
	if err != nil {
		t.Fatalf("write on missing file: %v", err)
	}
	if old != nil {
		t.Fatalf("expected nil old content for a missing file, got %q", old)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat after write: %v", err)
	}
	if info.Mode().Perm() != 0640 {
		t.Fatalf("mode = %v, want 0640", info.Mode().Perm())
	}

	// overwrite an existing file: old content is returned
	old, err = writeFileAtomicWithBackup(path, []byte("bantime = 200\n"))
	if err != nil {
		t.Fatalf("overwrite: %v", err)
	}
	if string(old) != "bantime = 100\n" {
		t.Fatalf("old content = %q, want %q", old, "bantime = 100\n")
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read after overwrite: %v", err)
	}
	if string(content) != "bantime = 200\n" {
		t.Fatalf("content = %q, want %q", content, "bantime = 200\n")
	}
}

// TestRestoreFileContent checks the file-level rollback used by the fail2ban
// conf updates: an existing file is restored byte-for-byte and a file created
// from a missing original (nil old content) is removed again.
func TestRestoreFileContent(t *testing.T) {
	dir := t.TempDir()

	// existing original -> content restored
	path := filepath.Join(dir, "a.conf")
	if err := os.WriteFile(path, []byte("original"), 0640); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := restoreFileContent(path, []byte("original")); err != nil {
		t.Fatalf("restore content: %v", err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read after restore: %v", err)
	}
	if string(content) != "original" {
		t.Fatalf("restored content = %q, want %q", content, "original")
	}

	// missing original -> the file the failed update created is removed
	created := filepath.Join(dir, "b.conf")
	if err := os.WriteFile(created, []byte("new"), 0640); err != nil {
		t.Fatalf("seed created: %v", err)
	}
	if err := restoreFileContent(created, nil); err != nil {
		t.Fatalf("restore missing original: %v", err)
	}
	if _, err := os.Stat(created); !os.IsNotExist(err) {
		t.Fatalf("file should have been removed, stat err = %v", err)
	}

	// nil old content on an already-missing file is a no-op, not an error
	if err := restoreFileContent(filepath.Join(dir, "never-existed.conf"), nil); err != nil {
		t.Fatalf("restore on missing file should be a no-op, got: %v", err)
	}

	// restore failure (read-only dir) surfaces the error; skipped under root,
	// whose CAP_DAC_OVERRIDE bypasses directory permissions.
	if os.Geteuid() == 0 {
		return
	}
	roDir := filepath.Join(dir, "ro")
	if err := os.MkdirAll(roDir, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	roFile := filepath.Join(roDir, "c.conf")
	if err := os.WriteFile(roFile, []byte("x"), 0640); err != nil {
		t.Fatalf("seed ro: %v", err)
	}
	if err := os.Chmod(roDir, 0500); err != nil {
		t.Fatalf("chmod ro dir: %v", err)
	}
	defer os.Chmod(roDir, 0700)
	if err := restoreFileContent(roFile, []byte("y")); err == nil {
		t.Fatalf("expected restore failure on read-only dir")
	}
}
