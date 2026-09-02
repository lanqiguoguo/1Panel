package client

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestBackupOutFileModesRegression pins the M6 fix: the dump output file
// must be created 0600 (not 0755, which made the live database dump
// world-readable while it was being written) and the target directory 0750
// (not os.ModePerm 0777).
func TestBackupOutFileModesRegression(t *testing.T) {
	base := t.TempDir()
	targetDir := filepath.Join(base, "database", "mysql", "local-mysql", "panel_db")
	outPath, f, err := backupOutFile(targetDir, "panel_db_20260902.sql.gz")
	if err != nil {
		t.Fatalf("backupOutFile failed: %v", err)
	}
	defer f.Close()

	fi, err := os.Stat(outPath)
	if err != nil {
		t.Fatalf("stat output file: %v", err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Fatalf("output file mode = %v, want 0600", fi.Mode().Perm())
	}
	di, err := os.Stat(targetDir)
	if err != nil {
		t.Fatalf("stat target dir: %v", err)
	}
	if di.Mode().Perm() != 0750 {
		t.Fatalf("target dir mode = %v, want 0750", di.Mode().Perm())
	}
}

// TestBackupOutFileSurvivesTruncate covers the remote pg backup path: the
// file is created up front (0600) and later truncated by the shell redirect
// in remoteBackupCommand (`... > file`), which does NOT reset the mode. The
// dump content streamed by that redirect must therefore stay 0600.
func TestBackupOutFileSurvivesTruncate(t *testing.T) {
	dir := t.TempDir()
	p, f, err := backupOutFile(dir, "dump.sql")
	if err != nil {
		t.Fatalf("backupOutFile failed: %v", err)
	}
	_ = f.Close()
	// Simulate the bash `> file` truncation of remoteBackupCommand.
	tf, err := os.OpenFile(p, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		t.Fatalf("open for truncate: %v", err)
	}
	_, _ = tf.WriteString("PGDMP data")
	_ = tf.Close()
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Mode().Perm() != 0600 {
		t.Fatalf("file mode after truncate = %v, want 0600", fi.Mode().Perm())
	}
	_ = os.Remove(p)
}

// TestBackupOutFileRejectsTraversal guards the helper against path traversal
// in fileName: no parent directory may be reached through the dump file.
func TestBackupOutFileRejectsTraversal(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"../escape.sql.gz", "a/../../escape.sql.gz"} {
		_, _, err := backupOutFile(dir, name)
		if err == nil {
			t.Fatalf("backupOutFile(%q) = nil error, want rejection", name)
		}
		if strings.Contains(err.Error(), "escape.sql.gz") {
			// open of ../escape.sql.gz would succeed; the guard must have fired first
			if _, statErr := os.Stat(filepath.Join(dir, "..", "escape.sql.gz")); statErr == nil {
				t.Fatalf("backupOutFile(%q) escaped the target dir", name)
			}
		}
	}
}
