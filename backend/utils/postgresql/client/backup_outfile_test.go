package client

import (
	"os"
	"path/filepath"
	"testing"
)

// TestBackupOutFileModesRegression pins the M6 fix for the pg dump path: the
// output file must be 0600 (not 0755) and the target directory 0750 (not
// os.ModePerm 0777), because the dump holds live database content while it
// is being written.
func TestBackupOutFileModesRegression(t *testing.T) {
	base := t.TempDir()
	targetDir := filepath.Join(base, "database", "postgresql", "local-pg", "pg_db")
	outPath, f, err := backupOutFile(targetDir, "pg_db_20260902.sql.gz")
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

// TestBackupOutFileSurvivesTruncate covers the remote pg backup path, where
// the file is created up front (0600) and later truncated by the bash
// redirect of remoteBackupCommand (`... > file`), which does not reset the
// mode: the streamed dump must stay 0600.
func TestBackupOutFileSurvivesTruncate(t *testing.T) {
	dir := t.TempDir()
	p, f, err := backupOutFile(dir, "dump.sql")
	if err != nil {
		t.Fatalf("backupOutFile failed: %v", err)
	}
	_ = f.Close()
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

// TestBackupOutFileRejectsTraversal guards the pg helper against path
// traversal in the file name.
func TestBackupOutFileRejectsTraversal(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"../escape.sql.gz", "a/../../escape.sql.gz", "", "/abs.sql.gz"} {
		if _, _, err := backupOutFile(dir, name); err == nil {
			t.Fatalf("backupOutFile(%q) = nil error, want rejection", name)
		}
	}
}
