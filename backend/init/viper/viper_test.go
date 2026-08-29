package viper

import (
	"os"
	"path"
	"testing"
)

func TestLoadInitialPasswordRequiresRootOnlyFile(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root ownership is part of the production file contract")
	}

	baseDir := t.TempDir()
	secretDir := path.Join(baseDir, "1panel", "conf")
	if err := os.MkdirAll(secretDir, 0755); err != nil {
		t.Fatal(err)
	}
	secretPath := path.Join(secretDir, "initial-password")
	if err := os.WriteFile(secretPath, []byte("secret-password\n"), 0600); err != nil {
		t.Fatal(err)
	}

	got, err := loadInitialPassword(baseDir)
	if err != nil {
		t.Fatalf("loadInitialPassword returned error: %v", err)
	}
	if got != "secret-password" {
		t.Fatalf("loadInitialPassword returned %q, want %q", got, "secret-password")
	}

	if err := os.Chmod(secretPath, 0640); err != nil {
		t.Fatal(err)
	}
	if _, err := loadInitialPassword(baseDir); err == nil {
		t.Fatal("loadInitialPassword accepted a group-readable secret")
	}
}

func TestCleanupInitialPassword(t *testing.T) {
	baseDir := t.TempDir()
	secretDir := path.Join(baseDir, "1panel", "conf")
	if err := os.MkdirAll(secretDir, 0700); err != nil {
		t.Fatal(err)
	}
	secretPath := path.Join(secretDir, "initial-password")
	if err := os.WriteFile(secretPath, []byte("secret-password\n"), 0600); err != nil {
		t.Fatal(err)
	}

	if err := CleanupInitialPassword(baseDir); err != nil {
		t.Fatalf("CleanupInitialPassword returned error: %v", err)
	}
	if _, err := os.Stat(secretPath); !os.IsNotExist(err) {
		t.Fatalf("secret file still exists or stat failed: %v", err)
	}
	if err := CleanupInitialPassword(baseDir); err != nil {
		t.Fatalf("cleanup should be idempotent: %v", err)
	}
}

func TestEnsureExistingDatabaseRejectsUninitializedFile(t *testing.T) {
	baseDir := t.TempDir()
	dbDir := path.Join(baseDir, "1panel", "db")
	if err := os.MkdirAll(dbDir, 0700); err != nil {
		t.Fatal(err)
	}
	dbPath := path.Join(dbDir, "1Panel.db")
	if err := os.WriteFile(dbPath, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := ensureExistingDatabase(baseDir); err == nil {
		t.Fatal("empty database file was accepted as an initialized panel")
	}
	if err := os.WriteFile(dbPath, []byte("sqlite"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := ensureExistingDatabase(baseDir); err != nil {
		t.Fatalf("initialized database file was rejected: %v", err)
	}
}
