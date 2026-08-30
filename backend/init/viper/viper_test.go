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

func TestLoadOptionalParamFrom(t *testing.T) {
	t.Run("reads value from control script", func(t *testing.T) {
		path := writeControlScript(t, "BASE_DIR=/opt\nORIGINAL_PASSWORD=abc123\nLANGUAGE=zh\n")
		if got := loadOptionalParamFrom(path, "ORIGINAL_PASSWORD"); got != "abc123" {
			t.Fatalf("loadOptionalParamFrom returned %q, want %q", got, "abc123")
		}
	})

	t.Run("value containing equals sign is preserved", func(t *testing.T) {
		path := writeControlScript(t, "ORIGINAL_PASSWORD=a=b\n")
		if got := loadOptionalParamFrom(path, "ORIGINAL_PASSWORD"); got != "a=b" {
			t.Fatalf("loadOptionalParamFrom returned %q, want %q", got, "a=b")
		}
	})

	t.Run("missing key returns empty string", func(t *testing.T) {
		path := writeControlScript(t, "BASE_DIR=/opt\nLANGUAGE=zh\n")
		if got := loadOptionalParamFrom(path, "ORIGINAL_PASSWORD"); got != "" {
			t.Fatalf("loadOptionalParamFrom returned %q, want %q", got, "")
		}
	})

	t.Run("missing file returns empty string", func(t *testing.T) {
		path := path.Join(t.TempDir(), "does-not-exist")
		if got := loadOptionalParamFrom(path, "ORIGINAL_PASSWORD"); got != "" {
			t.Fatalf("loadOptionalParamFrom returned %q, want %q", got, "")
		}
	})

	t.Run("multiline script with trailing newline parses correctly", func(t *testing.T) {
		path := writeControlScript(t, "BASE_DIR=/opt\nORIGINAL_PASSWORD=abc123\nLANGUAGE=zh\n")
		// Multiple reads confirm no state leakage and stable parsing.
		for i := 0; i < 2; i++ {
			if got := loadOptionalParamFrom(path, "ORIGINAL_PASSWORD"); got != "abc123" {
				t.Fatalf("loadOptionalParamFrom returned %q, want %q", got, "abc123")
			}
		}
	})

	t.Run("other key lines do not interfere", func(t *testing.T) {
		path := writeControlScript(t, "ORIGINAL_PASSWORD=abc123\nORIGINAL_USERNAME=admin\nORIGINAL_PASSWORDX=evil\n")
		if got := loadOptionalParamFrom(path, "ORIGINAL_PASSWORD"); got != "abc123" {
			t.Fatalf("loadOptionalParamFrom returned %q, want %q", got, "abc123")
		}
		if got := loadOptionalParamFrom(path, "ORIGINAL_USERNAME"); got != "admin" {
			t.Fatalf("loadOptionalParamFrom returned %q, want %q", got, "admin")
		}
	})
}

func writeControlScript(t *testing.T, content string) string {
	t.Helper()
	path := path.Join(t.TempDir(), "1pctl")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
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
