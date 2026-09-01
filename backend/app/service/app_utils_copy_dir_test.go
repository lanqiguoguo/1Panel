package service

import (
	"os"
	"path/filepath"
	"testing"
)

// seedAppDetailDir creates srcDir with the layout of an extracted app detail
// package: top-level files, a nested subdirectory and an entry whose name
// carries a space (legal in file names, previously handled by the shell glob).
func seedAppDetailDir(t *testing.T) string {
	t.Helper()
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "docker-compose.yml"), []byte("new"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "config file with spaces.env"), []byte("space"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(src, "scripts", "nested"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "scripts", "upgrade.sh"), []byte("echo up"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "scripts", "nested", "deep.txt"), []byte("deep"), 0644); err != nil {
		t.Fatal(err)
	}
	return src
}

// TestCopyDirContentNoClobberAndRecursion covers the semantics the replaced
// `cp -rn <srcDir>/* <dstDir> || true` provided: existing destination files
// are NOT overwritten (-n), new files land, subdirectories are copied
// recursively, and the call never fails the upgrade flow.
func TestCopyDirContentNoClobberAndRecursion(t *testing.T) {
	src := seedAppDetailDir(t)
	dst := t.TempDir()

	// pre-existing destination files that must survive untouched
	if err := os.WriteFile(filepath.Join(dst, "docker-compose.yml"), []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dst, "keep.txt"), []byte("keep"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := copyDirContent(src, dst); err != nil {
		t.Fatalf("copyDirContent failed: %v", err)
	}

	// -n semantics: pre-existing file not overwritten
	got, err := os.ReadFile(filepath.Join(dst, "docker-compose.yml"))
	if err != nil {
		t.Fatalf("read copied compose failed: %v", err)
	}
	if string(got) != "old" {
		t.Errorf("existing destination file was overwritten: got %q, want %q", got, "old")
	}
	// new file copied
	got, err = os.ReadFile(filepath.Join(dst, "config file with spaces.env"))
	if err != nil {
		t.Fatalf("read copied file with spaces failed: %v", err)
	}
	if string(got) != "space" {
		t.Errorf("new file content = %q, want %q", got, "space")
	}
	// unrelated pre-existing file untouched
	got, err = os.ReadFile(filepath.Join(dst, "keep.txt"))
	if err != nil {
		t.Fatalf("read keep.txt failed: %v", err)
	}
	if string(got) != "keep" {
		t.Errorf("keep.txt = %q, want %q", got, "keep")
	}
	// recursive subdirectory copy
	got, err = os.ReadFile(filepath.Join(dst, "scripts", "upgrade.sh"))
	if err != nil {
		t.Fatalf("read copied scripts/upgrade.sh failed: %v", err)
	}
	if string(got) != "echo up" {
		t.Errorf("scripts/upgrade.sh = %q, want %q", got, "echo up")
	}
	got, err = os.ReadFile(filepath.Join(dst, "scripts", "nested", "deep.txt"))
	if err != nil {
		t.Fatalf("read copied scripts/nested/deep.txt failed: %v", err)
	}
	if string(got) != "deep" {
		t.Errorf("scripts/nested/deep.txt = %q, want %q", got, "deep")
	}
}

// TestCopyDirContentSpacesInPaths asserts entries whose names contain spaces
// are copied intact (the old shell glob split them into multiple argv words;
// with argv cp they are single arguments).
func TestCopyDirContentSpacesInPaths(t *testing.T) {
	src := t.TempDir()
	dst := t.TempDir()
	spaceDir := filepath.Join(src, "my app dir")
	if err := os.MkdirAll(spaceDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(spaceDir, "inner.txt"), []byte("in"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := copyDirContent(src, dst); err != nil {
		t.Fatalf("copyDirContent failed: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dst, "my app dir", "inner.txt"))
	if err != nil {
		t.Fatalf("read copied spaced path failed: %v", err)
	}
	if string(got) != "in" {
		t.Errorf("inner.txt = %q, want %q", got, "in")
	}
}

// TestCopyDirContentMetacharacterNames is the injection regression test: the
// detail directory is derived from app Key/Version values synced from the app
// store, which a tampered store can populate with shell metacharacters. The
// copy runs as exec argv, so a hostile name must be treated as a literal file
// name: at most a (failing, logged) cp of a non-existent literal path - never
// a shell execution. No injected command may run.
func TestCopyDirContentMetacharacterNames(t *testing.T) {
	src := t.TempDir()
	dst := t.TempDir()
	hostile := "v$(touch /tmp/pwned-copy)"
	if err := os.MkdirAll(filepath.Join(src, hostile), 0755); err != nil {
		t.Fatal(err)
	}
	// the directory name IS a literal name here, so the copy succeeds as a
	// plain rename-safe argv copy; nothing shell-parsed may have happened
	if err := copyDirContent(src, dst); err != nil {
		t.Logf("copy of literally-named hostile entry returned: %v (acceptable)", err)
	}
	if _, err := os.Stat("/tmp/pwned-copy"); err == nil {
		t.Fatalf("injected command executed via cp path")
	}
	// also assert the whole hostile srcDir never reaches a shell
	hostileSrc := filepath.Join(t.TempDir(), "a; touch /tmp/pwned-copy2", "v1.0")
	if err := copyDirContent(hostileSrc, dst); err == nil {
		t.Logf("missing hostile srcDir returned no error (glob no-match, matches || true)")
	}
	if _, err := os.Stat("/tmp/pwned-copy2"); err == nil {
		t.Fatalf("injected command executed via srcDir path")
	}
}

// TestCopyDirContentMissingSource mirrors the original `|| true` tolerance:
// a srcDir without any entry (e.g. the download produced nothing) must not
// fail the upgrade flow.
func TestCopyDirContentMissingSource(t *testing.T) {
	if err := copyDirContent(filepath.Join(t.TempDir(), "does-not-exist"), t.TempDir()); err != nil {
		t.Errorf("missing source dir must be a tolerated no-op, got: %v", err)
	}
}
