package service

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// errInjected lets commitStagedMemberFn force a mid-commit failure.
var errInjected = errors.New("injected member failure")

// TestCommitStagedPayloadSwapAndMove covers the exchange primitive on a real
// (overlay) filesystem and the two commit shapes of a payload: members that
// replace an existing target (exchange) and members that move in over an
// absent target (rename). After the commit the target carries the staged
// content and the replaced pre-restore member is parked in the staging dir;
// the revert moves both back.
func TestCommitStagedPayloadSwapAndMove(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "live")
	staging := filepath.Join(root, "staging")
	if err := os.MkdirAll(target, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(staging, "a"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(target, "a"), 0755); err != nil {
		t.Fatal(err)
	}
	// existing member a (dir with a file) + fresh member b
	if err := os.WriteFile(filepath.Join(target, "a", "old.txt"), []byte("old-a"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staging, "a", "new.txt"), []byte("new-a"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staging, "b.txt"), []byte("brand-new"), 0640); err != nil {
		t.Fatal(err)
	}

	applied, err := commitStagedPayload(target, staging)
	if err != nil {
		t.Fatalf("commitStagedPayload failed: %v", err)
	}
	if len(applied) != 2 {
		t.Fatalf("applied %d members, want 2", len(applied))
	}
	// target now carries the staged content
	got, err := os.ReadFile(filepath.Join(target, "a", "new.txt"))
	if err != nil || string(got) != "new-a" {
		t.Fatalf("target a/new.txt = %q, err %v; want staged content", got, err)
	}
	got, err = os.ReadFile(filepath.Join(target, "b.txt"))
	if err != nil || string(got) != "brand-new" {
		t.Fatalf("target b.txt = %q, err %v; want staged content", got, err)
	}
	// the replaced old member is parked in the staging dir by the exchange
	got, err = os.ReadFile(filepath.Join(staging, "a", "old.txt"))
	if err != nil || string(got) != "old-a" {
		t.Fatalf("staging a/old.txt = %q, err %v; want pre-restore content parked for revert", got, err)
	}
	// the fresh member was moved out of the staging dir entirely
	if _, err := os.Stat(filepath.Join(staging, "b.txt")); !os.IsNotExist(err) {
		t.Fatal("staging b.txt still exists after commit, want moved into target")
	}

	// revert swaps everything back
	if err := revertStagedPayload(target, staging, applied); err != nil {
		t.Fatalf("revertStagedPayload failed: %v", err)
	}
	got, err = os.ReadFile(filepath.Join(target, "a", "old.txt"))
	if err != nil || string(got) != "old-a" {
		t.Fatalf("after revert target a/old.txt = %q, err %v; want original", got, err)
	}
	if _, err := os.Stat(filepath.Join(target, "b.txt")); !os.IsNotExist(err) {
		t.Fatalf("after revert target b.txt still exists, want removed")
	}
	if _, err := os.Stat(filepath.Join(target, "a", "new.txt")); !os.IsNotExist(err) {
		t.Fatal("after revert target a/new.txt still exists, want moved back to staging")
	}
	assertFileContent(t, filepath.Join(staging, "a", "new.txt"), "new-a")
}

// TestCommitStagedPayloadFailureRollsBack makes the commit fail on the second
// member (injected before the member is applied) and verifies the first
// member, which had already been applied, is swapped back — the target ends
// up byte-identical to its pre-commit state.
func TestCommitStagedPayloadFailureRollsBack(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "live")
	staging := filepath.Join(root, "staging")
	if err := os.MkdirAll(filepath.Join(staging, "a"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(staging, "b"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(target, "a"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(target, "b"), 0755); err != nil {
		t.Fatal(err)
	}
	// a: staged dir replaces existing dir (must swap fine first)
	if err := os.WriteFile(filepath.Join(target, "a", "old.txt"), []byte("old-a"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staging, "a", "new.txt"), []byte("new-a"), 0640); err != nil {
		t.Fatal(err)
	}
	// b: also a valid member, but the commit is told to fail right before it
	// (sorts after "a")
	if err := os.WriteFile(filepath.Join(staging, "b", "data.txt"), []byte("new-b"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "b", "keep.txt"), []byte("keep"), 0640); err != nil {
		t.Fatal(err)
	}

	origFn := commitStagedMemberFn
	t.Cleanup(func() { commitStagedMemberFn = origFn })
	commitStagedMemberFn = func(name string, index int) error {
		if name == "b" {
			return errInjected
		}
		return nil
	}

	_, err := commitStagedPayload(target, staging)
	if err == nil {
		t.Fatal("commitStagedPayload succeeded, want failure on member b")
	}
	if !strings.Contains(err.Error(), "member b") {
		t.Fatalf("error %q does not name the failing member", err)
	}
	// target must be fully rolled back: a/old.txt back, no a/new.txt, b intact
	got, err := os.ReadFile(filepath.Join(target, "a", "old.txt"))
	if err != nil || string(got) != "old-a" {
		t.Fatalf("after failed commit target a/old.txt = %q, err %v; want original", got, err)
	}
	if _, err := os.Stat(filepath.Join(target, "a", "new.txt")); !os.IsNotExist(err) {
		t.Fatal("after failed commit target a/new.txt still exists, want rolled back")
	}
	got, err = os.ReadFile(filepath.Join(target, "b", "keep.txt"))
	if err != nil || string(got) != "keep" {
		t.Fatalf("after failed commit target b/keep.txt = %q, err %v; want untouched", got, err)
	}
}

// TestRevertStagedPayloadRestoresMixedCommit exercises the revert on a
// commit that used both swap shapes: member a was exchanged (old content now
// in staging) and member c was moved in over an absent target. revert must
// restore the target exactly (c gone, a back to old content) and the staged
// member back into staging.
func TestRevertStagedPayloadRestoresMixedCommit(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "live")
	staging := filepath.Join(root, "staging")
	if err := os.MkdirAll(filepath.Join(staging, "a"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(target, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(target, "a"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "a", "old.txt"), []byte("old-a"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staging, "a", "new.txt"), []byte("new-a"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staging, "c.txt"), []byte("new-c"), 0640); err != nil {
		t.Fatal(err)
	}

	applied, err := commitStagedPayload(target, staging)
	if err != nil {
		t.Fatalf("commitStagedPayload failed: %v", err)
	}
	assertFileContent(t, filepath.Join(target, "a", "new.txt"), "new-a")
	assertFileContent(t, filepath.Join(target, "c.txt"), "new-c")

	if err := revertStagedPayload(target, staging, applied); err != nil {
		t.Fatalf("revertStagedPayload failed: %v", err)
	}
	assertFileContent(t, filepath.Join(target, "a", "old.txt"), "old-a")
	if _, err := os.Stat(filepath.Join(target, "c.txt")); !os.IsNotExist(err) {
		t.Fatal("target c.txt still exists after revert, want removed")
	}
	if _, err := os.Stat(filepath.Join(target, "a", "new.txt")); !os.IsNotExist(err) {
		t.Fatal("target a/new.txt still exists after revert")
	}
	assertFileContent(t, filepath.Join(staging, "c.txt"), "new-c")
	assertFileContent(t, filepath.Join(staging, "a", "new.txt"), "new-a")
}

// TestExchangePathsFallbackSymmetry verifies the non-exchange fallback keeps
// both paths valid and content-swapped.
func TestExchangePathsFallbackSymmetry(t *testing.T) {
	root := t.TempDir()
	a := filepath.Join(root, "a.txt")
	b := filepath.Join(root, "b.txt")
	if err := os.WriteFile(a, []byte("A"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b, []byte("B"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := exchangePathsFallback(a, b); err != nil {
		t.Fatalf("exchangePathsFallback failed: %v", err)
	}
	assertFileContent(t, a, "B")
	assertFileContent(t, b, "A")
	// and back
	if err := exchangePathsFallback(a, b); err != nil {
		t.Fatalf("second exchangePathsFallback failed: %v", err)
	}
	assertFileContent(t, a, "A")
	assertFileContent(t, b, "B")
}

func assertFileContent(t *testing.T, file, want string) {
	t.Helper()
	got, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("read %s failed: %v", file, err)
	}
	if string(got) != want {
		t.Fatalf("%s = %q, want %q", file, got, want)
	}
}
