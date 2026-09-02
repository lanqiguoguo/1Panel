package files

import (
	"os"
	"path/filepath"
	"testing"
)

// installProtectedCheck installs a cutProtectedPathCheckGlobal that flags the
// given verdict function and restores the previous hook on cleanup. NOTE: a
// FileOp snapshots the hook at NewFileOp() time, so callers must create a NEW
// FileOp after installing (mirroring production, where every request builds a
// fresh FileOp).
func installProtectedCheck(t *testing.T, verdict func(paths ...string) bool) {
	t.Helper()
	orig := cutProtectedPathCheckGlobal
	t.Cleanup(func() { cutProtectedPathCheckGlobal = orig })
	cutProtectedPathCheckGlobal = func(paths ...string) bool {
		return verdict(paths...)
	}
}

// flagAny returns a verdict that flags exactly the listed paths.
func flagAny(flag ...string) func(paths ...string) bool {
	return func(paths ...string) bool {
		for _, p := range paths {
			for _, f := range flag {
				if p == f {
					return true
				}
			}
		}
		return false
	}
}

// TestCutRealLandingTargetChecked proves the execution-point check vets the
// PER-SOURCE real landing spot: when the destination resolves to an existing
// directory the sources land at dstPath/<base(oldPath)>, and flagging only
// that inner path must abort the whole move before any source is removed.
func TestCutRealLandingTargetChecked(t *testing.T) {
	base := t.TempDir()
	srcDir := filepath.Join(base, "src")
	dstDir := filepath.Join(base, "dst")
	for _, d := range []string{srcDir, dstDir} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	src := filepath.Join(srcDir, "report.txt")
	if err := os.WriteFile(src, []byte("content"), 0644); err != nil {
		t.Fatalf("write src: %v", err)
	}
	// the real landing spot inside the existing dstDir is the only flagged path
	realTarget := filepath.Join(dstDir, "report.txt")
	installProtectedCheck(t, flagAny(realTarget))

	fo := NewFileOp()
	if err := fo.Cut([]string{src}, dstDir, "", true); err == nil {
		t.Fatal("Cut must abort when only the per-source real landing target is protected")
	}
	if _, err := os.Stat(src); err != nil {
		t.Fatalf("rejected Cut must leave the source in place: %v", err)
	}
	if _, err := os.Stat(realTarget); !os.IsNotExist(err) {
		t.Fatalf("rejected Cut must not write the real target: %v", err)
	}

	// the same shape with a rename (name): dstPath = dstDir/<name> does not
	// exist yet, so the real target is dstPath itself
	src2 := filepath.Join(srcDir, "second.txt")
	if err := os.WriteFile(src2, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	installProtectedCheck(t, flagAny(filepath.Join(dstDir, "new-name.txt")))
	fo2 := NewFileOp()
	if err := fo2.Cut([]string{src2}, dstDir, "new-name.txt", false); err == nil {
		t.Fatal("Cut with rename must abort when the real landing target is protected")
	}
	if _, err := os.Stat(src2); err != nil {
		t.Fatalf("rejected Cut must leave the second source in place: %v", err)
	}
}

// TestCutCoverOverwriteRealLanding proves that when dstPath IS an existing
// non-directory (the joined dst/name exists and is a file) the real target of
// mv -f is dst itself, and flagging it still aborts before any write — while
// the legitimate cover overwrite keeps working when nothing is flagged.
func TestCutCoverOverwriteRealLanding(t *testing.T) {
	base := t.TempDir()
	srcDir := filepath.Join(base, "src")
	dstDir := filepath.Join(base, "dst")
	for _, d := range []string{srcDir, dstDir} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	src := filepath.Join(srcDir, "report.txt")
	existing := filepath.Join(dstDir, "report.txt")
	if err := os.WriteFile(src, []byte("new content"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(existing, []byte("old content"), 0644); err != nil {
		t.Fatal(err)
	}

	// flag ONLY the existing non-directory dstDir itself: dstPath == dstDir,
	// not a dir, so the real landing spot IS dstDir — must abort
	installProtectedCheck(t, flagAny(dstDir))
	fo := NewFileOp()
	if err := fo.Cut([]string{src}, dstDir, "report.txt", true); err == nil {
		t.Fatal("Cut overwriting an existing protected file path must abort")
	}
	if _, err := os.Stat(src); err != nil {
		t.Fatalf("rejected Cut must leave the source in place: %v", err)
	}
	assertFileContent(t, existing, "old content")

	// nothing flagged -> the cover overwrite still replaces the content
	installProtectedCheck(t, flagAny())
	fo2 := NewFileOp()
	if err := fo2.Cut([]string{src}, dstDir, "report.txt", true); err != nil {
		t.Fatalf("Cut with cover: %v", err)
	}
	assertFileContent(t, existing, "new content")
}

// TestCopyExecutionPointProtectedCheck proves the copy family consults the
// execution-point check with the REAL landing target, mirroring cp's symlink
// following:
//   - CopyAndReName file onto an existing directory dst: landing is dst/<base>
//     (the cp -f 'src' 'dst' branch where dst is a dir copies inside it)
//   - CopyAndReName with name onto an existing DIRECTORY dst/name: landing is
//     dst/name/<base>
//   - plain Copy (file branch) has the same landing semantics
func TestCopyExecutionPointProtectedCheck(t *testing.T) {
	base := t.TempDir()
	srcDir := filepath.Join(base, "src")
	dstDir := filepath.Join(base, "dst")
	for _, d := range []string{srcDir, dstDir} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	src := filepath.Join(srcDir, "payload.bin")
	if err := os.WriteFile(src, []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}

	// dst is an existing directory: CopyAndReName(src, dstDir, "", true)
	// copies INSIDE dstDir, i.e. real target dstDir/payload.bin
	realTarget := filepath.Join(dstDir, "payload.bin")
	installProtectedCheck(t, flagAny(realTarget))
	fo := NewFileOp()
	if err := fo.CopyAndReName(src, dstDir, "", true); err == nil {
		t.Fatal("copy into a dir with a protected real landing spot must abort")
	}
	if _, err := os.Stat(realTarget); !os.IsNotExist(err) {
		t.Fatalf("rejected copy must not write the real target: %v", err)
	}
	if _, err := os.Stat(src); err != nil {
		t.Fatalf("source must survive a rejected copy: %v", err)
	}

	// generic Copy (file branch) deliberately does NOT run the hook: internal
	// flows (app install, nginx backup, restore) legitimately copy inside the
	// protected panel data dir, so a hook here would break them. Only
	// CopyAndReName (the /files/move API path) is guarded.
	fo2 := NewFileOp()
	if err := fo2.Copy(src, dstDir); err != nil {
		t.Fatalf("generic Copy must not be affected by the execution-point hook: %v", err)
	}
	if err := os.Remove(realTarget); err != nil {
		t.Fatalf("cleanup copied file: %v", err)
	}

	// copy with a name onto an existing directory dst/<name>: real landing is
	// dst/<name>/<base(src)>
	subDir := filepath.Join(dstDir, "bucket")
	if err := os.MkdirAll(subDir, 0755); err != nil {
		t.Fatal(err)
	}
	installProtectedCheck(t, flagAny(filepath.Join(subDir, "payload.bin")))
	fo3 := NewFileOp()
	if err := fo3.CopyAndReName(src, dstDir, "bucket", false); err == nil {
		t.Fatal("copy into an existing named dir with a protected real landing must abort")
	}
	if _, err := os.Stat(filepath.Join(subDir, "payload.bin")); !os.IsNotExist(err) {
		t.Fatalf("rejected copy must not write inside the named dir: %v", err)
	}

	// nothing flagged -> legitimate copies still succeed
	installProtectedCheck(t, flagAny())
	fo4 := NewFileOp()
	if err := fo4.CopyAndReName(src, dstDir, "", true); err != nil {
		t.Fatalf("legitimate copy: %v", err)
	}
	assertFileContent(t, realTarget, "data")
}

// TestCopySymlinkDstDirRealLanding proves the copy-family execution check
// treats a destination SYMLINK that points at an existing directory as the
// directory cp will write into: Stat (like cp) follows the link, so the real
// landing candidate handed to the injectable check is dstArg/<base(src)> —
// symlink-aware protection against the protected-dir list itself is the job of
// the injected hook (service.isProtectedPath resolves links), which the
// service-level tests cover end to end.
func TestCopySymlinkDstDirRealLanding(t *testing.T) {
	base := t.TempDir()
	srcDir := filepath.Join(base, "src")
	if err := os.MkdirAll(srcDir, 0755); err != nil {
		t.Fatal(err)
	}
	realDir := filepath.Join(base, "real-dst")
	if err := os.MkdirAll(realDir, 0755); err != nil {
		t.Fatal(err)
	}
	linkDir := filepath.Join(base, "link-dst")
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(srcDir, "f.txt")
	if err := os.WriteFile(src, []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}

	// the check must receive the landing candidate INSIDE the directory-shaped
	// destination: linkDir/f.txt (the resolved realDir/f.txt is reached through
	// the injectable hook's own link resolution)
	landingCandidate := filepath.Join(linkDir, "f.txt")
	installProtectedCheck(t, flagAny(landingCandidate))
	fo := NewFileOp()
	if err := fo.CopyAndReName(src, linkDir, "", true); err == nil {
		t.Fatal("copy through a destination symlink with a protected real landing must abort")
	}
	if _, err := os.Stat(filepath.Join(realDir, "f.txt")); !os.IsNotExist(err) {
		t.Fatalf("rejected copy must not write through the symlink: %v", err)
	}

	// flagging the plain dst path (linkDir) also aborts
	installProtectedCheck(t, flagAny(linkDir))
	fo2 := NewFileOp()
	if err := fo2.CopyAndReName(src, linkDir, "", true); err == nil {
		t.Fatal("copy must abort when the destination argument itself is flagged")
	}

	// a symlink pointing at a SAFE dir still allows the copy when nothing is
	// flagged
	installProtectedCheck(t, flagAny())
	fo3 := NewFileOp()
	if err := fo3.CopyAndReName(src, linkDir, "", true); err != nil {
		t.Fatalf("copy through a symlink to a safe dir should succeed: %v", err)
	}
	assertFileContent(t, filepath.Join(realDir, "f.txt"), "data")
}

// TestCopyWithoutHookStillWorks mirrors TestCutWithoutHookStillWorks: with no
// hook installed the copy family keeps its plain behavior (real copy, content
// intact) so test paths and non-service callers are unaffected.
func TestCopyWithoutHookStillWorks(t *testing.T) {
	base := t.TempDir()
	fo := NewFileOp()
	srcDir := filepath.Join(base, "src")
	dstDir := filepath.Join(base, "dst")
	for _, d := range []string{srcDir, dstDir} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	src := filepath.Join(srcDir, "plain.txt")
	if err := os.WriteFile(src, []byte("data"), 0644); err != nil {
		t.Fatalf("write src: %v", err)
	}
	if err := fo.Copy(src, dstDir); err != nil {
		t.Fatalf("Copy: %v", err)
	}
	assertFileContent(t, filepath.Join(dstDir, "plain.txt"), "data")
}
