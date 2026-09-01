package files

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestCutExecutionPointProtectedCheck wires the injectable protected-path
// re-check (the same hook the service layer installs in production) and
// proves Cut consults it at the execution point: when ANY effective target or
// source fails the check, the move is aborted with no source removed and no
// destination written. This shrinks the TOCTOU window between the service
// validation and the actual rename to the syscall itself.
func TestCutExecutionPointProtectedCheck(t *testing.T) {
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

	// install a check that protects dstDir (simulating a concurrent flip of
	// the destination into a protected directory after service validation)
	orig := cutProtectedPathCheckGlobal
	t.Cleanup(func() { cutProtectedPathCheckGlobal = orig })
	cutProtectedPathCheckGlobal = func(paths ...string) bool {
		for _, p := range paths {
			if p == dstDir || p == filepath.Join(dstDir, "report.txt") {
				return true
			}
		}
		return false
	}

	fo := NewFileOp()
	if err := fo.Cut([]string{src}, dstDir, "", true); err == nil {
		t.Fatal("Cut must abort when the execution-point check flags the destination")
	}
	// the source must remain untouched
	if _, err := os.Stat(src); err != nil {
		t.Fatalf("rejected Cut must leave the source in place: %v", err)
	}
	// and the destination must not have been created
	if _, err := os.Stat(filepath.Join(dstDir, "report.txt")); !os.IsNotExist(err) {
		t.Fatalf("rejected Cut must not write the destination: %v", err)
	}

	// a check that flags only the SOURCE also aborts
	cutProtectedPathCheckGlobal = func(paths ...string) bool {
		for _, p := range paths {
			if p == src {
				return true
			}
		}
		return false
	}
	if err := fo.Cut([]string{src}, dstDir, "", true); err == nil {
		t.Fatal("Cut must abort when the execution-point check flags the source")
	}
	if _, err := os.Stat(src); err != nil {
		t.Fatalf("rejected Cut must leave the source in place: %v", err)
	}
}

// TestCutWithoutHookStillWorks proves the plain test path (no hook installed)
// keeps the ordinary cut behavior: same-device moves land in the destination
// with content intact.
func TestCutWithoutHookStillWorks(t *testing.T) {
	base := t.TempDir()
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

	fo := NewFileOp()
	if err := fo.Cut([]string{src}, dstDir, "", true); err != nil {
		t.Fatalf("Cut: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dstDir, "plain.txt"))
	if err != nil || string(got) != "data" {
		t.Fatalf("cut result mismatch: %q, err: %v", string(got), err)
	}
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Fatalf("Cut left the source in place: %v", err)
	}
}

// TestCutCrossDeviceFallsBackToMv documents the cross-filesystem fallback:
// when rename(2) fails with EXDEV (source on another filesystem, e.g. tmpfs
// vs disk) Cut re-runs the affected sources through shell mv, which copies+
// removes across devices. On dev machines /dev/shm is usually a tmpfs and
// t.TempDir() lives on the overlay/disk, so the pair gives a real EXDEV; the
// test skips if the environment does not provide one (single-filesystem
// containers), in which case the fallback is exercised only by review.
func TestCutCrossDeviceFallsBackToMv(t *testing.T) {
	if os.Geteuid() != 0 && !dirWritable("/dev/shm") {
		t.Skip("/dev/shm not usable for the cross-device probe")
	}
	tmp := "/dev/shm"
	if !sameFilesystem(t.TempDir(), tmp) {
		base, err := os.MkdirTemp(tmp, "1panel-cut-exdev-*")
		if err != nil {
			t.Skipf("cannot create tmpfs source dir: %v", err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(base) })
		src := filepath.Join(base, "cross.txt")
		if err := os.WriteFile(src, []byte("cross-device"), 0644); err != nil {
			t.Fatalf("write src: %v", err)
		}
		dstDir := t.TempDir()
		fo := NewFileOp()
		if err := fo.Cut([]string{src}, dstDir, "", true); err != nil {
			t.Fatalf("cross-device Cut should succeed via mv fallback: %v", err)
		}
		got, err := os.ReadFile(filepath.Join(dstDir, "cross.txt"))
		if err != nil || string(got) != "cross-device" {
			t.Fatalf("cross-device cut result mismatch: %q, err: %v", string(got), err)
		}
		if _, err := os.Stat(src); !os.IsNotExist(err) {
			t.Fatalf("cross-device Cut left the source in place: %v", err)
		}
		return
	}
	t.Skip("temp dir and /dev/shm share a filesystem; no EXDEV available in this environment")
}

func dirWritable(dir string) bool {
	probe, err := os.MkdirTemp(dir, "1panel-writable-*")
	if err != nil {
		return false
	}
	_ = os.Remove(probe)
	return true
}

func sameFilesystem(a, b string) bool {
	ia, errA := os.Stat(a)
	ib, errB := os.Stat(b)
	if errA != nil || errB != nil {
		return false
	}
	return os.SameFile(ia, ib) || deviceOf(ia) == deviceOf(ib)
}

// deviceOf extracts the st_dev of a FileInfo via the underlying syscall; the
// repo already imports syscall in non-test code of this package.
func deviceOf(fi os.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Dev)
	}
	return 0
}
