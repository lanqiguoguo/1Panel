package service

import (
	"os"
	"path"
	"path/filepath"
	"testing"
	"time"

	"github.com/1Panel-dev/1Panel/backend/app/dto/request"
	"github.com/1Panel-dev/1Panel/backend/constant"
	"github.com/shirou/gopsutil/v3/disk"
)

// TestSourcePathConsistentWithFrom pins the filesystem-consistency check
// between an encoded restore target and the recycle dir it is restored from:
// the pair must be reproducible by Create/getClashDir (target on the same
// mount as the clash dir; the root clash dir only ever holds paths that lie
// on the root filesystem).
func TestSourcePathConsistentWithFrom(t *testing.T) {
	partitions := []disk.PartitionStat{
		{Mountpoint: "/", Device: "/dev/sda", Fstype: "ext4"},
		{Mountpoint: "/data", Device: "/dev/sdb", Fstype: "ext4"},
		{Mountpoint: "/mnt/volume", Device: "/dev/sdc", Fstype: "ext4"},
	}
	valid := []struct{ src, from string }{
		{"/tmp/site/a.conf", constant.RecycleBinDir}, // root filesystem path in the root clash dir
		{"/var/www/x", constant.RecycleBinDir},       // root filesystem path in the root clash dir
		{"/data", "/data/.1panel_clash"},             // the mountpoint itself is a legal source
		{"/data/site", "/data/.1panel_clash"},        // first listed mount wins, same as getClashDir
		{"/data/site/conf.d", "/data/.1panel_clash"}, // nested path on the same mount
		{"/mnt/volume/deep/file", "/mnt/volume/.1panel_clash"},
	}
	for _, c := range valid {
		if !sourcePathConsistentWithFrom(c.src, c.from, partitions) {
			t.Errorf("sourcePathConsistentWithFrom(%q, %q) = false, want true", c.src, c.from)
		}
	}
	invalid := []struct{ src, from string }{
		// cross-mount: a /data file would have been recycled into /data/.1panel_clash
		{"/data/site", constant.RecycleBinDir},
		{"/data/site", "/mnt/volume/.1panel_clash"},
		{"/mnt/volume/deep/file", constant.RecycleBinDir},
		{"/mnt/volume/deep/file", "/data/.1panel_clash"},
		{"/tmp/x", "/data/.1panel_clash"},
		// a source inside ANY recycle dir can never be a real recycled item
		{"/.1panel_clash", constant.RecycleBinDir},
		{"/.1panel_clash/x", constant.RecycleBinDir},
		{"/data/.1panel_clash", "/data/.1panel_clash"},
		{"/data/.1panel_clash/x", "/data/.1panel_clash"},
		{"/data/.1panel_clash", constant.RecycleBinDir},
		{"/data/.1panel_clash/x", constant.RecycleBinDir},
		{constant.RecycleBinDir, "/data/.1panel_clash"},
	}
	for _, c := range invalid {
		if sourcePathConsistentWithFrom(c.src, c.from, partitions) {
			t.Errorf("sourcePathConsistentWithFrom(%q, %q) = true, want false", c.src, c.from)
		}
	}
}

// writableNonRootClashDir finds a non-root mountpoint whose .1panel_clash
// directory can actually be created and written (mkdir alone can succeed on
// read-only filesystems, so a file write probe is used) and returns it with
// a cleanup callback. Skipped when no such mountpoint exists.
func writableNonRootClashDir(t *testing.T) string {
	t.Helper()
	parts, err := disk.Partitions(false)
	if err != nil {
		t.Skipf("cannot read partitions: %v", err)
	}
	for _, p := range parts {
		if p.Mountpoint == "/" || p.Mountpoint == "" {
			continue
		}
		clashDir := path.Join(p.Mountpoint, ".1panel_clash")
		if err := os.MkdirAll(clashDir, 0755); err != nil {
			continue
		}
		probeFile := path.Join(clashDir, "write_probe")
		if err := os.WriteFile(probeFile, []byte("x"), 0644); err != nil {
			_ = os.RemoveAll(clashDir)
			continue
		}
		_ = os.Remove(probeFile)
		// The mount must also host legitimate restore targets: mounts under a
		// protected prefix (e.g. /var/lib/docker) can never be a real recycle
		// origin, so they are skipped here.
		if isProtectedPath(path.Join(clashDir, "..", "site")) {
			_ = os.RemoveAll(clashDir)
			continue
		}
		t.Cleanup(func() { _ = os.RemoveAll(clashDir) })
		return clashDir
	}
	t.Skip("no writable non-root mountpoint available")
	return ""
}

// TestReduceRejectsCrossMountPlant verifies the RmRf guard end to end on a
// real non-root mountpoint when one is available (root required to create
// the clash dir there): an entry planted in a mount's clash dir whose name
// encodes a target OUTSIDE that mount (which Create would never have moved
// into this clash dir) must be rejected without deleting the target.
func TestReduceRejectsCrossMountPlant(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to create a clash dir on a non-root mountpoint")
	}
	clashDir := writableNonRootClashDir(t)
	svc := RecycleBinService{}

	// A target on the same mount is a legal restore: buildRName encodes it,
	// the entry "recycles" into this clash dir, Reduce pre-deletes the old
	// file and moves the entry back.
	sameMount := path.Join(clashDir, "..", "site", "app.conf")
	if err := os.MkdirAll(path.Dir(sameMount), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sameMount, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	rName := buildRName(sameMount, 3, time.Now().Unix())
	decoy := path.Join(clashDir, rName)
	if err := os.WriteFile(decoy, []byte("new"), 0644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(path.Dir(sameMount)) })
	if err := svc.Reduce(request.RecycleBinReduce{From: clashDir, RName: rName}); err != nil {
		t.Fatalf("same-mount reduce should succeed, got %v", err)
	}

	// A planted entry whose name encodes a target on a DIFFERENT mount (or on
	// the root filesystem while the clash dir sits on a dedicated mount) must
	// be refused before RmRf touches anything.
	foreign := path.Join(t.TempDir(), "victim") // root filesystem (os.TempDir is not under `mount`)
	if err := os.WriteFile(foreign, []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}
	rName = buildRName(foreign, 4, time.Now().Unix())
	decoy = path.Join(clashDir, rName)
	if err := os.WriteFile(decoy, []byte("decoy"), 0644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(decoy) })
	assertBusinessError(t, svc.Reduce(request.RecycleBinReduce{From: clashDir, RName: rName}), constant.ErrCmdIllegal)
	if _, err := os.Stat(foreign); err != nil {
		t.Fatalf("foreign target %s must not be deleted: %v", foreign, err)
	}
	if _, err := os.Stat(decoy); err != nil {
		t.Fatalf("decoy entry %s should stay in the clash dir: %v", decoy, err)
	}
}

// TestReduceRejectsSourceInsideOwnRecycleDir covers the self-recycle guard:
// an entry whose encoded target lies inside the very recycle dir it is
// restored from would make Reduce RmRf the whole clash dir (with every other
// recycled entry still inside) before the move. On the root clash dir this
// is already caught by isProtectedPath, so the test relies on the same
// conditional non-root mountpoint as TestReduceRejectsCrossMountPlant.
func TestReduceRejectsSourceInsideOwnRecycleDir(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to create a clash dir on a non-root mountpoint")
	}
	clashDir := writableNonRootClashDir(t)
	svc := RecycleBinService{}
	inside := filepath.Join(clashDir, "other_entry_still_here")
	rName := buildRName(inside, 5, time.Now().Unix())
	decoy := path.Join(clashDir, rName)
	if err := os.WriteFile(decoy, []byte("decoy"), 0644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(decoy) })
	assertBusinessError(t, svc.Reduce(request.RecycleBinReduce{From: clashDir, RName: rName}), constant.ErrCmdIllegal)
	if _, err := os.Stat(decoy); err != nil {
		t.Fatalf("decoy entry should stay in the clash dir: %v", err)
	}
}
