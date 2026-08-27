package service

import (
	"os"
	"path"
	"testing"

	"github.com/shirou/gopsutil/v3/disk"
)

// TestPageRecycleDedup verifies that the same physical recycle dir is only
// enumerated once, even when several mountpoints alias it (WSL2 bind mounts).
func TestPageRecycleDedup(t *testing.T) {
	base := t.TempDir()

	// 模拟两个不同 mountpoint 指向同一物理回收目录（bind mount）
	clashDir := path.Join(base, ".1panel_clash")
	if err := os.MkdirAll(clashDir, 0755); err != nil {
		t.Fatal(err)
	}
	recycleFile := path.Join(clashDir, "_1p_file_1p_tmp_1p_demo_p_123_1787812913")
	if err := os.WriteFile(recycleFile, []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}

	partitions := []disk.PartitionStat{
		{Mountpoint: base, Device: "/dev/sda", Fstype: "ext4"},
		// bind mount: 同一目录, 但 gopsutil 会把它列为独立分区
		{Mountpoint: path.Join(base, "mnt", "distro"), Device: "/dev/sda", Fstype: "ext4"},
	}

	result := collectRecycleFiles(partitions)
	if len(result) != 1 {
		t.Fatalf("expected 1 recycled file after dedup, got %d: %+v", len(result), result)
	}
	if result[0].RName != "_1p_file_1p_tmp_1p_demo_p_123_1787812913" {
		t.Fatalf("unexpected file name: %s", result[0].RName)
	}
}

// TestPageRecycleMultipleDirs verifies that genuinely different recycle dirs
// are all enumerated.
func TestPageRecycleMultipleDirs(t *testing.T) {
	base := t.TempDir()
	dirA := path.Join(base, "a")
	dirB := path.Join(base, "b")
	for _, d := range []string{dirA, dirB} {
		clashDir := path.Join(d, ".1panel_clash")
		if err := os.MkdirAll(clashDir, 0755); err != nil {
			t.Fatal(err)
		}
	}
	os.WriteFile(path.Join(dirA, ".1panel_clash", "_1p_file_1p_a_p_1_1787812913"), []byte("a"), 0644)
	os.WriteFile(path.Join(dirB, ".1panel_clash", "_1p_file_1p_b_p_1_1787812914"), []byte("b"), 0644)

	partitions := []disk.PartitionStat{
		{Mountpoint: dirA, Device: "/dev/sda", Fstype: "ext4"},
		{Mountpoint: dirB, Device: "/dev/sdb", Fstype: "ext4"},
	}

	result := collectRecycleFiles(partitions)
	if len(result) != 2 {
		t.Fatalf("expected 2 recycled files, got %d: %+v", len(result), result)
	}
}
