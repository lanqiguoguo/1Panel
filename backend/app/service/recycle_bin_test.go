package service

import (
	"bytes"
	"fmt"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/1Panel-dev/1Panel/backend/app/dto/request"
	"github.com/1Panel-dev/1Panel/backend/buserr"
	"github.com/1Panel-dev/1Panel/backend/constant"
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

// buildRName builds a recycle bin entry name in the exact format produced by
// RecycleBinService.Create when a file is moved into the recycle bin.
func buildRName(sourcePath string, size int64, deleteTime int64) string {
	paths := strings.Split(sourcePath, "/")
	rNamePre := strings.Join(paths, "_1p_")
	return fmt.Sprintf("_1p_%s%s_p_%d_%d", "file", rNamePre, size, deleteTime)
}

// ensureRootRecycleBin 准备根回收站目录（constant.RecycleBinDir）作为 Reduce
// 的合法 From；无权限创建时跳过测试，若目录由本测试创建则结束后清理。
func ensureRootRecycleBin(t *testing.T) string {
	t.Helper()
	created := false
	if _, err := os.Stat(constant.RecycleBinDir); err != nil {
		if !os.IsNotExist(err) {
			t.Skipf("stat %s failed: %v", constant.RecycleBinDir, err)
		}
		if err := os.MkdirAll(constant.RecycleBinDir, 0755); err != nil {
			t.Skipf("cannot create %s: %v", constant.RecycleBinDir, err)
		}
		created = true
	}
	if created {
		t.Cleanup(func() { _ = os.Remove(constant.RecycleBinDir) })
	}
	return constant.RecycleBinDir
}

// assertBusinessError asserts that err is the given named business error.
func assertBusinessError(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected business error %s, got nil", want)
	}
	be, ok := err.(buserr.BusinessError)
	if !ok || be.Msg != want {
		t.Fatalf("expected business error %s, got %v", want, err)
	}
}

// TestReduceRoundTrip verifies that a file moved into the recycle bin with
// Create's name format can be restored to its original location. Spaces,
// CJK chars and (consecutive) dots in the original name must all keep
// working.
func TestReduceRoundTrip(t *testing.T) {
	base := t.TempDir()
	siteDir := path.Join(base, "site")
	clashDir := ensureRootRecycleBin(t)
	if err := os.MkdirAll(siteDir, 0755); err != nil {
		t.Fatal(err)
	}

	content := []byte("important data")
	sourcePath := path.Join(siteDir, "my notes 数据..备份 v2.txt")
	if err := os.WriteFile(sourcePath, content, 0644); err != nil {
		t.Fatal(err)
	}
	rName := buildRName(sourcePath, int64(len(content)), time.Now().Unix())
	// simulate what RecycleBinService.Create does on delete
	if err := os.Rename(sourcePath, path.Join(clashDir, rName)); err != nil {
		t.Fatal(err)
	}

	svc := RecycleBinService{}
	if err := svc.Reduce(request.RecycleBinReduce{From: clashDir, RName: rName}); err != nil {
		t.Fatalf("reduce should succeed, got %v", err)
	}
	got, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, content) {
		t.Fatalf("restored content mismatch: %s", got)
	}
	// 根回收站目录可能包含本机既有条目，只断言本测试的条目已被还原走
	if _, err := os.Stat(path.Join(clashDir, rName)); !os.IsNotExist(err) {
		t.Fatalf("entry %s should be gone after restore: %v", rName, err)
	}
}

// TestReduceOverExistingTarget verifies the RmRf branch: restoring onto a
// source path that already exists replaces the old file.
func TestReduceOverExistingTarget(t *testing.T) {
	base := t.TempDir()
	siteDir := path.Join(base, "site")
	clashDir := ensureRootRecycleBin(t)
	if err := os.MkdirAll(siteDir, 0755); err != nil {
		t.Fatal(err)
	}

	sourcePath := path.Join(siteDir, "app.conf")
	if err := os.WriteFile(sourcePath, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	rName := buildRName(sourcePath, 3, time.Now().Unix())
	if err := os.WriteFile(path.Join(clashDir, rName), []byte("new"), 0644); err != nil {
		t.Fatal(err)
	}

	svc := RecycleBinService{}
	if err := svc.Reduce(request.RecycleBinReduce{From: clashDir, RName: rName}); err != nil {
		t.Fatalf("reduce should succeed, got %v", err)
	}
	got, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new" {
		t.Fatalf("expected restored content 'new', got %q", got)
	}
}

// TestReduceRejectsProtectedPath verifies that a crafted rName which
// reconstructs a protected path is rejected before any filesystem
// operation, leaving both the recycled file and the protected file
// untouched.
func TestReduceRejectsProtectedPath(t *testing.T) {
	setTestBaseDir(t, "/opt")
	clashDir := ensureRootRecycleBin(t)

	passwdBefore, err := os.ReadFile("/etc/passwd")
	if err != nil {
		t.Fatal(err)
	}

	cases := []string{
		"_1p_file_1p_etc_1p_passwd_p_0_1",           // reconstructs /etc/passwd
		buildRName("/opt/1panel/db/secret", 5, 123), // reconstructs panel data dir
	}
	svc := RecycleBinService{}
	for _, rName := range cases {
		decoy := path.Join(clashDir, rName)
		t.Cleanup(func() { _ = os.Remove(decoy) })
		if err := os.WriteFile(decoy, []byte("decoy"), 0644); err != nil {
			t.Fatal(err)
		}
		assertBusinessError(t, svc.Reduce(request.RecycleBinReduce{From: clashDir, RName: rName}), constant.ErrPathNotDelete)
		if _, err := os.Stat(decoy); err != nil {
			t.Errorf("recycled file %s should stay in the recycle dir: %v", rName, err)
		}
	}

	passwdAfter, err := os.ReadFile("/etc/passwd")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(passwdBefore, passwdAfter) {
		t.Fatal("/etc/passwd was modified")
	}
}

// TestReduceRejectsMetacharAndTraversal verifies that rNames reconstructing
// shell payloads or traversal segments are rejected without executing any
// command (marker files prove it) and without consuming the recycled file.
func TestReduceRejectsMetacharAndTraversal(t *testing.T) {
	clashDir := ensureRootRecycleBin(t)
	svc := RecycleBinService{}

	// (1) quote based shell injection in the reconstructed source path: if
	// the value reached RmRf/Mv unvalidated it would break out of the
	// single quotes and run $(touch <canary>).
	canary := fmt.Sprintf("/tmp/1p_reduce_canary_%d_%d", os.Getpid(), time.Now().UnixNano())
	rName := buildRName(fmt.Sprintf("/tmp/a'$(touch %s)'", canary), 5, 123)
	decoy := path.Join(clashDir, rName)
	if err := os.WriteFile(decoy, []byte("decoy"), 0644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(decoy) })
	assertBusinessError(t, svc.Reduce(request.RecycleBinReduce{From: clashDir, RName: rName}), constant.ErrCmdIllegal)
	if _, err := os.Stat(canary); !os.IsNotExist(err) {
		t.Fatalf("shell injection was executed, canary %s exists", canary)
	}
	if _, err := os.Stat(decoy); err != nil {
		t.Fatalf("recycled file should stay in the recycle dir: %v", err)
	}

	// (2) traversal segments in the reconstructed source path
	traversalTarget := fmt.Sprintf("/victim_%d", time.Now().UnixNano())
	rName = buildRName("/tmp/.."+traversalTarget, 5, 123)
	decoy = path.Join(clashDir, rName)
	if err := os.WriteFile(decoy, []byte("decoy"), 0644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(decoy) })
	assertBusinessError(t, svc.Reduce(request.RecycleBinReduce{From: clashDir, RName: rName}), constant.ErrCmdIllegal)
	if _, err := os.Stat(decoy); err != nil {
		t.Fatalf("recycled file should stay in the recycle dir: %v", err)
	}
	if _, err := os.Stat(traversalTarget); !os.IsNotExist(err) {
		t.Fatalf("traversal target %s must not be touched", traversalTarget)
	}

	// (3) From 指向任意目录时整体拒绝（无论其内容是否像回收站条目）
	base := t.TempDir()
	fromDir := path.Join(base, "not_a_recycle_dir")
	if err := os.MkdirAll(fromDir, 0755); err != nil {
		t.Fatal(err)
	}
	unique := fmt.Sprintf("/tmp/ok_%d", time.Now().UnixNano())
	rName = buildRName(unique, 5, 123)
	decoy = path.Join(fromDir, rName)
	if err := os.WriteFile(decoy, []byte("decoy"), 0644); err != nil {
		t.Fatal(err)
	}
	assertBusinessError(t, svc.Reduce(request.RecycleBinReduce{From: fromDir, RName: rName}), constant.ErrCmdIllegal)
	if _, err := os.Stat(decoy); err != nil {
		t.Fatalf("recycled file should stay in place: %v", err)
	}
	if _, err := os.Stat(unique); !os.IsNotExist(err) {
		t.Fatalf("mv target %s must not be created", unique)
	}
}

// TestReduceRejectsPathSeparatorsInRName verifies that rNames which are not
// plain file names are rejected before any path is joined or touched.
func TestReduceRejectsPathSeparatorsInRName(t *testing.T) {
	base := t.TempDir()
	cases := []string{"..", ".", "../escape", "sub/file", `back\slash`, "/etc/passwd"}
	svc := RecycleBinService{}
	for _, rName := range cases {
		assertBusinessError(t, svc.Reduce(request.RecycleBinReduce{From: base, RName: rName}), constant.ErrCmdIllegal)
	}
}

// TestReduceRejectsArbitraryFrom 验证 From 不在回收站目录白名单内时整体拒绝，
// 即使目录里放着形如回收站条目的文件也不会被还原。
func TestReduceRejectsArbitraryFrom(t *testing.T) {
	base := t.TempDir()
	siteDir := path.Join(base, "site")
	if err := os.MkdirAll(siteDir, 0755); err != nil {
		t.Fatal(err)
	}
	sourcePath := path.Join(siteDir, "victim.txt")
	rName := buildRName(sourcePath, 5, 123)

	svc := RecycleBinService{}
	for _, from := range []string{
		base,                                     // 任意普通目录
		path.Join(base, "fake", ".1panel_clash"), // 非挂载点下的同名目录
		"/etc",                                   // 受保护系统目录
	} {
		_ = os.MkdirAll(from, 0755)
		decoy := path.Join(from, rName)
		_ = os.WriteFile(decoy, []byte("decoy"), 0644)
		t.Cleanup(func() { _ = os.Remove(decoy) })

		if err := svc.Reduce(request.RecycleBinReduce{From: from, RName: rName}); err == nil {
			t.Errorf("From %q should be rejected", from)
		} else {
			assertBusinessError(t, err, constant.ErrCmdIllegal)
		}
		if _, err := os.Stat(sourcePath); !os.IsNotExist(err) {
			t.Fatalf("source %s must not be created by a rejected From %q", sourcePath, from)
		}
	}
}

// TestIsValidRecycleFrom 验证 From 白名单的精确匹配语义：挂载点下的
// .1panel_clash 与根回收站目录合法，兄弟目录、子路径均非法。
func TestIsValidRecycleFrom(t *testing.T) {
	partitions := []disk.PartitionStat{
		{Mountpoint: "/data", Device: "/dev/sda", Fstype: "ext4"},
		{Mountpoint: "/mnt/volume", Device: "/dev/sdb", Fstype: "ext4"},
	}
	valid := []string{
		constant.RecycleBinDir,
		constant.RecycleBinDir + "/", // 尾部分隔符在 Clean 后等价
		"/data/.1panel_clash",
		"/mnt/volume/.1panel_clash",
	}
	for _, from := range valid {
		if !isValidRecycleFrom(from, partitions) {
			t.Errorf("From %q should be a valid recycle dir", from)
		}
	}
	invalid := []string{
		"", "/",
		"/data",                    // 挂载点本身
		"/data-evil/.1panel_clash", // 兄弟目录
		"/data/.1panel_clash/x",    // 子路径
		"/data/.1panel_clash/..",   // 穿越后落回挂载点
		"/etc", "/tmp/links/.1panel_clash",
	}
	for _, from := range invalid {
		if isValidRecycleFrom(from, partitions) {
			t.Errorf("From %q should be rejected", from)
		}
	}
}

// TestPathUnderMount 验证挂载点边界的判断：简单前缀比较会把兄弟目录误判
// 为挂载点之内（getClashDir 的旧缺陷）。
func TestPathUnderMount(t *testing.T) {
	cases := []struct {
		realPath   string
		mountpoint string
		want       bool
	}{
		{"/data", "/data", true},
		{"/data/x", "/data", true},
		{"/data/x/y", "/data", true},
		{"/data-evil/x", "/data", false}, // 旧前缀比较的误判场景
		{"/datahouse/x", "/data", false},
		{"/dat", "/data", false},
		{"/anything", "/", true},
	}
	for _, c := range cases {
		if got := pathUnderMount(c.realPath, c.mountpoint); got != c.want {
			t.Errorf("pathUnderMount(%q, %q) = %v, want %v", c.realPath, c.mountpoint, got, c.want)
		}
	}
}
