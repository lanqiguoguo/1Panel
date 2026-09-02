package service

import (
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/app/dto/request"
	"github.com/1Panel-dev/1Panel/backend/constant"
	"github.com/1Panel-dev/1Panel/backend/utils/files"
)

// makeSymlinkPath 在一个可写的临时"非保护"根下搭出 symlink 攻击路径：
//
//	<tmp>/www              —— 普通目录（词法上不在黑名单）
//	<tmp>/www/lnk_etc      —— 指向 <tmp>/fakeprot/ssh 的目录 symlink
//	<tmp>/www/lnk_dangling —— 悬空 symlink（目标链尚不存在，但目标词法上
//	                          位于受保护目录 /etc 之下，见下）
//
// "受保护"目录不直接用 /etc 本体（本测试进程无权写），而是用 BaseDir 机制：
// setTestBaseDir 把 <tmp>/base 设为面板 BaseDir，于是 <tmp>/base/1panel 及其
// 下全部成为受保护目录。fakeprot 目录则模拟"词法上等于 /etc 的系统目录"：
// 通过把根保护目录与真实受保护目录映射成同一词法形态不现实，因此测试里用
// 指向 <tmp>/base/1panel 的 symlink 完成"词法安全、解析后受保护"的等价。
//
// 返回的 dirs 结构：
//   - www:        词法安全目录
//   - fakeTarget: 真实受保护目录 <tmp>/base/1panel/data
//   - lnkDir:     <www>/lnk  -> fakeTarget（目录 symlink，已存在目标）
//   - lnkFile:    <www>/lnkfile -> fakeTarget（文件形态 symlink 指向目录）
//   - lnkDangling: <www>/dang -> <tmp>/base/1panel/not-yet（悬空，父级受保护）
func buildSymlinkAttackLayout(t *testing.T) (www, fakeTarget, lnkDir, lnkFile, lnkDangling string) {
	t.Helper()
	base := t.TempDir()
	setTestBaseDir(t, base) // <base>/1panel 成为受保护目录

	www = filepath.Join(base, "www")
	if err := os.MkdirAll(www, 0755); err != nil {
		t.Fatal(err)
	}
	fakeTarget = filepath.Join(base, "1panel", "data")
	if err := os.MkdirAll(fakeTarget, 0755); err != nil {
		t.Fatal(err)
	}
	lnkDir = filepath.Join(www, "lnk")
	if err := os.Symlink(fakeTarget, lnkDir); err != nil {
		t.Fatal(err)
	}
	lnkFile = filepath.Join(www, "lnkfile")
	if err := os.Symlink(fakeTarget, lnkFile); err != nil {
		t.Fatal(err)
	}
	lnkDangling = filepath.Join(www, "dang")
	if err := os.Symlink(filepath.Join(base, "1panel", "not-yet"), lnkDangling); err != nil {
		t.Fatal(err)
	}
	return
}

// TestProtectedPathResolvesSymlinks 验证 isProtectedPath 的词法放行路径若经
// symlink 解析后落入受保护目录（面板数据目录），判定为受保护；指向非保护
// 目录的 symlink 保持放行。
func TestProtectedPathResolvesSymlinks(t *testing.T) {
	www, fakeTarget, lnkDir, _, lnkDangling := buildSymlinkAttackLayout(t)
	if !isProtectedPath(fakeTarget) {
		t.Fatal("sanity: the real target under the panel dir must be protected")
	}

	cases := []struct {
		name string
		path string
		want bool
	}{
		{"symlink dir points into panel dir", filepath.Join(lnkDir, "anything.conf"), true},
		{"symlink dir itself (resolves to panel dir)", lnkDir, true},
		{"through symlink into nested subdir", filepath.Join(lnkDir, "a", "b", "c.txt"), true},
		{"real path still protected", filepath.Join(fakeTarget, "x"), true},
		{"dangling symlink whose target parent is protected", filepath.Join(lnkDangling, "future.conf"), true},
		{"plain lexical protected path still detected", "/etc/passwd", true},
		{"plain safe path stays safe", www, false},
		{"safe file inside safe dir stays safe", filepath.Join(www, "a.txt"), false},
		{"non-existent path under safe dir stays safe", filepath.Join(www, "nested", "not-there"), false},
	}
	for _, c := range cases {
		if got := isProtectedPath(c.path); got != c.want {
			t.Errorf("%s: isProtectedPath(%q) = %v, want %v", c.name, c.path, got, c.want)
		}
	}
}

// TestProtectedPathSymlinkToSafeDir 验证 symlink 指向非保护目录时保持放行。
func TestProtectedPathSymlinkToSafeDir(t *testing.T) {
	base := t.TempDir()
	setTestBaseDir(t, base)
	safe := filepath.Join(base, "1panel_other") // 兄弟目录，词法与解析后都不受保护
	if err := os.MkdirAll(safe, 0755); err != nil {
		t.Fatal(err)
	}
	lnk := filepath.Join(base, "lnk-safe")
	if err := os.Symlink(safe, lnk); err != nil {
		t.Fatal(err)
	}
	if isProtectedPath(filepath.Join(lnk, "x.txt")) {
		t.Errorf("path through symlink to a safe dir must stay unprotected")
	}
	// BaseDir 本身（其下 1panel 之外）也不受保护
	if isProtectedPath(base) {
		t.Errorf("temp base dir must not be protected")
	}
}

// TestProtectedPathBoundaries 验证边界场景：
//   - 悬空 symlink 的目标词法路径本身受保护时不依赖目标是否存在（解析父级）；
//   - symlink 环不会导致死循环；
//   - 根目录与相对路径语义不回退。
func TestProtectedPathBoundaries(t *testing.T) {
	base := t.TempDir()
	setTestBaseDir(t, base)
	www := filepath.Join(base, "www")
	if err := os.MkdirAll(www, 0755); err != nil {
		t.Fatal(err)
	}

	// 悬空 symlink -> 词法上受保护的父级（本机 /etc 一定存在，不能真建链，
	// 因此链接目标选 <base>/1panel/absent，父级 <base>/1panel 受保护）
	dang := filepath.Join(www, "dang")
	if err := os.Symlink(filepath.Join(base, "1panel", "not-there"), dang); err != nil {
		t.Fatal(err)
	}
	if !isProtectedPath(filepath.Join(dang, "child.conf")) {
		t.Errorf("dangling symlink into a protected dir must be rejected")
	}

	// symlink 环：lnk -> loop, loop -> lnk（两个都解析失败时回退词法，
	// 且不 panic）
	loopA := filepath.Join(www, "loopA")
	loopB := filepath.Join(www, "loopB")
	if err := os.Symlink(loopB, loopA); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(loopA, loopB); err != nil {
		t.Fatal(err)
	}
	isProtectedPath(filepath.Join(loopA, "x")) // must terminate

	// 根目录仍然受保护；相对路径按词法（无影响）
	if !isProtectedPath("/") {
		t.Errorf("/ must be protected")
	}
}

// TestMvFileSymlinkTargetRejected（H8 回归）：
//  1. cut 到 <www>/lnk（指向受保护目录的 symlink）：预检与执行点都要拒绝，
//     源文件必须留在原地；
//  2. copy 文件 cover=true 到 <www>/lnkfile（symlink 指向受保护目录）：
//     不得把内容写进受保护目录；
//  3. cut 源位于经 symlink 可达的受保护目录内（词法路径是 <www>/lnk/...）
//     也必须拒绝。
func TestMvFileSymlinkTargetRejected(t *testing.T) {
	www, _, lnkDir, lnkFile, _ := buildSymlinkAttackLayout(t)
	svc := FileService{}
	src := filepath.Join(www, "payload.txt")
	if err := os.WriteFile(src, []byte("secret"), 0644); err != nil {
		t.Fatal(err)
	}

	// 1) cut into symlinked protected dir
	err := svc.MvFile(request.FileMove{Type: "cut", OldPaths: []string{src}, NewPath: lnkDir})
	if err == nil {
		t.Fatal("cut into a symlinked protected dir must be rejected")
	}
	assertBusinessError(t, err, constant.ErrPathNotDelete)
	if _, err := os.Stat(src); err != nil {
		t.Fatalf("rejected cut must leave the source in place: %v", err)
	}

	// 2) copy (cover) onto a symlink pointing at a protected dir
	src2 := filepath.Join(www, "payload2.txt")
	if err := os.WriteFile(src2, []byte("secret2"), 0644); err != nil {
		t.Fatal(err)
	}
	err = svc.MvFile(request.FileMove{Type: "copy", OldPaths: []string{src2}, NewPath: lnkFile, Cover: true})
	if err == nil {
		t.Fatal("copy onto a symlink pointing at a protected dir must be rejected")
	}
	assertBusinessError(t, err, constant.ErrPathNotDelete)

	// 3) cut a source that lives inside the protected dir through the symlink
	err = svc.MvFile(request.FileMove{Type: "cut", OldPaths: []string{filepath.Join(lnkDir, "stolen.conf")}, NewPath: www})
	if err == nil {
		t.Fatal("cut from a protected dir reached through a symlink must be rejected")
	}
	assertBusinessError(t, err, constant.ErrPathNotDelete)
}

// TestMvFileSymlinkToSafeTargetAllowed 验证向指向"非保护目录"的 symlink
// 移动/复制仍然放行（不误伤合法用途）。
func TestMvFileSymlinkToSafeTargetAllowed(t *testing.T) {
	base := t.TempDir()
	setTestBaseDir(t, base)
	www := filepath.Join(base, "www")
	if err := os.MkdirAll(www, 0755); err != nil {
		t.Fatal(err)
	}
	safe := filepath.Join(base, "1panel_other", "data") // 解析后仍安全
	if err := os.MkdirAll(safe, 0755); err != nil {
		t.Fatal(err)
	}
	lnk := filepath.Join(www, "lnk-safe")
	if err := os.Symlink(safe, lnk); err != nil {
		t.Fatal(err)
	}

	svc := FileService{}
	src := filepath.Join(www, "f.txt")
	if err := os.WriteFile(src, []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := svc.MvFile(request.FileMove{Type: "cut", OldPaths: []string{src}, NewPath: lnk}); err != nil {
		t.Fatalf("cut into symlink to a safe dir should succeed, got %v", err)
	}
	got, err := os.ReadFile(filepath.Join(safe, "f.txt"))
	if err != nil || string(got) != "data" {
		t.Fatalf("file not moved through the safe symlink: %q, err: %v", string(got), err)
	}
}

// TestMvFileCutIntoExistingDirRealLanding 覆盖 H8 的落点回退推导：NewPath/Name
// 已存在时 Cut 把 dstPath 回退为 NewPath 本身；NewPath 是已存在目录时每个源
// 的真实落点是 NewPath/<base(oldPath)>。服务级成功路径验证该推导与执行点
// 不冲突（不回退时 Name 指向普通目录，落点为 NewPath/Name，同样放行）。
func TestMvFileCutIntoExistingDirRealLanding(t *testing.T) {
	base := t.TempDir()
	setTestBaseDir(t, base)
	svc := FileService{}

	srcDir := filepath.Join(base, "www", "srcdir")
	dstDir := filepath.Join(base, "www", "dst")
	for _, d := range []string{srcDir, dstDir} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}
	// NewPath/Name 已存在（目录）：Cut 回退到 NewPath，真实落点 NewPath/<base>
	existing := filepath.Join(dstDir, "bucket")
	if err := os.MkdirAll(existing, 0755); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(srcDir, "item.txt")
	if err := os.WriteFile(src, []byte("v"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := svc.MvFile(request.FileMove{Type: "cut", OldPaths: []string{src}, NewPath: dstDir, Name: "bucket"}); err != nil {
		t.Fatalf("cut with existing Name must still work: %v", err)
	}
	// 回退语义：落到 NewPath/<base>，即 dstDir/item.txt
	if _, err := os.Stat(filepath.Join(dstDir, "item.txt")); err != nil {
		t.Fatalf("cut with existing Name falls back to NewPath/<base>: %v", err)
	}
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Fatalf("source must be gone after cut: %v", err)
	}

	// Name 不存在时落点是 NewPath/Name（普通文件重命名语义）
	src2 := filepath.Join(srcDir, "item2.txt")
	if err := os.WriteFile(src2, []byte("v2"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := svc.MvFile(request.FileMove{Type: "cut", OldPaths: []string{src2}, NewPath: dstDir, Name: "renamed.txt"}); err != nil {
		t.Fatalf("cut with fresh Name must still work: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dstDir, "renamed.txt")); err != nil {
		t.Fatalf("cut with fresh Name lands at NewPath/Name: %v", err)
	}
}

// TestIsProtectedPathSafeLogStyleRegression 防止 safeLogPath 既有语义被波及：
// 确认 resolveExistingPath 对不存在路径按父级解析、对已存在文件路径直接解析。
func TestIsProtectedPathRegressionNormalOps(t *testing.T) {
	base := t.TempDir()
	setTestBaseDir(t, base)
	www := filepath.Join(base, "www")
	if err := os.MkdirAll(www, 0755); err != nil {
		t.Fatal(err)
	}
	// 已存在的普通文件路径放行
	f := filepath.Join(www, "file.txt")
	if err := os.WriteFile(f, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	if isProtectedPath(f) || isProtectedPath(path.Join(www, "sub", "future")) {
		t.Errorf("ordinary paths under a safe dir must stay unprotected")
	}
}

// TestCutExecutionPointBlocksSymlinkProtectedRealLanding 是 H8+H9 的端到端
// 回归：直接调用 utils 层执行点 fo.Cut（绕过 service 预检），目标是普通
// 目录下指向受保护目录的 symlink（词法安全、解析后受保护）。file.go 的 init
// 已把 isProtectedPath 注入 Cut 执行点，真实落点 dstArg/<base> 解析后位于
// 受保护目录内，移动必须被中止且源文件保留。
func TestCutExecutionPointBlocksSymlinkProtectedRealLanding(t *testing.T) {
	www, _, lnkDir, _, _ := buildSymlinkAttackLayout(t)
	src := filepath.Join(www, "move-me.conf")
	if err := os.WriteFile(src, []byte("secret"), 0644); err != nil {
		t.Fatal(err)
	}
	fo := files.NewFileOp()
	if err := fo.Cut([]string{src}, lnkDir, "", true); err == nil {
		t.Fatal("Cut execution point must reject a move whose real landing resolves into a protected dir")
	}
	if _, err := os.Stat(src); err != nil {
		t.Fatalf("rejected Cut must leave the source in place: %v", err)
	}
}

// TestCopyAndReNameBlocksProtectedRealLanding 是 H8 copy 路径的执行点回归：
// CopyAndReName 把文件拷到词法安全、解析后指向受保护目录的 symlink 上
// （cover 分支，落点为 symlink 目标内部），必须被拒绝。
func TestCopyAndReNameBlocksProtectedRealLanding(t *testing.T) {
	www, _, lnkDir, _, _ := buildSymlinkAttackLayout(t)
	src := filepath.Join(www, "payload.bin")
	if err := os.WriteFile(src, []byte("secret"), 0644); err != nil {
		t.Fatal(err)
	}
	fo := files.NewFileOp()
	if err := fo.CopyAndReName(src, lnkDir, "", true); err == nil {
		t.Fatal("CopyAndReName execution point must reject a copy whose real landing resolves into a protected dir")
	}
}
