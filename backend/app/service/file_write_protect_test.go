package service

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/app/dto/request"
	"github.com/1Panel-dev/1Panel/backend/app/model"
	"github.com/1Panel-dev/1Panel/backend/constant"
	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

// setupFileWriteTestDB prepares an in-memory sqlite DB with the favorite
// table that files.NewFileInfo queries, mirroring the harness style of
// input_validation_test.go, so the normal-path assertions can run without a
// real panel database.
func setupFileWriteTestDB(t *testing.T) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open in-memory sqlite failed: %v", err)
	}
	if err := db.AutoMigrate(&model.Favorite{}); err != nil {
		t.Fatalf("migrate tables failed: %v", err)
	}
	oldDB := global.DB
	global.DB = db
	t.Cleanup(func() { global.DB = oldDB })
}

// TestWriteOpsRejectProtectedPath 验证写操作入口（改名/保存/移动/权限/属主）
// 对涉及的源路径与目标路径统一执行受保护目录检查，命中时返回与删除一致的
// ErrPathNotDelete。
func TestWriteOpsRejectProtectedPath(t *testing.T) {
	setTestBaseDir(t, "/opt")
	base := t.TempDir()
	src := filepath.Join(base, "plain.txt")
	if err := os.WriteFile(src, []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}
	dstDir := filepath.Join(base, "dst")
	if err := os.MkdirAll(dstDir, 0755); err != nil {
		t.Fatal(err)
	}

	svc := FileService{}
	cases := []struct {
		name string
		call func() error
	}{
		{"change mode on protected path", func() error {
			return svc.ChangeMode(request.FileCreate{Path: "/etc/passwd", Mode: 0644})
		}},
		{"change owner on protected path", func() error {
			return svc.ChangeOwner(request.FileRoleUpdate{Path: "/etc/passwd", User: "root", Group: "root"})
		}},
		{"batch change on protected path", func() error {
			return svc.BatchChangeModeAndOwner(request.FileRoleReq{Paths: []string{"/etc/passwd"}, Mode: 0644, User: "root", Group: "root"})
		}},
		{"save content into panel dir", func() error {
			return svc.SaveContent(request.FileEdit{Path: "/opt/1panel/db/secret.conf", Content: "x"})
		}},
		{"rename from protected path", func() error {
			return svc.ChangeName(request.FileRename{OldName: "/etc/passwd", NewName: filepath.Join(base, "renamed.txt")})
		}},
		{"rename into protected path", func() error {
			return svc.ChangeName(request.FileRename{OldName: src, NewName: "/etc/evil"})
		}},
		{"move into protected dir", func() error {
			return svc.MvFile(request.FileMove{Type: "cut", OldPaths: []string{src}, NewPath: "/etc"})
		}},
		{"copy from protected path", func() error {
			return svc.MvFile(request.FileMove{Type: "copy", OldPaths: []string{"/etc/passwd"}, NewPath: dstDir})
		}},
	}
	for _, c := range cases {
		if err := c.call(); err == nil {
			t.Errorf("%s: should be rejected", c.name)
		} else {
			assertBusinessError(t, err, constant.ErrPathNotDelete)
		}
	}

	// 原文件保持原位
	if _, err := os.Stat(src); err != nil {
		t.Fatalf("source file must stay in place: %v", err)
	}
}

// TestWriteOpsNormalPathsStillWork 验证非保护目录下的正常写操作不受影响。
func TestWriteOpsNormalPathsStillWork(t *testing.T) {
	setupFileWriteTestDB(t)
	base := t.TempDir()
	svc := FileService{}

	// rename
	oldPath := filepath.Join(base, "a.txt")
	if err := os.WriteFile(oldPath, []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}
	newPath := filepath.Join(base, "b.txt")
	if err := svc.ChangeName(request.FileRename{OldName: oldPath, NewName: newPath}); err != nil {
		t.Fatalf("rename should succeed, got %v", err)
	}
	if _, err := os.Stat(newPath); err != nil {
		t.Fatalf("renamed file missing: %v", err)
	}

	// save content
	if err := svc.SaveContent(request.FileEdit{Path: newPath, Content: "updated"}); err != nil {
		t.Fatalf("save content should succeed, got %v", err)
	}
	got, err := os.ReadFile(newPath)
	if err != nil || string(got) != "updated" {
		t.Fatalf("saved content = %q, err = %v", got, err)
	}

	// move (cut)
	dstDir := filepath.Join(base, "dst")
	if err := os.MkdirAll(dstDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := svc.MvFile(request.FileMove{Type: "cut", OldPaths: []string{newPath}, NewPath: dstDir}); err != nil {
		t.Fatalf("cut should succeed, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(dstDir, "b.txt")); err != nil {
		t.Fatalf("moved file missing: %v", err)
	}
	if _, err := os.Stat(newPath); !os.IsNotExist(err) {
		t.Fatalf("source file should be gone after cut: %v", err)
	}

	// change mode
	modePath := filepath.Join(dstDir, "b.txt")
	if err := svc.ChangeMode(request.FileCreate{Path: modePath, Mode: 0640}); err != nil {
		t.Fatalf("change mode should succeed, got %v", err)
	}
	info, err := os.Stat(modePath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0640 {
		t.Fatalf("mode after change = %04o, want 0640", info.Mode().Perm())
	}
}

// currentUserAndGroup 返回当前进程用户/组名，供 chown 回归测试使用。
func currentUserAndGroup(t *testing.T) (string, string) {
	t.Helper()
	u, err := user.LookupId(strconv.Itoa(os.Getuid()))
	if err != nil {
		t.Skipf("cannot resolve current user: %v", err)
	}
	g, err := user.LookupGroupId(strconv.Itoa(os.Getgid()))
	if err != nil {
		t.Skipf("cannot resolve current group: %v", err)
	}
	return u.Username, g.Name
}

// TestBatchChangeModeAndOwnerNormalPaths 验证批量权限/属主修改在普通路径下
// 仍然生效（走真实 chmod/chown 命令）。
func TestBatchChangeModeAndOwnerNormalPaths(t *testing.T) {
	userName, groupName := currentUserAndGroup(t)
	base := t.TempDir()
	p := filepath.Join(base, "batch.txt")
	if err := os.WriteFile(p, []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}

	svc := FileService{}
	if err := svc.BatchChangeModeAndOwner(request.FileRoleReq{
		Paths: []string{p}, Mode: 0644, User: userName, Group: groupName,
	}); err != nil {
		t.Fatalf("batch change should succeed, got %v", err)
	}
	info, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0644 {
		t.Fatalf("mode after batch change = %04o, want 0644", info.Mode().Perm())
	}
}

// TestChangeModeStripsSpecialBits 验证服务端强制 mode & 0o777：setuid/
// setgid/sticky 位无法经 API 设置，负值被拒绝。
func TestChangeModeStripsSpecialBits(t *testing.T) {
	base := t.TempDir()
	svc := FileService{}

	cases := []struct {
		name string
		mode int64
		want os.FileMode
	}{
		{"setuid is dropped", 0o4755, 0o755},
		{"setgid is dropped", 0o2755, 0o755},
		{"sticky is dropped", 0o1755, 0o755},
		{"regular mode unchanged", 0o640, 0o640},
	}
	for i, c := range cases {
		p := filepath.Join(base, "f"+strconv.Itoa(i)+".txt")
		if err := os.WriteFile(p, []byte("x"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := svc.ChangeMode(request.FileCreate{Path: p, Mode: c.mode}); err != nil {
			t.Fatalf("%s: change mode should succeed, got %v", c.name, err)
		}
		info, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != c.want {
			t.Errorf("%s: perm = %04o, want %04o", c.name, info.Mode().Perm(), c.want)
		}
		if info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
			t.Errorf("%s: special bits leaked: %v", c.name, info.Mode())
		}
	}

	// batch 入口同样收敛
	p := filepath.Join(base, "batch_special.txt")
	if err := os.WriteFile(p, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	userName, groupName := currentUserAndGroup(t)
	if err := svc.BatchChangeModeAndOwner(request.FileRoleReq{
		Paths: []string{p}, Mode: 0o4755, User: userName, Group: groupName,
	}); err != nil {
		t.Fatalf("batch change should succeed, got %v", err)
	}
	info, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o755 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		t.Fatalf("batch mode after change = %v, want 0755 without special bits", info.Mode())
	}

	// 负值直接拒绝
	if err := svc.ChangeMode(request.FileCreate{Path: p, Mode: -1}); err == nil {
		t.Fatal("negative mode should be rejected")
	} else {
		assertBusinessError(t, err, constant.ErrCmdIllegal)
	}
	if err := svc.BatchChangeModeAndOwner(request.FileRoleReq{
		Paths: []string{p}, Mode: -1, User: userName, Group: groupName,
	}); err == nil {
		t.Fatal("negative batch mode should be rejected")
	} else {
		assertBusinessError(t, err, constant.ErrCmdIllegal)
	}
}
