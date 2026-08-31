package service

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/app/dto/request"
	"github.com/1Panel-dev/1Panel/backend/constant"
)

// TestCreateRejectProtectedPath 验证创建入口（文件/目录/链接）对目标路径执行
// 受保护目录检查，命中时返回与删除一致的 ErrPathNotDelete。
func TestCreateRejectProtectedPath(t *testing.T) {
	setTestBaseDir(t, "/opt")
	svc := FileService{}

	cases := []struct {
		name string
		op   request.FileCreate
	}{
		{"create file in /etc", request.FileCreate{Path: "/etc/evil.conf", Mode: 0644}},
		{"create file in /usr/bin", request.FileCreate{Path: "/usr/bin/evil", Mode: 0755}},
		{"create file in /root", request.FileCreate{Path: "/root/evil", Mode: 0600}},
		{"create file in panel dir", request.FileCreate{Path: "/opt/1panel/db/evil.db", Mode: 0644}},
		{"create dir in /etc", request.FileCreate{Path: "/etc/evildir", IsDir: true}},
		{"symlink into /etc", request.FileCreate{Path: filepath.Join(os.TempDir(), "1p-create-link-evil"), IsLink: true, IsSymlink: true, LinkPath: "/etc/passwd"}},
		{"hardlink into /etc", request.FileCreate{Path: filepath.Join(os.TempDir(), "1p-create-hlink-evil"), IsLink: true, LinkPath: "/etc/passwd"}},
	}
	for _, c := range cases {
		if err := svc.Create(c.op); err == nil {
			t.Errorf("%s: should be rejected", c.name)
		} else {
			assertBusinessError(t, err, constant.ErrPathNotDelete)
		}
	}

	// 保护路径下未产生新条目
	for _, p := range []string{"/etc/evil.conf", "/usr/bin/evil", "/root/evil", "/etc/evildir"} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("protected path %s must not be created", p)
		}
	}
}

// TestCreateRejectProtectedLinkSource 验证链接源路径位于保护目录时同样被拒绝
// （LinkPath 为读语义，但硬链接/symlink 组合可被用于提权，入口统一拦截）。
func TestCreateRejectProtectedLinkSource(t *testing.T) {
	setTestBaseDir(t, "/opt")
	base := t.TempDir()
	svc := FileService{}

	dst := filepath.Join(base, "link-evil")
	err := svc.Create(request.FileCreate{Path: dst, IsLink: true, IsSymlink: true, LinkPath: "/etc/passwd"})
	if err == nil {
		t.Fatal("symlink with protected source should be rejected")
	}
	assertBusinessError(t, err, constant.ErrPathNotDelete)
	if _, err := os.Lstat(dst); !os.IsNotExist(err) {
		t.Fatalf("link target %s must not be created", dst)
	}
}

// TestCreateFileStripsSpecialBits 验证文件创建入口强制 mode & 0o777：
// setuid/setgid/sticky 位无法经 API 落盘。
func TestCreateFileStripsSpecialBits(t *testing.T) {
	base := t.TempDir()
	svc := FileService{}

	cases := []struct {
		name string
		mode int64
		want os.FileMode
	}{
		{"setuid dropped", int64(os.ModeSetuid) | 0755, 0755},
		{"numeric setuid dropped", 8389101, 0755},
		{"setgid dropped", int64(os.ModeSetgid) | 0755, 0755},
		{"sticky dropped", 0o1755, 0755},
		{"regular mode kept", 0644, 0644},
	}
	for i, c := range cases {
		p := filepath.Join(base, "f"+strconv.Itoa(i)+".txt")
		if err := svc.Create(request.FileCreate{Path: p, Mode: c.mode}); err != nil {
			t.Fatalf("%s: create should succeed, got %v", c.name, err)
		}
		info, err := os.Stat(p)
		if err != nil {
			t.Fatalf("%s: stat: %v", c.name, err)
		}
		if info.Mode().Perm() != c.want {
			t.Errorf("%s: perm = %04o, want %04o", c.name, info.Mode().Perm(), c.want)
		}
		if info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
			t.Errorf("%s: special bits leaked: %v", c.name, info.Mode())
		}
	}
}

// TestCreateNormalPathsStillWork 验证非保护目录下的正常创建（文件/目录/软链）
// 不受影响。
func TestCreateNormalPathsStillWork(t *testing.T) {
	setTestBaseDir(t, "/opt")
	base := t.TempDir()
	svc := FileService{}

	// 普通文件 0644
	f := filepath.Join(base, "a.txt")
	if err := svc.Create(request.FileCreate{Path: f, Mode: 0644}); err != nil {
		t.Fatalf("create file should succeed, got %v", err)
	}
	info, err := os.Stat(f)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0644 {
		t.Fatalf("file perm = %04o, want 0644", info.Mode().Perm())
	}

	// 目录 0755
	d := filepath.Join(base, "dir1")
	if err := svc.Create(request.FileCreate{Path: d, IsDir: true, Mode: 0755}); err != nil {
		t.Fatalf("create dir should succeed, got %v", err)
	}
	info, err = os.Stat(d)
	if err != nil || !info.IsDir() {
		t.Fatalf("created dir missing or not a dir: %v", err)
	}

	// 软链指向同目录文件
	link := filepath.Join(base, "link-a")
	if err := svc.Create(request.FileCreate{Path: link, IsLink: true, IsSymlink: true, LinkPath: f}); err != nil {
		t.Fatalf("create symlink should succeed, got %v", err)
	}
	if _, err := os.ReadFile(link); err != nil {
		t.Fatalf("read through symlink: %v", err)
	}

	// mode 缺省时继承父目录权限
	f2 := filepath.Join(base, "b.txt")
	if err := svc.Create(request.FileCreate{Path: f2}); err != nil {
		t.Fatalf("create file with default mode should succeed, got %v", err)
	}
	if _, err := os.Stat(f2); err != nil {
		t.Fatalf("default-mode file missing: %v", err)
	}
}
