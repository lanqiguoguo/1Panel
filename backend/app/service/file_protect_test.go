package service

import (
	"testing"

	"github.com/1Panel-dev/1Panel/backend/global"
)

// setTestBaseDir 设置面板 BaseDir 用于测试，并在测试结束后恢复原值
func setTestBaseDir(t *testing.T, baseDir string) {
	t.Helper()
	oldBaseDir := global.CONF.System.BaseDir
	global.CONF.System.BaseDir = baseDir
	t.Cleanup(func() {
		global.CONF.System.BaseDir = oldBaseDir
	})
}

// TestProtectedPath 验证系统目录、面板数据目录、回收站目录均被识别为受保护路径
func TestProtectedPath(t *testing.T) {
	setTestBaseDir(t, "/opt")

	protected := []string{
		"/",
		"/etc",
		"/etc/passwd",
		"/usr",
		"/usr/bin",
		"/var/log",
		"/home",
		"/home/user",
		"/root",
		"/proc",
		"/sys",
		"/opt/1panel",
		"/opt/1panel/db",
		"/opt/1panel/backup",
		"/.1panel_clash",
		"/.1panel_clash/_1p_foo",
	}
	for _, p := range protected {
		if !isProtectedPath(p) {
			t.Errorf("path %s should be protected", p)
		}
	}
}

// TestUnprotectedPath 验证普通用户路径不在保护列表内，且 BaseDir 本身（/opt）不受保护
func TestUnprotectedPath(t *testing.T) {
	setTestBaseDir(t, "/opt")

	unprotected := []string{
		"/www",
		"/www/sites/site1",
		"/data",
		"/data/backup",
		"/tmp",
		"/opt",
		"/opt/other",
		"/opt/1panel_original",
		"/opt/1panel-backup",
		"/opt/1panelX",
		"/var_other",
	}
	for _, p := range unprotected {
		if isProtectedPath(p) {
			t.Errorf("path %s should not be protected", p)
		}
	}
}

// TestProtectedPathEmptyBaseDir 验证 BaseDir 未配置时不会 panic，且不误判任何 /opt 路径
func TestProtectedPathEmptyBaseDir(t *testing.T) {
	setTestBaseDir(t, "")

	if isProtectedPath("/opt/1panel") {
		t.Errorf("path /opt/1panel should not be protected when BaseDir is empty")
	}
	if !isProtectedPath("/") {
		t.Errorf("path / should always be protected")
	}
}

// TestProtectedPathCustomBaseDir 验证 BaseDir 自定义时，<BaseDir>/1panel 仍被保护
func TestProtectedPathCustomBaseDir(t *testing.T) {
	setTestBaseDir(t, "/data")

	protected := []string{
		"/data/1panel",
		"/data/1panel/db",
	}
	for _, p := range protected {
		if !isProtectedPath(p) {
			t.Errorf("path %s should be protected with BaseDir=/data", p)
		}
	}
	unprotected := []string{
		"/data",
		"/data/backup",
	}
	for _, p := range unprotected {
		if isProtectedPath(p) {
			t.Errorf("path %s should not be protected with BaseDir=/data", p)
		}
	}
}
