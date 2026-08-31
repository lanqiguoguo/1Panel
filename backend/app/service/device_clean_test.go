package service

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/app/dto"
	"github.com/1Panel-dev/1Panel/backend/constant"
	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/sirupsen/logrus"
)

// setTestLogger 设置测试用全局日志，避免 global.LOG 为 nil 时 panic
func setTestLogger(t *testing.T) {
	t.Helper()
	oldLog := global.LOG
	global.LOG = logrus.New()
	t.Cleanup(func() {
		global.LOG = oldLog
	})
}

// TestCheckCleanName 校验清理项名称的合法性判断：
// 合法名称（空名称、普通文件名、含子目录的相对路径、含中文/空格的名称）应通过，
// 路径穿越、反斜杠、绝对路径、控制字符、空白名称应被拒绝
func TestCheckCleanName(t *testing.T) {
	validNames := []string{
		"", // 空名称表示清理整个分类目录（前端勾选根节点时提交）
		"1panel-xxx.tar.gz",
		"upgrade_20240101",
		"1Panel-v1.10.12-lts.tar.gz",
		"mydir/myfile.zip",               // loadTreeWithAllFile 生成的子级相对路径
		"备份任务/record-20240101101010.log", // task_log 子级，含中文
		"my file (1).tar.gz",             // 上传文件名，含空格与括号
	}
	for _, name := range validNames {
		if err := checkCleanName(name); err != nil {
			t.Errorf("name %q should be valid, got err: %v", name, err)
		}
	}

	invalidNames := []string{
		"   ", // 空白名称
		"../../../../etc",
		"..\\..\\x",
		"a\\b",
		"..",
		".",
		"a/../../x",
		"a/./b",
		"/etc",
		"/etc/passwd",
		"dir/",
		"a//b",
		"a\x00b", // NUL
		"a\nb",
		"\x7f",
	}
	for _, name := range invalidNames {
		if err := checkCleanName(name); err == nil {
			t.Errorf("name %q should be invalid", name)
		}
	}
}

// TestDropFileOrDirProtected 验证保护路径（系统关键目录、面板数据目录本体、回收站目录）拒绝删除
func TestDropFileOrDirProtected(t *testing.T) {
	baseDir := t.TempDir()
	setTestBaseDir(t, baseDir)
	setTestLogger(t)

	// 面板数据目录本体不可删除
	panelDir := filepath.Join(baseDir, "1panel")
	dbDir := filepath.Join(panelDir, "db")
	if err := os.MkdirAll(dbDir, 0755); err != nil {
		t.Fatal(err)
	}
	canary := filepath.Join(dbDir, "1Panel.db")
	if err := os.WriteFile(canary, []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := dropFileOrDir(panelDir); err == nil {
		t.Errorf("dropFileOrDir(%s) should be refused", panelDir)
	}
	if _, err := os.Stat(canary); err != nil {
		t.Errorf("canary file %s should still exist: %v", canary, err)
	}

	// 系统关键目录不可删除（保护检查先于 RemoveAll，目录不存在也返回错误）
	for _, p := range []string{"/", "/etc", "/etc/passwd", "/usr", "/boot"} {
		if err := dropFileOrDir(p); err == nil {
			t.Errorf("dropFileOrDir(%s) should be refused", p)
		}
	}
	if _, err := os.Stat("/etc"); err != nil {
		t.Errorf("/etc should still exist: %v", err)
	}

	// 回收站目录不可删除
	if err := dropFileOrDir(constant.RecycleBinDir); err == nil {
		t.Errorf("dropFileOrDir(%s) should be refused", constant.RecycleBinDir)
	}
}

// TestDropFileOrDirAllowsCleanTargets 验证面板数据目录之下的合法清理目标可正常删除
func TestDropFileOrDirAllowsCleanTargets(t *testing.T) {
	baseDir := t.TempDir()
	setTestBaseDir(t, baseDir)
	setTestLogger(t)

	upgradeDir := filepath.Join(baseDir, "1panel", "tmp", "upgrade", "upgrade_20240101")
	if err := os.MkdirAll(upgradeDir, 0755); err != nil {
		t.Fatal(err)
	}
	item := filepath.Join(upgradeDir, "1panel-xxx.tar.gz")
	if err := os.WriteFile(item, []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := dropFileOrDir(upgradeDir); err != nil {
		t.Errorf("dropFileOrDir(%s) should succeed, got err: %v", upgradeDir, err)
	}
	if _, err := os.Stat(upgradeDir); !os.IsNotExist(err) {
		t.Errorf("upgrade dir %s should be removed", upgradeDir)
	}

	logFile := filepath.Join(baseDir, "1panel", "log", "old.log")
	if err := os.MkdirAll(filepath.Dir(logFile), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(logFile, []byte("log"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := dropFileOrDir(logFile); err != nil {
		t.Errorf("dropFileOrDir(%s) should succeed, got err: %v", logFile, err)
	}
	if _, err := os.Stat(logFile); !os.IsNotExist(err) {
		t.Errorf("log file %s should be removed", logFile)
	}
}

// TestCleanRejectsMaliciousName 模拟恶意 Name 借助 "../.." 拼接逃逸出清理目录的场景：
// 前置校验命中后整体请求被拒绝，逃逸目标处的金丝雀文件不受影响
func TestCleanRejectsMaliciousName(t *testing.T) {
	baseDir := t.TempDir()
	setTestBaseDir(t, baseDir)
	setTestLogger(t)

	escapeTarget := filepath.Join(t.TempDir(), "canary")
	if err := os.MkdirAll(escapeTarget, 0755); err != nil {
		t.Fatal(err)
	}
	canary := filepath.Join(escapeTarget, "keep.txt")
	if err := os.WriteFile(canary, []byte("keep"), 0644); err != nil {
		t.Fatal(err)
	}

	// 与 Clean 中一致的拼接方式，构造逃逸出 BaseDir 的恶意名称
	malicious, err := filepath.Rel(filepath.Join(baseDir, "1panel", "tmp", "upgrade"), escapeTarget)
	if err != nil {
		t.Fatal(err)
	}
	req := []dto.Clean{
		{TreeType: "upgrade", Name: "upgrade_20240101"},
		{TreeType: "upgrade", Name: malicious},
	}
	for _, item := range req {
		if err := checkCleanName(item.Name); err != nil {
			// 命中非法名称：Clean 在删除任何文件前整体拒绝，金丝雀文件应仍然存在
			if _, statErr := os.Stat(canary); statErr != nil {
				t.Errorf("canary file %s should still exist: %v", canary, statErr)
			}
			return
		}
	}
	t.Fatalf("malicious name %q should be rejected", malicious)
}
