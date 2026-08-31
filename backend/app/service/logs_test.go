package service

import (
	"os"
	"path"
	"testing"
	"time"

	"github.com/1Panel-dev/1Panel/backend/constant"
	"github.com/1Panel-dev/1Panel/backend/global"
)

// setTestDataDir 设置面板 DataDir 用于测试，并在测试结束后恢复原值
func setTestDataDir(t *testing.T, dataDir string) {
	t.Helper()
	oldDataDir := global.CONF.System.DataDir
	global.CONF.System.DataDir = dataDir
	t.Cleanup(func() {
		global.CONF.System.DataDir = oldDataDir
	})
}

// TestLoadSystemLogValidDates 验证合法日期名可以读到对应日志内容，当天日期
// 读到 1Panel.log
func TestLoadSystemLogValidDates(t *testing.T) {
	base := t.TempDir()
	setTestDataDir(t, base)
	logDir := path.Join(base, "log")
	if err := os.MkdirAll(logDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path.Join(logDir, "1Panel-2024-01-02.log"), []byte("old log"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path.Join(logDir, "1Panel.log"), []byte("today log"), 0644); err != nil {
		t.Fatal(err)
	}

	svc := LogService{}
	got, err := svc.LoadSystemLog("2024-01-02")
	if err != nil {
		t.Fatalf("valid date should load, got %v", err)
	}
	if got != "old log" {
		t.Fatalf("valid date content = %q, want %q", got, "old log")
	}

	today := time.Now().Format("2006-01-02")
	got, err = svc.LoadSystemLog(today)
	if err != nil {
		t.Fatalf("today's date should load, got %v", err)
	}
	if got != "today log" {
		t.Fatalf("today content = %q, want %q", got, "today log")
	}
}

// TestLoadSystemLogRejectsNonDateNames 验证非日期格式（含路径穿越片段）的
// 名称一律拒绝，不会拼接出日志目录之外的路径
func TestLoadSystemLogRejectsNonDateNames(t *testing.T) {
	base := t.TempDir()
	setTestDataDir(t, base)
	logDir := path.Join(base, "log")
	if err := os.MkdirAll(logDir, 0755); err != nil {
		t.Fatal(err)
	}
	// 攻击者想要读到的目标文件（位于日志目录之外，扩展名 .log）
	secret := path.Join(base, "secret.log")
	if err := os.WriteFile(secret, []byte("secret"), 0644); err != nil {
		t.Fatal(err)
	}

	svc := LogService{}
	for _, name := range []string{
		"../secret",        // 穿越
		"../../etc/passwd", // 跨层穿越
		"2024-01-02/..",    // 日期夹带穿越
		"abc",              // 普通非日期串
		"2024-1-2",         // 位数不足
		"20240102",         // 无分隔
		"2024-01-02.gz",    // 夹带扩展名
		"",                 // 空串
	} {
		if _, err := svc.LoadSystemLog(name); err == nil {
			t.Errorf("name %q should be rejected", name)
		} else {
			assertBusinessError(t, err, constant.ErrCmdIllegal)
		}
	}

	if _, err := os.Stat(secret); err != nil {
		t.Fatalf("outside file %s must stay untouched: %v", secret, err)
	}
}
