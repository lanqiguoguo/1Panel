package service

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/app/dto/request"
	"github.com/1Panel-dev/1Panel/backend/buserr"
	"github.com/1Panel-dev/1Panel/backend/constant"
	"github.com/1Panel-dev/1Panel/backend/global"
	badger_db "github.com/1Panel-dev/1Panel/backend/init/cache/badger_db"
	"github.com/dgraph-io/badger/v4"
)

// setupWgetCache 为 wget 合法用例提供内存缓存（下载层写进度用），结束后恢复。
func setupWgetCache(t *testing.T) {
	t.Helper()
	oldCache := global.CACHE
	cache, err := badger.Open(badger.DefaultOptions("").WithInMemory(true))
	if err != nil {
		t.Fatalf("open in-memory badger failed: %v", err)
	}
	t.Cleanup(func() {
		_ = cache.Close()
		global.CACHE = oldCache
	})
	global.CACHE = badger_db.NewCacheDB(cache)
}

// TestWgetRejectsProtectedPath 验证 wget 目标目录或最终路径位于受保护目录内
// 时被拒，返回与上传一致的 ErrPathNotDelete。请求地址指向必然被下载层 SSRF
// 校验拒绝的本机端口：若错误不是入口校验的 BusinessError，说明校验未前置。
func TestWgetRejectsProtectedPath(t *testing.T) {
	setTestBaseDir(t, "/opt")

	svc := FileService{}
	url := "http://127.0.0.1:1/x"

	cases := []struct {
		name string
		req  request.FileWget
	}{
		{"protected dir", request.FileWget{Url: url, Path: "/etc", Name: "evil"}},
		{"protected final path", request.FileWget{Url: url, Path: "/tmp", Name: "../../../etc/evil"}},
	}
	for _, tc := range cases {
		_, err := svc.Wget(tc.req)
		if err == nil {
			t.Fatalf("%s: wget to %s should be rejected", tc.name, tc.req.Path)
		}
		assertBusinessError(t, err, constant.ErrPathNotDelete)
		target := filepath.Join(tc.req.Path, tc.req.Name)
		if _, statErr := os.Stat(target); !os.IsNotExist(statErr) {
			t.Fatalf("%s: protected target %s must not be created: %v", tc.name, target, statErr)
		}
	}
}

// TestWgetRejectsBadName 验证文件名含分隔符或穿越分量时在下载前被拒
// （SanitizeFilename 返回 ErrCmdIllegal），且不会在目标目录留下文件。
func TestWgetRejectsBadName(t *testing.T) {
	setTestBaseDir(t, "/opt")

	svc := FileService{}
	dir := t.TempDir()
	url := "http://127.0.0.1:1/x"

	for _, name := range []string{"../../evil", "a/b", `a\b`, "..", "."} {
		_, err := svc.Wget(request.FileWget{Url: url, Path: dir, Name: name})
		if err == nil {
			t.Fatalf("wget with name %q should be rejected", name)
		}
		assertBusinessError(t, err, constant.ErrCmdIllegal)
	}
}

// TestWgetLegalPathReachesDownloadLayer 验证合法目录与合法文件名能通过全部
// 入口校验并到达下载层：请求指向本机 httptest 地址，最终被下载层的 SSRF
// 防护拒绝并返回普通（非 BusinessError）错误——错误类型差异本身证明拒绝
// 发生在下载层而非入口校验，即入口校验未误伤合法路径。
//
// P2-10 加固后下载层有三道 SSRF 校验：入口 URL 校验（下载函数内部的第一步，
// 属下载层而非 service 入口）、每连接 IP 复验（dialer Control）、每跳重定向
// 复验。本机 httptest 地址在第一道即被拒绝（err = "request to internal or
// reserved address is forbidden"），恰好证明 service 入口放行了该请求、拒绝
// 来自下载层内部；redirect/IP 两道守卫由 utils/files 的 ssrf_guard_test.go
// 与 utils/http 的 IsPublicIP 测试单独覆盖。
func TestWgetLegalPathReachesDownloadLayer(t *testing.T) {
	setTestBaseDir(t, "/opt")
	setupWgetCache(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("wget content"))
	}))
	defer srv.Close()

	dir := t.TempDir()
	svc := FileService{}
	_, err := svc.Wget(request.FileWget{Url: srv.URL + "/pkg.tar.gz", Path: dir, Name: "ok.bin"})
	if err == nil {
		t.Fatal("download against a loopback test server should fail the SSRF check inside the download layer")
	}
	var be buserr.BusinessError
	if errors.As(err, &be) {
		t.Fatalf("legal path must pass entrance validation, got business error %v", err)
	}
	// 拒绝必须来自下载层内部的 SSRF 校验（错误文案为下载层 SSRF 守卫的固定
	// 文案），且不会在目标目录留下文件
	if err.Error() != "request to internal or reserved address is forbidden" {
		t.Fatalf("expected download-layer SSRF rejection, got: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "ok.bin")); !os.IsNotExist(statErr) {
		t.Fatalf("failed download must not leave a file behind: %v", statErr)
	}
}
