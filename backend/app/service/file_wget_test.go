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
// 入口校验并进入下载层：请求指向本机 httptest 地址，下载层 SSRF 校验返回
// 普通（非 BusinessError）错误——错误类型差异本身证明拒绝发生在下载层而
// 非入口校验，即入口校验未误伤合法路径。
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
	if _, statErr := os.Stat(filepath.Join(dir, "ok.bin")); !os.IsNotExist(statErr) {
		t.Fatalf("failed download must not leave a file behind: %v", statErr)
	}
}
