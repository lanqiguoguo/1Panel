package v1

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/app/dto"
	"github.com/1Panel-dev/1Panel/backend/app/dto/request"
	"github.com/1Panel-dev/1Panel/backend/constant"
	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/gin-gonic/gin"
)

// runCheckFileRequest 构造 /files/check 请求并调用 CheckFile。
func runCheckFileRequest(t *testing.T, path string, withInit bool) (int, []byte) {
	t.Helper()
	body, err := json.Marshal(request.FilePathCheck{Path: path, WithInit: withInit})
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/files/check", bytes.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")
	new(BaseApi).CheckFile(c)
	return recorder.Code, recorder.Body.Bytes()
}

// TestCheckFileWithInitRejectsProtectedPath 验证 withInit=true 对受保护目录
// 的建目录请求被拒绝,且不会在受保护位置留下新目录。旧实现直接
// MkdirAll(req.Path),使 /files/check 成为绕过其它创建接口保护检查的路径。
func TestCheckFileWithInitRejectsProtectedPath(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root to probe /etc")
	}
	target := filepath.Join("/etc", "1panel_check_denied_"+t.Name())
	defer os.RemoveAll(target)

	_, raw := runCheckFileRequest(t, target, true)
	var resp dto.Response
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("check response is not JSON: %q: %v", raw, err)
	}
	if resp.Code == constant.CodeSuccess {
		t.Fatalf("check withInit on protected path %s unexpectedly succeeded: %+v", target, resp)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("protected dir %s must not be created: %v", target, err)
	}
}

// TestCheckFileWithInitAllowedPathSucceeds 验证普通目录的 withInit 建目录
// 行为不受影响。
func TestCheckFileWithInitAllowedPathSucceeds(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "1panel")
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		t.Fatal(err)
	}
	oldDataDir := global.CONF.System.DataDir
	global.CONF.System.DataDir = dataDir
	defer func() { global.CONF.System.DataDir = oldDataDir }()

	target := filepath.Join(dataDir, "not", "yet", "created")
	_, raw := runCheckFileRequest(t, target, true)
	var resp dto.Response
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("check response is not JSON: %q: %v", raw, err)
	}
	if resp.Code != constant.CodeSuccess {
		t.Fatalf("check withInit on %s failed: %+v", target, resp)
	}
	if ok, _ := resp.Data.(bool); !ok {
		t.Fatalf("check withInit data = %v, want true", resp.Data)
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("allowed dir %s was not created: %v", target, err)
	}
}
