package v1

import (
	"bytes"
	"encoding/json"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/app/dto"
	"github.com/1Panel-dev/1Panel/backend/buserr"
	"github.com/1Panel-dev/1Panel/backend/constant"
	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/gin-gonic/gin"
)

// runUploadRequest 构造 multipart 上传请求并调用 UploadFiles。
func runUploadRequest(t *testing.T, targetPath, filename string, content []byte) (int, []byte) {
	t.Helper()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("file", filename)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteField("path", targetPath); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/files/upload", body)
	c.Request.Header.Set("Content-Type", writer.FormDataContentType())
	new(BaseApi).UploadFiles(c)
	return recorder.Code, recorder.Body.Bytes()
}

// TestUploadRejectsProtectedPath 验证上传目标目录位于受保护目录内时被拒绝，
// 且不会在目标位置留下任何文件。
func TestUploadRejectsProtectedPath(t *testing.T) {
	targetDir := "/etc/1panel_upload_denied"
	target := filepath.Join(targetDir, "evil.txt")

	status, body := runUploadRequest(t, targetDir, "evil.txt", []byte("data"))
	if status != http.StatusOK {
		t.Fatalf("upload status = %d, want %d", status, http.StatusOK)
	}
	var response dto.Response
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatalf("upload response is not JSON: %q: %v", body, err)
	}
	if response.Code == constant.CodeSuccess {
		t.Fatalf("upload to %s unexpectedly succeeded: %+v", targetDir, response)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("protected target %s must not be created: %v", target, err)
	}
}

// TestUploadToTempDirSucceeds 验证普通目录上传不受影响。
func TestUploadToTempDirSucceeds(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "up.txt")
	const content = "upload content"

	status, body := runUploadRequest(t, dir, "up.txt", []byte(content))
	if status != http.StatusOK {
		t.Fatalf("upload status = %d, want %d", status, http.StatusOK)
	}
	var response dto.Response
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatalf("upload response is not JSON: %q: %v", body, err)
	}
	if response.Code != constant.CodeSuccess {
		t.Fatalf("upload to %s failed: %+v", target, response)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("uploaded file missing: %v", err)
	}
	if string(got) != content {
		t.Fatalf("uploaded content = %q, want %q", got, content)
	}
}

// runChunkUploadRequest 构造分片上传请求并调用 UploadChunkFiles。
func runChunkUploadRequest(t *testing.T, dstDir, filename string, content []byte, index, count int) (int, []byte) {
	t.Helper()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("chunk", filename)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(content); err != nil {
		t.Fatal(err)
	}
	for _, field := range [][2]string{
		{"chunkIndex", strconv.Itoa(index)},
		{"chunkCount", strconv.Itoa(count)},
		{"filename", filename},
		{"path", dstDir},
	} {
		if err := writer.WriteField(field[0], field[1]); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/files/chunkupload", body)
	c.Request.Header.Set("Content-Type", writer.FormDataContentType())
	new(BaseApi).UploadChunkFiles(c)
	return recorder.Code, recorder.Body.Bytes()
}

// TestUploadChunkFilesEndToEnd 验证分片上传经流式落盘与流式合并后内容完整、
// 分片目录被清理。
func TestUploadChunkFilesEndToEnd(t *testing.T) {
	origTmp := global.CONF.System.TmpDir
	global.CONF.System.TmpDir = t.TempDir()
	defer func() { global.CONF.System.TmpDir = origTmp }()

	dstDir := t.TempDir()
	name := "merged.txt"

	// 中间分片：不触发合并，无响应体
	status, body := runChunkUploadRequest(t, dstDir, name, []byte("part1-"), 0, 2)
	if status != http.StatusOK {
		t.Fatalf("chunk 0 status = %d, want %d", status, http.StatusOK)
	}
	if len(body) != 0 {
		t.Fatalf("intermediate chunk should not respond, body = %q", body)
	}
	if _, err := os.Stat(filepath.Join(dstDir, name)); !os.IsNotExist(err) {
		t.Fatalf("file must not exist before the last chunk: %v", err)
	}

	// 最后一个分片：触发合并
	status, body = runChunkUploadRequest(t, dstDir, name, []byte("part2"), 1, 2)
	if status != http.StatusOK {
		t.Fatalf("chunk 1 status = %d, want %d", status, http.StatusOK)
	}
	var response dto.Response
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatalf("chunk upload response is not JSON: %q: %v", body, err)
	}
	if response.Code != constant.CodeSuccess {
		t.Fatalf("chunk upload failed: %+v", response)
	}

	got, err := os.ReadFile(filepath.Join(dstDir, name))
	if err != nil {
		t.Fatalf("merged file missing: %v", err)
	}
	if string(got) != "part1-part2" {
		t.Fatalf("merged content = %q, want %q", got, "part1-part2")
	}

	// 分片临时目录应已被 mergeChunks 清理
	chunkDir := filepath.Join(global.CONF.System.TmpDir, "upload", name)
	if _, err := os.Stat(chunkDir); !os.IsNotExist(err) {
		t.Fatalf("chunk dir %s should be removed after merge: %v", chunkDir, err)
	}
}

// TestMergeChunksDirect 验证流式合并本身的功能与清理行为。
func TestMergeChunksDirect(t *testing.T) {
	base := t.TempDir()
	fileDir := filepath.Join(base, "parts")
	if err := os.MkdirAll(fileDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fileDir, "big.bin.0"), []byte("hello "), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fileDir, "big.bin.1"), []byte("world"), 0644); err != nil {
		t.Fatal(err)
	}
	dstDir := filepath.Join(base, "dst")
	if err := os.MkdirAll(dstDir, 0755); err != nil {
		t.Fatal(err)
	}

	if err := mergeChunks("big.bin", fileDir, dstDir, 2, true); err != nil {
		t.Fatalf("mergeChunks should succeed, got %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dstDir, "big.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello world" {
		t.Fatalf("merged content = %q, want %q", got, "hello world")
	}
	if _, err := os.Stat(fileDir); !os.IsNotExist(err) {
		t.Fatalf("chunk dir %s should be removed after merge: %v", fileDir, err)
	}
}

// TestChunkUploadRejectsProtectedPath 验证分片上传合并目标位于受保护目录内
// 时被拒（与普通上传一致），且不会在目标位置留下任何文件。单片 chunkCount=1
// 走完整合并流程，覆盖 mergeChunks 的最终落盘路径校验。
func TestChunkUploadRejectsProtectedPath(t *testing.T) {
	origTmp := global.CONF.System.TmpDir
	global.CONF.System.TmpDir = t.TempDir()
	defer func() { global.CONF.System.TmpDir = origTmp }()

	target := "/etc/evil.txt"
	status, body := runChunkUploadRequest(t, "/etc", "evil.txt", []byte("data"), 0, 1)
	if status != http.StatusOK {
		t.Fatalf("chunk upload status = %d, want %d", status, http.StatusOK)
	}
	var response dto.Response
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatalf("chunk upload response is not JSON: %q: %v", body, err)
	}
	if response.Code == constant.CodeSuccess {
		t.Fatalf("chunk upload to %s unexpectedly succeeded: %+v", target, response)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("protected target %s must not be created: %v", target, err)
	}
}

// TestChunkUploadToTempDirSucceeds 验证合法目录下单分片上传走完整合并且内容
// 正确，即保护路径校验未误伤正常分片上传。
func TestChunkUploadToTempDirSucceeds(t *testing.T) {
	origTmp := global.CONF.System.TmpDir
	global.CONF.System.TmpDir = t.TempDir()
	defer func() { global.CONF.System.TmpDir = origTmp }()

	dstDir := t.TempDir()
	target := filepath.Join(dstDir, "single.txt")
	const content = "single chunk content"

	status, body := runChunkUploadRequest(t, dstDir, "single.txt", []byte(content), 0, 1)
	if status != http.StatusOK {
		t.Fatalf("chunk upload status = %d, want %d", status, http.StatusOK)
	}
	var response dto.Response
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatalf("chunk upload response is not JSON: %q: %v", body, err)
	}
	if response.Code != constant.CodeSuccess {
		t.Fatalf("chunk upload to %s failed: %+v", target, response)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("merged file missing: %v", err)
	}
	if string(got) != content {
		t.Fatalf("merged content = %q, want %q", got, content)
	}
}

// TestMergeChunksRejectsProtectedPath 直接验证合并函数对最终落盘路径的护栏：
// 即使调用方漏检，mergeChunks 也必须拒绝向受保护目录合并。
func TestMergeChunksRejectsProtectedPath(t *testing.T) {
	base := t.TempDir()
	fileDir := filepath.Join(base, "parts")
	if err := os.MkdirAll(fileDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fileDir, "evil.txt.0"), []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := mergeChunks("evil.txt", fileDir, "/etc", 1, true); err == nil {
		t.Fatal("mergeChunks into /etc should be rejected")
	} else {
		assertChunkBusinessError(t, err)
	}
	target := "/etc/evil.txt"
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("protected target %s must not be created: %v", target, err)
	}
}

// assertChunkBusinessError 断言 err 是 Msg 为 ErrPathNotDelete 的业务错误。
func assertChunkBusinessError(t *testing.T, err error) {
	t.Helper()
	var be buserr.BusinessError
	if !errors.As(err, &be) || be.Msg != constant.ErrPathNotDelete {
		t.Fatalf("got %v (%T), want ErrPathNotDelete business error", err, err)
	}
}
