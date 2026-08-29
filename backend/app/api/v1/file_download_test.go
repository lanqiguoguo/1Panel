package v1

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/app/dto"
	"github.com/1Panel-dev/1Panel/backend/constant"
	"github.com/gin-gonic/gin"
)

func runDownloadRequest(t *testing.T, filePath string) (int, http.Header, []byte) {
	t.Helper()

	recorder := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(recorder)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/files/download?path="+url.QueryEscape(filePath), nil)
	context.Request = request
	new(BaseApi).Download(context)

	return recorder.Code, recorder.Header(), recorder.Body.Bytes()
}

func decodeDownloadError(t *testing.T, body []byte) dto.Response {
	t.Helper()

	var response dto.Response
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatalf("download error response is not JSON: %q: %v", body, err)
	}
	if response.Code == constant.CodeSuccess {
		t.Fatalf("download error response unexpectedly succeeded: %+v", response)
	}
	return response
}

func TestDownloadMissingFileDoesNotPanic(t *testing.T) {
	missingPath := filepath.Join(t.TempDir(), "missing.txt")

	status, _, body := runDownloadRequest(t, missingPath)
	if status != http.StatusOK {
		t.Fatalf("missing file status = %d, want %d", status, http.StatusOK)
	}
	decodeDownloadError(t, body)
}

func TestDownloadDirectoryRejected(t *testing.T) {
	directoryPath := t.TempDir()

	status, _, body := runDownloadRequest(t, directoryPath)
	if status != http.StatusOK {
		t.Fatalf("directory status = %d, want %d", status, http.StatusOK)
	}
	response := decodeDownloadError(t, body)
	if response.Message == "" {
		t.Fatal("directory response has an empty error message")
	}
}

func TestDownloadRegularFile(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "download.txt")
	const content = "download content\n"
	if err := os.WriteFile(filePath, []byte(content), 0600); err != nil {
		t.Fatalf("create test file: %v", err)
	}

	status, headers, body := runDownloadRequest(t, filePath)
	if status != http.StatusOK {
		t.Fatalf("regular file status = %d, want %d", status, http.StatusOK)
	}
	if string(body) != content {
		t.Fatalf("regular file body = %q, want %q", body, content)
	}
	if got := headers.Get("Content-Length"); got != "17" {
		t.Fatalf("Content-Length = %q, want %q", got, "17")
	}
	if headers.Get("Content-Disposition") == "" {
		t.Fatal("Content-Disposition header is empty")
	}
}
