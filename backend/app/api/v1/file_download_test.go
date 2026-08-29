package v1

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/app/dto"
	"github.com/1Panel-dev/1Panel/backend/app/dto/request"
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

func TestParseByteRange(t *testing.T) {
	const fileSize = int64(10)

	tests := []struct {
		name      string
		header    string
		wantStart int64
		wantEnd   int64
		wantErr   bool
	}{
		{name: "malformed", header: "malformed", wantErr: true},
		{name: "missing end separator", header: "bytes=1", wantErr: true},
		{name: "negative suffix range", header: "bytes=-1", wantErr: true},
		{name: "negative end", header: "bytes=1--2", wantErr: true},
		{name: "reverse range", header: "bytes=5-2", wantErr: true},
		{name: "end beyond file", header: "bytes=0-10", wantErr: true},
		{name: "start beyond file", header: "bytes=10-10", wantErr: true},
		{name: "multiple ranges", header: "bytes=0-1,2-3", wantErr: true},
		{name: "start overflow", header: "bytes=9223372036854775808-", wantErr: true},
		{name: "explicit range", header: "bytes=2-5", wantStart: 2, wantEnd: 5},
		{name: "open ended range", header: "bytes=2-", wantStart: 2, wantEnd: 9},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			start, end, err := parseByteRange(test.header, fileSize)
			if test.wantErr {
				if err == nil {
					t.Fatalf("parseByteRange(%q) error = nil, want an error", test.header)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseByteRange(%q) returned error: %v", test.header, err)
			}
			if start != test.wantStart || end != test.wantEnd {
				t.Fatalf("parseByteRange(%q) = %d-%d, want %d-%d", test.header, start, end, test.wantStart, test.wantEnd)
			}
		})
	}
}

func runChunkDownloadRequest(t *testing.T, filePath, rangeHeader string) (int, http.Header, []byte) {
	t.Helper()

	recorder := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(recorder)
	body, err := json.Marshal(request.FileChunkDownload{Path: filePath, Name: filepath.Base(filePath)})
	if err != nil {
		t.Fatalf("marshal chunk download request: %v", err)
	}
	httpRequest := httptest.NewRequest(http.MethodPost, "/api/v1/files/chunkdownload", bytes.NewReader(body))
	httpRequest.Header.Set("Content-Type", "application/json")
	if rangeHeader != "" {
		httpRequest.Header.Set("Range", rangeHeader)
	}
	context.Request = httpRequest
	new(BaseApi).DownloadChunkFiles(context)

	return recorder.Code, recorder.Header(), recorder.Body.Bytes()
}

func TestDownloadChunkRangeResponse(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "chunk.txt")
	const content = "0123456789"
	if err := os.WriteFile(filePath, []byte(content), 0600); err != nil {
		t.Fatalf("create test file: %v", err)
	}

	status, headers, body := runChunkDownloadRequest(t, filePath, "bytes=2-5")
	if status != http.StatusPartialContent {
		t.Fatalf("chunk status = %d, want %d", status, http.StatusPartialContent)
	}
	if string(body) != "2345" {
		t.Fatalf("chunk body = %q, want %q", body, "2345")
	}
	if got := headers.Get("Content-Length"); got != "4" {
		t.Fatalf("chunk Content-Length = %q, want %q", got, "4")
	}
	if got := headers.Get("Content-Range"); got != "bytes 2-5/10" {
		t.Fatalf("chunk Content-Range = %q, want %q", got, "bytes 2-5/10")
	}
}

func TestDownloadChunkInvalidRangeReturns416(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "chunk.txt")
	if err := os.WriteFile(filePath, []byte("0123456789"), 0600); err != nil {
		t.Fatalf("create test file: %v", err)
	}

	status, headers, body := runChunkDownloadRequest(t, filePath, "bytes=1")
	if status != http.StatusRequestedRangeNotSatisfiable {
		t.Fatalf("invalid chunk status = %d, want %d", status, http.StatusRequestedRangeNotSatisfiable)
	}
	if got := headers.Get("Content-Range"); got != "bytes */10" {
		t.Fatalf("invalid chunk Content-Range = %q, want %q", got, "bytes */10")
	}
	if len(body) != 0 {
		t.Fatalf("invalid chunk body = %q, want empty body", body)
	}
}
