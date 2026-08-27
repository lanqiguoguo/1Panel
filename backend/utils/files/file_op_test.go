package files

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/1Panel-dev/1Panel/backend/init/cache/badger_db"
	"github.com/dgraph-io/badger/v4"
	"github.com/sirupsen/logrus"
)

// usePermissiveDownloadURL relaxes the SSRF guard for tests that exercise
// downloads from local httptest servers (127.0.0.1); the guard is restored
// after the test so it stays covered by the dedicated SSRF tests.
func usePermissiveDownloadURL(t *testing.T) {
	t.Helper()
	orig := validateDownloadURL
	validateDownloadURL = func(rawURL string) error { return nil }
	t.Cleanup(func() { validateDownloadURL = orig })
}

// TestMain sets up the globals used by DownloadFileWithProcess so the
// download progress is reported through the same cache as in production.
func TestMain(m *testing.M) {
	global.LOG = logrus.New()
	global.LOG.SetOutput(os.Stdout)

	cachePath := filepath.Join(os.TempDir(), "1panel-test-cache")
	_ = os.RemoveAll(cachePath)
	_ = os.MkdirAll(cachePath, 0755)
	db, err := badger.Open(badger.DefaultOptions(cachePath))
	if err != nil {
		fmt.Fprintf(os.Stderr, "open badger cache: %v\n", err)
		os.Exit(1)
	}
	global.CacheDb = db
	global.CACHE = badger_db.NewCacheDB(db)

	code := m.Run()

	_ = db.Close()
	_ = os.RemoveAll(cachePath)
	os.Exit(code)
}

// TestDownloadFileWithProcessSync checks that the file is fully written when
// the function returns and that the download progress reaches 100%.
func TestDownloadFileWithProcessSync(t *testing.T) {
	usePermissiveDownloadURL(t)
	content := "hello 1panel download\nsecond line\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(content))
	}))
	defer srv.Close()

	dst := filepath.Join(t.TempDir(), "downloaded.txt")
	key := "file-wget-test-sync"
	fo := NewFileOp()
	if err := fo.DownloadFileWithProcess(srv.URL, dst, key, false); err != nil {
		t.Fatalf("DownloadFileWithProcess returned error: %v", err)
	}
	data, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("file not readable after download: %v", err)
	}
	if string(data) != content {
		t.Fatalf("downloaded content mismatch, got %q want %q", string(data), content)
	}
	value, err := global.CACHE.Get(key)
	if err != nil {
		t.Fatalf("download progress not written to cache: %v", err)
	}
	process := &Process{}
	if err := json.Unmarshal(value, process); err != nil {
		t.Fatalf("unmarshal process: %v", err)
	}
	if process.Percent != 100 {
		t.Fatalf("expected percent 100, got %f", process.Percent)
	}
	if process.Written != uint64(len(content)) {
		t.Fatalf("expected written %d, got %d", len(content), process.Written)
	}
}

// TestDownloadFileWithProcessBadRequest checks that a request creation
// failure is returned to the caller instead of being swallowed.
func TestDownloadFileWithProcessBadRequest(t *testing.T) {
	fo := NewFileOp()
	dst := filepath.Join(t.TempDir(), "bad.txt")
	if err := fo.DownloadFileWithProcess("://bad", dst, "file-wget-test-bad", false); err == nil {
		t.Fatal("expected error for invalid url, got nil")
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Fatalf("unexpected file %s created, err: %v", dst, err)
	}
}

// TestDownloadFileWithProcessConnRefused checks that a connection failure is
// returned to the caller instead of being swallowed.
func TestDownloadFileWithProcessConnRefused(t *testing.T) {
	usePermissiveDownloadURL(t)
	fo := NewFileOp()
	dst := filepath.Join(t.TempDir(), "refused.txt")
	if err := fo.DownloadFileWithProcess("http://127.0.0.1:1/x", dst, "file-wget-test-refused", false); err == nil {
		t.Fatal("expected error for refused connection, got nil")
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Fatalf("unexpected file %s created, err: %v", dst, err)
	}
}

// TestDownloadFileWithProcessSSRF checks that URLs targeting internal or
// non-http resources are rejected before any request is made.
func TestDownloadFileWithProcessSSRF(t *testing.T) {
	fo := NewFileOp()
	tests := []struct {
		name string
		url  string
	}{
		{"loopback", "http://127.0.0.1:8080/"},
		{"link-local metadata", "http://169.254.169.254/latest/meta-data/"},
		{"private range", "http://10.0.0.1/"},
		{"file scheme", "file:///etc/passwd"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dst := filepath.Join(t.TempDir(), "ssrf.txt")
			err := fo.DownloadFileWithProcess(tt.url, dst, "file-wget-test-ssrf", false)
			if err == nil {
				t.Fatalf("expected error for url %q, got nil", tt.url)
			}
			if _, statErr := os.Stat(dst); !os.IsNotExist(statErr) {
				t.Fatalf("unexpected file %s created, err: %v", dst, statErr)
			}
		})
	}
}

// TestDownloadFileWithProcessSizeLimit checks that a response larger than the
// download cap is rejected and the partial file is removed.
func TestDownloadFileWithProcessSizeLimit(t *testing.T) {
	usePermissiveDownloadURL(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", 2048)))
	}))
	defer srv.Close()

	orig := downloadMaxSize
	downloadMaxSize = 1024
	defer func() { downloadMaxSize = orig }()

	fo := NewFileOp()
	dst := filepath.Join(t.TempDir(), "big.txt")
	err := fo.DownloadFileWithProcess(srv.URL, dst, "file-wget-test-size", false)
	if err == nil {
		t.Fatal("expected error for oversized download, got nil")
	}
	if !strings.Contains(err.Error(), "size limit") {
		t.Fatalf("expected size limit error, got: %v", err)
	}
	if _, statErr := os.Stat(dst); !os.IsNotExist(statErr) {
		t.Fatalf("partial file %s not cleaned up, err: %v", dst, statErr)
	}
}

// TestDownloadFileWithProcessSizeLimitExact checks that a response exactly at
// the cap is accepted.
func TestDownloadFileWithProcessSizeLimitExact(t *testing.T) {
	usePermissiveDownloadURL(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("y", 512)))
	}))
	defer srv.Close()

	orig := downloadMaxSize
	downloadMaxSize = 512
	defer func() { downloadMaxSize = orig }()

	fo := NewFileOp()
	dst := filepath.Join(t.TempDir(), "exact.txt")
	if err := fo.DownloadFileWithProcess(srv.URL, dst, "file-wget-test-exact", false); err != nil {
		t.Fatalf("DownloadFileWithProcess returned error: %v", err)
	}
	data, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("file not readable after download: %v", err)
	}
	if len(data) != 512 {
		t.Fatalf("expected 512 bytes, got %d", len(data))
	}
}
