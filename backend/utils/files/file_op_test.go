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

// assertFileContent fails the test when path cannot be read or does not hold
// exactly the expected content.
func assertFileContent(t *testing.T, path, want string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if string(data) != want {
		t.Fatalf("content mismatch in %s: got %q want %q", path, string(data), want)
	}
}

// assertNoMarker fails the test when an injection payload managed to execute
// a shell command and create the marker file.
func assertNoMarker(t *testing.T, context, marker string) {
	t.Helper()
	if _, err := os.Stat(marker); err == nil {
		t.Fatalf("%s: payload executed a shell command and created %s", context, marker)
	}
}

// TestMoveCopyInjectionRejected proves that injection payloads reaching the
// move/copy family (Cut, Mv, CopyAndReName, CopyFile, CopyDir) through hostile
// file names are rejected by validation before any shell command is built:
// every call fails with the ErrCmdIllegal business error and no payload
// manages to create the marker file. Names carrying such characters pass
// SanitizeFilename/IsInvalidChar and can exist on disk, so the operation
// layer is the line of defense under test here.
func TestMoveCopyInjectionRejected(t *testing.T) {
	base := t.TempDir()
	marker := filepath.Join(base, "pwned")
	fo := NewFileOp()

	// hostile source names are created as real files, so they cannot carry
	// "/" themselves; their payload targets the marker through the working
	// directory a spawned shell would inherit
	relMarker := "pwned-marker"
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}
	cwdMarker := filepath.Join(cwd, relMarker)
	t.Cleanup(func() { _ = os.Remove(cwdMarker) })

	// a real file and directory whose names carry shell payloads
	hostileFile := filepath.Join(base, "a'; touch "+relMarker+"; '.txt")
	if err := os.WriteFile(hostileFile, []byte("hostile"), 0644); err != nil {
		t.Fatalf("create hostile file: %v", err)
	}
	hostileDir := filepath.Join(base, "d`touch "+relMarker+"`.d")
	if err := os.MkdirAll(hostileDir, 0755); err != nil {
		t.Fatalf("create hostile dir: %v", err)
	}

	goodSrc := filepath.Join(base, "src.txt")
	if err := os.WriteFile(goodSrc, []byte("src"), 0644); err != nil {
		t.Fatalf("create source file: %v", err)
	}
	goodDir := filepath.Join(base, "copydir-src")
	if err := os.MkdirAll(goodDir, 0755); err != nil {
		t.Fatalf("create source dir: %v", err)
	}

	// payloads as destination: semicolon chaining, command substitution,
	// backtick substitution and a single-quote breakout
	pathPayloads := []string{
		"out; touch " + marker,
		"out$(touch " + marker + ")",
		"out`touch " + marker + "`",
		"out'; touch " + marker + "; '",
	}
	for _, p := range pathPayloads {
		hostileDst := filepath.Join(base, p)
		ctx := fmt.Sprintf("payload %q", p)

		assertCmdIllegal(t, ctx+" Cut dst name", fo.Cut([]string{goodSrc}, base, p, true))
		if _, err := os.Stat(goodSrc); err != nil {
			t.Fatalf("%s: Cut removed the source despite rejection: %v", ctx, err)
		}
		assertCmdIllegal(t, ctx+" Mv dst", fo.Mv(goodSrc, hostileDst))
		assertCmdIllegal(t, ctx+" CopyAndReName dst", fo.CopyAndReName(goodSrc, hostileDst, "", true))
		assertCmdIllegal(t, ctx+" CopyAndReName name", fo.CopyAndReName(goodSrc, base, p, false))
		assertCmdIllegal(t, ctx+" CopyFile dst", fo.Copy(goodSrc, hostileDst))
		assertCmdIllegal(t, ctx+" CopyDir dst", fo.Copy(goodDir, hostileDst))
		assertNoMarker(t, ctx, marker)
	}

	// payloads carried by the source path itself
	assertCmdIllegal(t, "hostile src Cut", fo.Cut([]string{hostileFile}, base, "", true))
	assertCmdIllegal(t, "hostile src Mv", fo.Mv(hostileFile, base))
	assertCmdIllegal(t, "hostile src CopyAndReName", fo.CopyAndReName(hostileFile, base, "", true))
	assertCmdIllegal(t, "hostile src CopyFile", fo.Copy(hostileFile, base))
	assertCmdIllegal(t, "hostile src CopyDir", fo.Copy(hostileDir, base))
	assertNoMarker(t, "hostile src", cwdMarker)
}

// TestCutMoveAndCopyLegitimateNames proves the move/copy family keeps working
// for ordinary names: spaces, CJK characters, dots and dashes must survive a
// cut->move round trip and a copy round trip with their content unchanged.
func TestCutMoveAndCopyLegitimateNames(t *testing.T) {
	base := t.TempDir()
	fo := NewFileOp()
	names := []string{
		"my file.txt",
		"文档 测试.txt",
		"backup-v1.2.final.tar.gz",
		"报告 2026.md",
	}

	srcDir := filepath.Join(base, "src")
	dstDir := filepath.Join(base, "dst")
	mvDir := filepath.Join(base, "mv dst dir")
	cpDir := filepath.Join(base, "cp dir")
	for _, d := range []string{srcDir, dstDir, mvDir, cpDir} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}

	for _, name := range names {
		content := "content of " + name

		// cut without an explicit name moves the file into dstDir
		src := filepath.Join(srcDir, name)
		if err := os.WriteFile(src, []byte(content), 0644); err != nil {
			t.Fatalf("write %s: %v", src, err)
		}
		if err := fo.Cut([]string{src}, dstDir, "", true); err != nil {
			t.Fatalf("Cut %q: %v", name, err)
		}
		assertFileContent(t, filepath.Join(dstDir, name), content)
		if _, err := os.Stat(src); !os.IsNotExist(err) {
			t.Fatalf("Cut left the source %s in place", src)
		}

		// cut with an explicit new name renames while moving
		renamed := "renamed-" + name
		src2 := filepath.Join(srcDir, name)
		if err := os.WriteFile(src2, []byte(content), 0644); err != nil {
			t.Fatalf("write %s: %v", src2, err)
		}
		if err := fo.Cut([]string{src2}, dstDir, renamed, false); err != nil {
			t.Fatalf("Cut with rename %q: %v", name, err)
		}
		assertFileContent(t, filepath.Join(dstDir, renamed), content)

		// Mv moves the file into a directory whose name contains a space
		if err := fo.Mv(filepath.Join(dstDir, renamed), mvDir); err != nil {
			t.Fatalf("Mv %q: %v", name, err)
		}
		assertFileContent(t, filepath.Join(mvDir, renamed), content)

		// Copy (file branch) duplicates the file into another directory
		if err := fo.Copy(filepath.Join(mvDir, renamed), cpDir); err != nil {
			t.Fatalf("Copy file %q: %v", name, err)
		}
		assertFileContent(t, filepath.Join(cpDir, renamed), content)
	}

	// Copy (dir branch) duplicates a whole directory tree, including a
	// directory name with spaces and CJK characters
	treeSrc := filepath.Join(base, "tree dir 文档")
	treeDst := filepath.Join(base, "tree-out")
	if err := os.MkdirAll(filepath.Join(treeSrc, "nested 子目录"), 0755); err != nil {
		t.Fatalf("mkdir tree: %v", err)
	}
	if err := os.WriteFile(filepath.Join(treeSrc, "nested 子目录", "data file.txt"), []byte("tree"), 0644); err != nil {
		t.Fatalf("write tree file: %v", err)
	}
	if err := fo.Copy(treeSrc, treeDst); err != nil {
		t.Fatalf("Copy dir: %v", err)
	}
	assertFileContent(t, filepath.Join(treeDst, "tree dir 文档", "nested 子目录", "data file.txt"), "tree")

	// CopyAndReName copies a file under a new name
	fsrc := filepath.Join(srcDir, names[0])
	if err := os.WriteFile(fsrc, []byte("rename me"), 0644); err != nil {
		t.Fatalf("write %s: %v", fsrc, err)
	}
	if err := fo.CopyAndReName(fsrc, cpDir, "新 名字.txt", false); err != nil {
		t.Fatalf("CopyAndReName file: %v", err)
	}
	assertFileContent(t, filepath.Join(cpDir, "新 名字.txt"), "rename me")

	// CopyAndReName on a directory copies it into the target directory
	treeDst2 := filepath.Join(base, "tree-out-2")
	if err := os.MkdirAll(treeDst2, 0755); err != nil {
		t.Fatalf("mkdir %s: %v", treeDst2, err)
	}
	if err := fo.CopyAndReName(treeSrc, treeDst2, "", true); err != nil {
		t.Fatalf("CopyAndReName dir: %v", err)
	}
	assertFileContent(t, filepath.Join(treeDst2, "tree dir 文档", "nested 子目录", "data file.txt"), "tree")
}

// TestCutCoverOverwrite proves the mv -f overwrite path still works: cutting
// a file onto an existing destination with cover enabled replaces its content.
func TestCutCoverOverwrite(t *testing.T) {
	base := t.TempDir()
	fo := NewFileOp()
	srcDir := filepath.Join(base, "src")
	dstDir := filepath.Join(base, "dst")
	for _, d := range []string{srcDir, dstDir} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}

	src := filepath.Join(srcDir, "report.txt")
	if err := os.WriteFile(src, []byte("new content"), 0644); err != nil {
		t.Fatalf("write %s: %v", src, err)
	}
	existing := filepath.Join(dstDir, "report.txt")
	if err := os.WriteFile(existing, []byte("old content"), 0644); err != nil {
		t.Fatalf("write %s: %v", existing, err)
	}

	// the joined destination exists, so Cut resolves to mv -f '<src>' '<dstDir>'
	if err := fo.Cut([]string{src}, dstDir, "report.txt", true); err != nil {
		t.Fatalf("Cut with cover: %v", err)
	}
	assertFileContent(t, existing, "new content")
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Fatalf("Cut with cover left the source %s in place", src)
	}
}
