package files

import (
	"archive/tar"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/sirupsen/logrus"
)

// tarGzLogCapture collects the debug messages routed through global.LOG while
// the shell archiver builds its commands, so the exact bash -c command string
// can be asserted on.
type tarGzLogCapture struct {
	mu      sync.Mutex
	entries []string
}

func (h *tarGzLogCapture) Fire(entry *logrus.Entry) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.entries = append(h.entries, entry.Message)
	return nil
}

func (h *tarGzLogCapture) Levels() []logrus.Level { return logrus.AllLevels }

func (h *tarGzLogCapture) messages() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.entries...)
}

func swapTarGzDebugLog(t *testing.T, hook *tarGzLogCapture) {
	t.Helper()
	origLog := global.LOG
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)
	logger.AddHook(hook)
	global.LOG = logger
	t.Cleanup(func() { global.LOG = origLog })
}

// TestTarGzArchiverEncryptedRoundTrip guards the fd-passing migration: the
// Compress path encrypts through `openssl -pass fd:3` inside a bash pipeline
// (secret inherited over fd 3 from the ExtraFiles-aware exec helper), and the
// produced archive must be extractable by the panel's own decrypt path
// (Extract -> buildDecryptCmd). The secret must never appear in any logged
// command, because the logged string is exactly what lands in the bash -c
// argv.
func TestTarGzArchiverEncryptedRoundTrip(t *testing.T) {
	capture := &tarGzLogCapture{}
	swapTarGzDebugLog(t, capture)

	const secret = "round-trip S3cret.42"
	base := t.TempDir()
	srcDir := filepath.Join(base, "src")
	if err := os.MkdirAll(srcDir, 0755); err != nil {
		t.Fatalf("mkdir src: %v", err)
	}
	source := filepath.Join(srcDir, "payload.txt")
	if err := os.WriteFile(source, []byte("fd inheritance round trip"), 0644); err != nil {
		t.Fatalf("write source: %v", err)
	}

	outDir := filepath.Join(base, "out")
	if err := os.MkdirAll(outDir, 0755); err != nil {
		t.Fatalf("mkdir out: %v", err)
	}
	archive := filepath.Join(outDir, "enc.tar.gz")
	shellArchiver := NewTarGzArchiver()
	if err := shellArchiver.Compress([]string{source}, archive, secret); err != nil {
		t.Fatalf("Compress encrypted tar.gz: %v", err)
	}
	info, err := os.Stat(archive)
	if err != nil {
		t.Fatalf("encrypted archive not created: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("encrypted archive is empty")
	}

	dstDir := filepath.Join(base, "extract")
	if err := os.MkdirAll(dstDir, 0755); err != nil {
		t.Fatalf("mkdir dst: %v", err)
	}
	if err := shellArchiver.Extract(archive, dstDir, secret); err != nil {
		t.Fatalf("Extract encrypted tar.gz: %v", err)
	}
	content, err := os.ReadFile(filepath.Join(dstDir, "payload.txt"))
	if err != nil {
		t.Fatalf("read extracted file: %v", err)
	}
	if string(content) != "fd inheritance round trip" {
		t.Fatalf("extracted content = %q, want %q", content, "fd inheritance round trip")
	}

	// The captured debug lines are the exact bash -c argv strings: none may
	// carry the secret, the encrypted branch must use -pass fd:3 and no -k.
	for _, msg := range capture.messages() {
		if strings.Contains(msg, secret) {
			t.Fatalf("logged command leaks the secret: %s", msg)
		}
		if strings.Contains(msg, "-k ") {
			t.Fatalf("logged command still passes -k: %s", msg)
		}
	}
	joined := strings.Join(capture.messages(), "\n")
	if !strings.Contains(joined, "-pass fd:3") {
		t.Fatalf("logged command does not use -pass fd:3, commands:\n%s", joined)
	}
}

// TestTarGzArchiverExtractLegacyKFormat pins backward compatibility: archives
// produced by the old `openssl enc -aes-256-cbc -salt -k <secret>` command
// (the pre-migration format, identical KDF) must still be extractable by the
// new fd-based decrypt path.
func TestTarGzArchiverExtractLegacyKFormat(t *testing.T) {
	plainPath := writeTarGzToFile(t, func(tw *tar.Writer) {
		if err := addTarEntry(tw, "legacy.txt", "legacy k-format content"); err != nil {
			t.Fatalf("write entry: %v", err)
		}
	})
	const secret = "legacy k secret"
	legacyEncrypted := encryptTarGzForTest(t, plainPath, secret)

	dstDir := t.TempDir()
	if err := NewTarGzArchiver().Extract(legacyEncrypted, dstDir, secret); err != nil {
		t.Fatalf("Extract legacy -k archive: %v", err)
	}
	content, err := os.ReadFile(filepath.Join(dstDir, "legacy.txt"))
	if err != nil {
		t.Fatalf("read extracted file: %v", err)
	}
	if string(content) != "legacy k-format content" {
		t.Fatalf("extracted content = %q, want %q", content, "legacy k-format content")
	}
}

// TestTarGzArchiverExtractWrongSecretFails checks that a wrong password on
// the migrated path surfaces as an error instead of silently extracting
// garbage.
func TestTarGzArchiverExtractWrongSecretFails(t *testing.T) {
	plainPath := writeTarGzToFile(t, func(tw *tar.Writer) {
		if err := addTarEntry(tw, "file.txt", "encrypted content"); err != nil {
			t.Fatalf("write entry: %v", err)
		}
	})
	encrypted := encryptTarGzForTest(t, plainPath, "right secret")
	if err := NewTarGzArchiver().Extract(encrypted, t.TempDir(), "wrong secret"); err == nil {
		t.Fatal("Extract with wrong secret: expected error, got nil")
	}
}

// TestTarGzCompressProducesPanelDecryptableArchive re-checks at the archiver
// level that the new encrypt output is consumable by the panel's FileOp
// decrypt path (the same openssl invocation used by Decompress).
func TestTarGzCompressProducesPanelDecryptableArchive(t *testing.T) {
	const secret = "panel decrypt path"
	base := t.TempDir()
	srcDir := filepath.Join(base, "src")
	if err := os.MkdirAll(srcDir, 0755); err != nil {
		t.Fatalf("mkdir src: %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "data.txt"), []byte("panel data"), 0644); err != nil {
		t.Fatalf("write source: %v", err)
	}
	outDir := filepath.Join(base, "out")
	if err := os.MkdirAll(outDir, 0755); err != nil {
		t.Fatalf("mkdir out: %v", err)
	}
	archive := filepath.Join(outDir, "enc.tar.gz")
	if err := NewTarGzArchiver().Compress([]string{filepath.Join(srcDir, "data.txt")}, archive, secret); err != nil {
		t.Fatalf("Compress: %v", err)
	}

	decryptedPath, err := decryptTarGz(archive, secret)
	if err != nil {
		t.Fatalf("panel decrypt path cannot open new-format archive: %v", err)
	}
	defer os.Remove(decryptedPath)
	members, err := exec.Command("tar", "-tzf", decryptedPath).CombinedOutput()
	if err != nil {
		t.Fatalf("decrypted archive is not a valid tar.gz: %v, output: %s", err, members)
	}
	if !strings.Contains(string(members), "data.txt") {
		t.Fatalf("decrypted archive misses data.txt, members:\n%s", members)
	}
}
