package service

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/sirupsen/logrus"
)

func writeHandleUnTarArchive(t *testing.T, build func(*tar.Writer)) string {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	build(tw)
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar writer: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("close gzip writer: %v", err)
	}
	archivePath := filepath.Join(t.TempDir(), "backup.tar.gz")
	if err := os.WriteFile(archivePath, buf.Bytes(), 0644); err != nil {
		t.Fatalf("write archive: %v", err)
	}
	return archivePath
}

func addHandleUnTarFile(t *testing.T, tw *tar.Writer, name, content string) {
	t.Helper()
	hdr := &tar.Header{
		Name:     name,
		Mode:     0644,
		Size:     int64(len(content)),
		Typeflag: tar.TypeReg,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatalf("write %q header: %v", name, err)
	}
	if _, err := io.WriteString(tw, content); err != nil {
		t.Fatalf("write %q content: %v", name, err)
	}
}

func encryptHandleUnTarArchive(t *testing.T, source, secret string) string {
	t.Helper()
	archivePath := filepath.Join(t.TempDir(), "encrypted backup.tar.gz")
	command := exec.Command("openssl", "enc", "-aes-256-cbc", "-salt", "-k", secret, "-in", source, "-out", archivePath)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("encrypt archive: %v, output: %s", err, output)
	}
	return archivePath
}

func ensureHandleUnTarLogger(t *testing.T) {
	t.Helper()
	if global.LOG != nil {
		return
	}
	global.LOG = logrus.New()
	t.Cleanup(func() { global.LOG = nil })
}

func TestHandleUnTarExtractsPlainAndEncryptedArchives(t *testing.T) {
	ensureHandleUnTarLogger(t)
	for _, handler := range []struct {
		name string
		call func(string, string, string) error
	}{
		{name: "backup", call: handleUnTar},
		{name: "snapshot", call: (&SnapshotService{}).handleUnTar},
	} {
		t.Run(handler.name, func(t *testing.T) {
			for _, archiveCase := range []struct {
				name      string
				encrypted bool
			}{
				{name: "plain", encrypted: false},
				{name: "encrypted", encrypted: true},
			} {
				t.Run(archiveCase.name, func(t *testing.T) {
					archivePath := writeHandleUnTarArchive(t, func(tw *tar.Writer) {
						addHandleUnTarFile(t, tw, "payload/file.txt", "recovery content")
					})
					secret := ""
					if archiveCase.encrypted {
						secret = "test secret phrase"
						archivePath = encryptHandleUnTarArchive(t, archivePath, secret)
					}

					baseDir := filepath.Join(t.TempDir(), "backup data")
					targetDir := filepath.Join(baseDir, "extract here")
					if err := handler.call(archivePath, targetDir, secret); err != nil {
						t.Fatalf("handleUnTar() error = %v", err)
					}
					content, err := os.ReadFile(filepath.Join(targetDir, "payload", "file.txt"))
					if err != nil {
						t.Fatalf("read extracted file: %v", err)
					}
					if string(content) != "recovery content" {
						t.Fatalf("extracted content = %q, want %q", content, "recovery content")
					}
				})
			}
		})
	}
}

func TestHandleUnTarRejectsUnsafeArchiveEntries(t *testing.T) {
	ensureHandleUnTarLogger(t)
	baseDir := t.TempDir()
	outside := filepath.Join(baseDir, "outside.txt")
	tests := []struct {
		name  string
		build func(*tar.Writer)
	}{
		{
			name: "parent traversal",
			build: func(tw *tar.Writer) {
				addHandleUnTarFile(t, tw, "../outside.txt", "escape")
			},
		},
		{
			name: "absolute path",
			build: func(tw *tar.Writer) {
				addHandleUnTarFile(t, tw, outside, "escape")
			},
		},
		{
			name: "symbolic link",
			build: func(tw *tar.Writer) {
				hdr := &tar.Header{Name: "link", Mode: 0777, Typeflag: tar.TypeSymlink, Linkname: outside}
				if err := tw.WriteHeader(hdr); err != nil {
					t.Fatalf("write symlink header: %v", err)
				}
			},
		},
		{
			name: "hard link",
			build: func(tw *tar.Writer) {
				hdr := &tar.Header{Name: "hardlink", Mode: 0644, Typeflag: tar.TypeLink, Linkname: "payload.txt"}
				if err := tw.WriteHeader(hdr); err != nil {
					t.Fatalf("write hard-link header: %v", err)
				}
			},
		},
	}

	for _, handler := range []struct {
		name string
		call func(string, string, string) error
	}{
		{name: "backup", call: handleUnTar},
		{name: "snapshot", call: (&SnapshotService{}).handleUnTar},
	} {
		t.Run(handler.name, func(t *testing.T) {
			for _, tc := range tests {
				t.Run(tc.name, func(t *testing.T) {
					targetDir := filepath.Join(baseDir, handler.name, tc.name)
					archivePath := writeHandleUnTarArchive(t, tc.build)
					if err := handler.call(archivePath, targetDir, ""); err == nil {
						t.Fatal("handleUnTar() error = nil, want unsafe archive error")
					}
					if _, err := os.Stat(outside); err == nil {
						t.Fatal("unsafe archive wrote outside the destination")
					}
					if info, err := os.Lstat(filepath.Join(targetDir, "link")); err == nil && info.Mode()&os.ModeSymlink != 0 {
						t.Fatal("unsafe archive created a symbolic link")
					}
					if _, err := os.Lstat(filepath.Join(targetDir, "hardlink")); err == nil {
						t.Fatal("unsafe archive created a hard link")
					}
				})
			}
		})
	}
}

func TestHandleUnTarRejectsCommandInjectionArguments(t *testing.T) {
	ensureHandleUnTarLogger(t)
	marker := filepath.Join(t.TempDir(), "command-injection-marker")
	archivePath := writeHandleUnTarArchive(t, func(tw *tar.Writer) {
		addHandleUnTarFile(t, tw, "payload.txt", "content")
	})
	validTarget := filepath.Join(t.TempDir(), "extract")
	tests := []struct {
		name       string
		sourceFile string
		targetDir  string
		secret     string
	}{
		{
			name:       "source",
			sourceFile: "$(touch " + marker + ")",
			targetDir:  validTarget,
		},
		{
			name:       "target",
			sourceFile: archivePath,
			targetDir:  "$(touch " + marker + ")",
		},
		{
			name:       "secret",
			sourceFile: archivePath,
			targetDir:  validTarget,
			secret:     "$(touch " + marker + ")",
		},
	}

	for _, handler := range []struct {
		name string
		call func(string, string, string) error
	}{
		{name: "backup", call: handleUnTar},
		{name: "snapshot", call: (&SnapshotService{}).handleUnTar},
	} {
		t.Run(handler.name, func(t *testing.T) {
			for _, tc := range tests {
				t.Run(tc.name, func(t *testing.T) {
					if err := handler.call(tc.sourceFile, tc.targetDir, tc.secret); err == nil {
						t.Fatal("handleUnTar() error = nil, want command argument validation error")
					}
					if _, err := os.Stat(marker); err == nil {
						t.Fatal("command injection marker was created")
					}
				})
			}
		})
	}
}
