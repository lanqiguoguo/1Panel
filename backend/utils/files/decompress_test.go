package files

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// writeTarGzToFile writes the tar archive built by build into a temp file and
// returns its path, so it can be handed to decompressWithSDK.
func writeTarGzToFile(t *testing.T, build func(tw *tar.Writer)) string {
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
	archivePath := filepath.Join(t.TempDir(), "evil.tar.gz")
	if err := os.WriteFile(archivePath, buf.Bytes(), 0644); err != nil {
		t.Fatalf("write archive: %v", err)
	}
	return archivePath
}

// addTarEntry writes a regular file entry with the given name and content.
func addTarEntry(tw *tar.Writer, name, content string) error {
	hdr := &tar.Header{
		Name:     name,
		Mode:     0644,
		Size:     int64(len(content)),
		Typeflag: tar.TypeReg,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	if _, err := io.WriteString(tw, content); err != nil {
		return err
	}
	return nil
}

func TestDecompressWithSDKPathTraversal(t *testing.T) {
	op := NewFileOp()
	cases := []struct {
		name     string
		fileName string
	}{
		{"parent traversal", "../evil.txt"},
		{"deep parent traversal", "../../evil.txt"},
		{"nested parent traversal", "sub/../../evil.txt"},
		{"absolute path", "/etc/evil.txt"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			archivePath := writeTarGzToFile(t, func(tw *tar.Writer) {
				if err := addTarEntry(tw, tc.fileName, "evil"); err != nil {
					t.Fatalf("write entry: %v", err)
				}
			})
			dst := t.TempDir()
			err := op.decompressWithSDK(archivePath, dst, SdkTarGz)
			if err == nil {
				t.Fatalf("Decompress with entry %q: expected error, got nil", tc.fileName)
			}
			if _, statErr := os.Stat(filepath.Join(filepath.Dir(dst), "evil.txt")); statErr == nil {
				t.Fatalf("Decompress with entry %q: evil.txt was written outside dst", tc.fileName)
			}
			if _, statErr := os.Stat("/etc/evil.txt"); statErr == nil {
				t.Fatalf("Decompress with entry %q: evil.txt was written to /etc", tc.fileName)
			}
		})
	}
}

func TestDecompressWithSDKSymlinkRejected(t *testing.T) {
	op := NewFileOp()
	archivePath := writeTarGzToFile(t, func(tw *tar.Writer) {
		hdr := &tar.Header{
			Name:     "link",
			Mode:     0777,
			Typeflag: tar.TypeSymlink,
			Linkname: "/etc/passwd",
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("write symlink entry: %v", err)
		}
	})
	dst := t.TempDir()
	if err := op.decompressWithSDK(archivePath, dst, SdkTarGz); err == nil {
		t.Fatal("Decompress with symlink entry: expected error, got nil")
	}
	if _, err := os.Stat(filepath.Join(dst, "link")); err == nil {
		t.Fatal("symlink entry was written to dst")
	}
}

func TestDecompressWithSDKNormal(t *testing.T) {
	op := NewFileOp()
	archivePath := writeTarGzToFile(t, func(tw *tar.Writer) {
		if err := addTarEntry(tw, "dir/nested/file.txt", "hello world"); err != nil {
			t.Fatalf("write entry: %v", err)
		}
	})
	dst := t.TempDir()
	if err := op.decompressWithSDK(archivePath, dst, SdkTarGz); err != nil {
		t.Fatalf("Decompress normal archive: unexpected error: %v", err)
	}
	content, err := os.ReadFile(filepath.Join(dst, "dir", "nested", "file.txt"))
	if err != nil {
		t.Fatalf("read extracted file: %v", err)
	}
	if string(content) != "hello world" {
		t.Fatalf("extracted content = %q, want %q", string(content), "hello world")
	}
}

func TestDecompressWithSDKEntryLimit(t *testing.T) {
	op := NewFileOp()
	archivePath := writeTarGzToFile(t, func(tw *tar.Writer) {
		// exceed the 100000 entry limit without materializing big content
		for i := 0; i < decompressMaxEntries+1; i++ {
			if err := addTarEntry(tw, "f", ""); err != nil {
				t.Fatalf("write entry %d: %v", i, err)
			}
		}
	})
	dst := t.TempDir()
	if err := op.decompressWithSDK(archivePath, dst, SdkTarGz); err == nil {
		t.Fatal("Decompress with too many entries: expected error, got nil")
	}
	entries, err := os.ReadDir(dst)
	if err != nil {
		t.Fatalf("read dst: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d files in dst, want 1 (limit check should stop early)", len(entries))
	}
}

func TestDecompressWithSDKSizeLimit(t *testing.T) {
	op := NewFileOp()
	const maxSize = 1024
	archivePath := writeTarGzToFile(t, func(tw *tar.Writer) {
		// a single entry larger than the total size limit
		content := bytes.Repeat([]byte("x"), maxSize*2)
		if err := addTarEntry(tw, "huge", string(content)); err != nil {
			t.Fatalf("write entry: %v", err)
		}
	})
	dst := t.TempDir()
	if err := op.decompressWithSDKWithLimits(archivePath, dst, SdkTarGz, decompressMaxEntries, maxSize); err == nil {
		t.Fatal("Decompress with oversized entry: expected error, got nil")
	}
	if info, err := os.Stat(filepath.Join(dst, "huge")); err == nil && info.Size() > maxSize {
		t.Fatalf("oversized file was written beyond the limit (%d bytes)", info.Size())
	}
}
