package files

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/buserr"
	"github.com/1Panel-dev/1Panel/backend/constant"
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

// assertCmdIllegal fails the test when err is not the ErrCmdIllegal business
// error returned by the shell archiver validation.
func assertCmdIllegal(t *testing.T, context string, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: expected error, got nil", context)
	}
	be, ok := err.(buserr.BusinessError)
	if !ok || be.Msg != constant.ErrCmdIllegal {
		t.Fatalf("%s: expected %s business error, got: %v", context, constant.ErrCmdIllegal, err)
	}
}

// TestShellArchiverInjectionRejected proves that injection payloads in the
// source path, destination, output file or source name are rejected by
// validation before any shell command is built: every call fails with the
// ErrCmdIllegal business error and no payload manages to create the marker
// file.
func TestShellArchiverInjectionRejected(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "pwned")
	pathPayloads := []string{
		fmt.Sprintf("/tmp/a; touch %s", marker),
		fmt.Sprintf("/tmp/$(touch %s)", marker),
		fmt.Sprintf("/tmp/`touch %s`", marker),
		fmt.Sprintf("/tmp/a& touch %s", marker),
		fmt.Sprintf("/tmp/a| touch %s", marker),
		fmt.Sprintf("/tmp/a\n touch %s", marker),
		"/tmp/a'b",
		`/tmp/a"b`,
		"/tmp/a>b",
		fmt.Sprintf("/tmp/$(touch %s).tar.gz", marker),
	}
	for _, p := range pathPayloads {
		dst := t.TempDir()
		out := filepath.Join(t.TempDir(), "out.tar.gz")

		assertCmdIllegal(t, fmt.Sprintf("ZipArchiver.Extract src %q", p), NewZipArchiver().Extract(p, dst, ""))
		assertCmdIllegal(t, fmt.Sprintf("TarArchiver.Extract src %q", p), NewTarArchiver(Tar).Extract(p, dst, ""))
		assertCmdIllegal(t, fmt.Sprintf("TarGzArchiver.Extract src %q", p), NewTarGzArchiver().Extract(p, dst, ""))
		assertCmdIllegal(t, fmt.Sprintf("ZipArchiver.Extract dst %q", p), NewZipArchiver().Extract(filepath.Join(t.TempDir(), "src.zip"), p, ""))
		assertCmdIllegal(t, fmt.Sprintf("TarGzArchiver.Compress src %q", p), NewTarGzArchiver().Compress([]string{p}, out, ""))

		if _, err := os.Stat(marker); err == nil {
			t.Fatalf("payload %q executed a shell command and created %s", p, marker)
		}
	}

	// ZipArchiver.Compress only interpolates the source basenames into its
	// command (the parent dir is only used as working directory), so its
	// injection vector is a poisoned file name
	namePayloads := []string{
		"$(touch .pwned)",
		"`touch .pwned`",
		"a;b",
		"a&b",
		"a|b",
		"a'b",
		`a"b`,
		"a>b",
		"a<b",
		"$(id).txt",
	}
	for _, p := range namePayloads {
		out := filepath.Join(t.TempDir(), "out.zip")
		assertCmdIllegal(t, fmt.Sprintf("ZipArchiver.Compress src name %q", p), NewZipArchiver().Compress([]string{"/data/dir/" + p}, out, ""))
	}

	// the secret is interpolated into openssl enc -k '...' by the tar.gz
	// archiver: a single quote must not break out of the quoting
	src := filepath.Join(t.TempDir(), "src.txt")
	if err := os.WriteFile(src, []byte("x"), 0644); err != nil {
		t.Fatalf("write src: %v", err)
	}
	secretPayload := fmt.Sprintf("'; touch %s ; '", marker)
	assertCmdIllegal(t, "TarGzArchiver.Extract secret", NewTarGzArchiver().Extract(src, t.TempDir(), secretPayload))
	assertCmdIllegal(t, "TarGzArchiver.Compress secret", NewTarGzArchiver().Compress([]string{src}, filepath.Join(t.TempDir(), "out.tar.gz"), secretPayload))
	if _, err := os.Stat(marker); err == nil {
		t.Fatalf("secret payload executed a shell command and created %s", marker)
	}
}

// TestDecompressInjectionRejected feeds injection payloads through
// FileOp.Decompress. The source file is garbage so the SDK path fails and the
// shell fallback is reached; the payloads must be rejected by validation
// instead of being interpolated into a bash -c command.
func TestDecompressInjectionRejected(t *testing.T) {
	op := NewFileOp()
	src := filepath.Join(t.TempDir(), "src.tar.gz")
	if err := os.WriteFile(src, []byte("not an archive"), 0644); err != nil {
		t.Fatalf("write src: %v", err)
	}
	marker := filepath.Join(t.TempDir(), "pwned")

	dstPayload := t.TempDir() + fmt.Sprintf("; touch %s", marker)
	assertCmdIllegal(t, "payload in dst", op.Decompress(src, dstPayload, TarGz, ""))
	secretPayload := fmt.Sprintf("'; touch %s ; '", marker)
	assertCmdIllegal(t, "payload in secret", op.Decompress(src, t.TempDir(), TarGz, secretPayload))
	assertCmdIllegal(t, "payload in src", op.Decompress(fmt.Sprintf("$(touch %s)", marker), t.TempDir(), TarGz, ""))

	if _, err := os.Stat(marker); err == nil {
		t.Fatalf("injection payload executed a shell command and created %s", marker)
	}
}

// TestCompressDecompressRoundTrip compresses sample files (including names
// with spaces and CJK characters) and extracts them again through the SDK
// path, for zip and tar.gz.
func TestCompressDecompressRoundTrip(t *testing.T) {
	op := NewFileOp()
	for _, cType := range []CompressType{Zip, TarGz} {
		t.Run(string(cType), func(t *testing.T) {
			srcDir := t.TempDir()
			sources := []string{
				filepath.Join(srcDir, "a b.txt"),
				filepath.Join(srcDir, "数据.txt"),
			}
			if err := os.WriteFile(sources[0], []byte("round trip"), 0644); err != nil {
				t.Fatalf("write source: %v", err)
			}
			if err := os.WriteFile(sources[1], []byte("你好 1Panel"), 0644); err != nil {
				t.Fatalf("write source: %v", err)
			}

			outDir := t.TempDir()
			name := "archive." + string(cType)
			if err := op.Compress(sources, outDir, name, cType, ""); err != nil {
				t.Fatalf("Compress %s: %v", cType, err)
			}
			dst := t.TempDir()
			if err := op.Decompress(filepath.Join(outDir, name), dst, cType, ""); err != nil {
				t.Fatalf("Decompress %s: %v", cType, err)
			}
			content, err := os.ReadFile(filepath.Join(dst, "a b.txt"))
			if err != nil {
				t.Fatalf("read extracted file: %v", err)
			}
			if string(content) != "round trip" {
				t.Fatalf("extracted content = %q, want %q", content, "round trip")
			}
			content, err = os.ReadFile(filepath.Join(dst, "数据.txt"))
			if err != nil {
				t.Fatalf("read extracted file: %v", err)
			}
			if string(content) != "你好 1Panel" {
				t.Fatalf("extracted content = %q, want %q", content, "你好 1Panel")
			}
		})
	}
}

// TestCompressDecompressEncryptedTarGz checks that an openssl-encrypted
// tar.gz, which the SDK cannot handle, still round-trips through the
// validated shell archiver.
func TestCompressDecompressEncryptedTarGz(t *testing.T) {
	op := NewFileOp()
	srcDir := t.TempDir()
	source := filepath.Join(srcDir, "secret.txt")
	if err := os.WriteFile(source, []byte("top secret"), 0644); err != nil {
		t.Fatalf("write source: %v", err)
	}
	outDir := t.TempDir()
	if err := op.Compress([]string{source}, outDir, "enc.tar.gz", TarGz, "my secret phrase"); err != nil {
		t.Fatalf("Compress encrypted tar.gz: %v", err)
	}
	dst := t.TempDir()
	if err := op.Decompress(filepath.Join(outDir, "enc.tar.gz"), dst, TarGz, "my secret phrase"); err != nil {
		t.Fatalf("Decompress encrypted tar.gz: %v", err)
	}
	content, err := os.ReadFile(filepath.Join(dst, "secret.txt"))
	if err != nil {
		t.Fatalf("read extracted file: %v", err)
	}
	if string(content) != "top secret" {
		t.Fatalf("extracted content = %q, want %q", content, "top secret")
	}
}
