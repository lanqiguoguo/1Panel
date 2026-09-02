package files

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/buserr"
	"github.com/1Panel-dev/1Panel/backend/constant"
	"github.com/mholt/archiver/v4"
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

func encryptTarGzForTest(t *testing.T, source, secret string) string {
	t.Helper()
	encryptedPath := filepath.Join(t.TempDir(), "encrypted.tar.gz")
	command := exec.Command("openssl", "enc", "-aes-256-cbc", "-salt", "-k", secret, "-in", source, "-out", encryptedPath)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("encrypt tar.gz: %v, output: %s", err, output)
	}
	return encryptedPath
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

// addTarDirEntry writes an explicit directory entry with the given mode.
func addTarDirEntry(tw *tar.Writer, name string, mode int64) error {
	hdr := &tar.Header{
		Name:     name,
		Mode:     mode,
		Typeflag: tar.TypeDir,
	}
	return tw.WriteHeader(hdr)
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
		{"current dir entry", "."},
		{"current dir with dot component", "./."},
		{"parent via dot prefix", "./.."},
		{"parent traversal via dot prefix", "./../evil.txt"},
		{"trailing dotdot entry", "x/.."},
		{"folded dotdot entry", "a/../b"},
		{"nested dotdot entry", "x/../y"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			archivePath := writeTarGzToFile(t, func(tw *tar.Writer) {
				if err := addTarEntry(tw, tc.fileName, "evil"); err != nil {
					t.Fatalf("write entry: %v", err)
				}
			})
			dst := t.TempDir()
			marker := filepath.Join(dst, "marker.txt")
			if err := os.WriteFile(marker, []byte("keep me"), 0644); err != nil {
				t.Fatalf("write marker: %v", err)
			}
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
			if _, statErr := os.Stat(filepath.Join(dst, "b")); statErr == nil {
				t.Fatalf("Decompress with entry %q: folded path was written to dst", tc.fileName)
			}
			if _, statErr := os.Stat(filepath.Join(dst, "y")); statErr == nil {
				t.Fatalf("Decompress with entry %q: folded path was written to dst", tc.fileName)
			}
			if _, statErr := os.Stat(filepath.Join(dst, "evil.txt")); statErr == nil {
				t.Fatalf("Decompress with entry %q: evil.txt was written to dst", tc.fileName)
			}
			// the destination itself must not have been replaced or truncated
			if _, statErr := os.Stat(dst); statErr != nil {
				t.Fatalf("Decompress with entry %q: dst directory is gone: %v", tc.fileName, statErr)
			}
			if content, readErr := os.ReadFile(marker); readErr != nil || string(content) != "keep me" {
				t.Fatalf("Decompress with entry %q: dst contents were tampered with (marker read err %v, content %q)", tc.fileName, readErr, string(content))
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

func TestDecompressRejectsUnsafeTarGzWithoutShellFallback(t *testing.T) {
	cases := []struct {
		name string
		add  func(tw *tar.Writer, outside string)
	}{
		{
			name: "parent traversal",
			add: func(tw *tar.Writer, outside string) {
				if err := addTarEntry(tw, "../"+filepath.Base(outside), "evil"); err != nil {
					t.Fatalf("write traversal entry: %v", err)
				}
			},
		},
		{
			name: "absolute path",
			add: func(tw *tar.Writer, outside string) {
				if err := addTarEntry(tw, outside, "evil"); err != nil {
					t.Fatalf("write absolute entry: %v", err)
				}
			},
		},
		{
			name: "symbolic link",
			add: func(tw *tar.Writer, outside string) {
				hdr := &tar.Header{Name: "link", Mode: 0777, Typeflag: tar.TypeSymlink, Linkname: outside}
				if err := tw.WriteHeader(hdr); err != nil {
					t.Fatalf("write symlink entry: %v", err)
				}
			},
		},
		{
			name: "hard link",
			add: func(tw *tar.Writer, outside string) {
				hdr := &tar.Header{Name: "hard-link", Mode: 0644, Typeflag: tar.TypeLink, Linkname: "../" + filepath.Base(outside)}
				if err := tw.WriteHeader(hdr); err != nil {
					t.Fatalf("write hard link entry: %v", err)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			dst := filepath.Join(root, "destination")
			if err := os.Mkdir(dst, 0755); err != nil {
				t.Fatalf("create destination: %v", err)
			}
			outside := filepath.Join(root, "escaped.txt")
			archivePath := writeTarGzToFile(t, func(tw *tar.Writer) { tc.add(tw, outside) })

			err := NewFileOp().Decompress(archivePath, dst, TarGz, "")
			if err == nil {
				t.Fatalf("Decompress %s: expected unsafe archive error", tc.name)
			}
			if !errors.Is(err, errUnsafeArchive) {
				t.Fatalf("Decompress %s: expected unsafe archive error, got %v", tc.name, err)
			}
			if _, statErr := os.Lstat(outside); statErr == nil {
				t.Fatalf("Decompress %s: shell fallback wrote outside destination", tc.name)
			}
			if tc.name == "symbolic link" {
				if _, statErr := os.Lstat(filepath.Join(dst, "link")); statErr == nil {
					t.Fatalf("Decompress %s: shell fallback created a symlink", tc.name)
				}
			}
		})
	}
}

func TestDecompressEncryptedUnsafeTarGzWithoutShellFallback(t *testing.T) {
	root := t.TempDir()
	dst := filepath.Join(root, "destination")
	if err := os.Mkdir(dst, 0755); err != nil {
		t.Fatalf("create destination: %v", err)
	}
	outside := filepath.Join(root, "escaped.txt")
	plainPath := writeTarGzToFile(t, func(tw *tar.Writer) {
		if err := addTarEntry(tw, "../"+filepath.Base(outside), "evil"); err != nil {
			t.Fatalf("write traversal entry: %v", err)
		}
	})
	const secret = "attacker supplied secret"
	encryptedPath := encryptTarGzForTest(t, plainPath, secret)

	err := NewFileOp().Decompress(encryptedPath, dst, TarGz, secret)
	if err == nil {
		t.Fatal("Decompress encrypted unsafe archive: expected unsafe archive error")
	}
	if !errors.Is(err, errUnsafeArchive) {
		t.Fatalf("Decompress encrypted unsafe archive: expected unsafe archive error, got %v", err)
	}
	if _, statErr := os.Lstat(outside); statErr == nil {
		t.Fatal("Decompress encrypted unsafe archive: shell fallback wrote outside destination")
	}
}

// TestDecompressRejectsDotAndDotdotEntries feeds archives whose members resolve
// to the destination itself or to a silently re-folded path inside it (".",
// "./.", "./..", "./../evil.txt", "x/..", "a/../b", "x/../y") through the full
// Decompress entry point, plain and openssl-encrypted. All of them must be
// rejected as unsafe and must not touch the destination. ("./evil.txt" is NOT
// in this list: it folds to "evil.txt" inside dst and is a legitimate entry
// produced by "tar -cf x.tar ./src"; see TestDecompressAllowsDotPrefixEntries.)
func TestDecompressRejectsDotAndDotdotEntries(t *testing.T) {
	op := NewFileOp()
	cases := []struct {
		name     string
		fileName string
	}{
		{"current dir entry", "."},
		{"current dir with dot component", "./."},
		{"parent via dot prefix", "./.."},
		{"parent traversal via dot prefix", "./../evil.txt"},
		{"trailing dotdot entry", "x/.."},
		{"folded dotdot entry", "a/../b"},
		{"nested dotdot entry", "x/../y"},
	}
	for _, tc := range cases {
		t.Run(tc.name+" plain", func(t *testing.T) {
			root := t.TempDir()
			dst := filepath.Join(root, "destination")
			if err := os.Mkdir(dst, 0755); err != nil {
				t.Fatalf("create destination: %v", err)
			}
			marker := filepath.Join(dst, "marker.txt")
			if err := os.WriteFile(marker, []byte("keep me"), 0644); err != nil {
				t.Fatalf("write marker: %v", err)
			}
			archivePath := writeTarGzToFile(t, func(tw *tar.Writer) {
				if err := addTarEntry(tw, tc.fileName, "evil"); err != nil {
					t.Fatalf("write entry: %v", err)
				}
			})
			err := op.Decompress(archivePath, dst, TarGz, "")
			if err == nil {
				t.Fatalf("Decompress %q: expected unsafe archive error, got nil", tc.fileName)
			}
			if !errors.Is(err, errUnsafeArchive) {
				t.Fatalf("Decompress %q: expected unsafe archive error, got %v", tc.fileName, err)
			}
			if _, statErr := os.Stat(filepath.Join(dst, "evil.txt")); statErr == nil {
				t.Fatalf("Decompress %q: evil.txt was written to dst", tc.fileName)
			}
			if _, statErr := os.Stat(filepath.Join(dst, "b")); statErr == nil {
				t.Fatalf("Decompress %q: folded path b was written to dst", tc.fileName)
			}
			if _, statErr := os.Stat(filepath.Join(dst, "y")); statErr == nil {
				t.Fatalf("Decompress %q: folded path y was written to dst", tc.fileName)
			}
			if _, statErr := os.Stat(dst); statErr != nil {
				t.Fatalf("Decompress %q: dst directory is gone: %v", tc.fileName, statErr)
			}
			if content, readErr := os.ReadFile(marker); readErr != nil || string(content) != "keep me" {
				t.Fatalf("Decompress %q: dst contents were tampered with (marker read err %v, content %q)", tc.fileName, readErr, string(content))
			}
		})
		t.Run(tc.name+" encrypted", func(t *testing.T) {
			root := t.TempDir()
			dst := filepath.Join(root, "destination")
			if err := os.Mkdir(dst, 0755); err != nil {
				t.Fatalf("create destination: %v", err)
			}
			marker := filepath.Join(dst, "marker.txt")
			if err := os.WriteFile(marker, []byte("keep me"), 0644); err != nil {
				t.Fatalf("write marker: %v", err)
			}
			plainPath := writeTarGzToFile(t, func(tw *tar.Writer) {
				if err := addTarEntry(tw, tc.fileName, "evil"); err != nil {
					t.Fatalf("write entry: %v", err)
				}
			})
			const secret = "attacker supplied secret"
			encryptedPath := encryptTarGzForTest(t, plainPath, secret)
			err := op.Decompress(encryptedPath, dst, TarGz, secret)
			if err == nil {
				t.Fatalf("Decompress encrypted %q: expected unsafe archive error, got nil", tc.fileName)
			}
			if !errors.Is(err, errUnsafeArchive) {
				t.Fatalf("Decompress encrypted %q: expected unsafe archive error, got %v", tc.fileName, err)
			}
			if _, statErr := os.Stat(filepath.Join(dst, "evil.txt")); statErr == nil {
				t.Fatalf("Decompress encrypted %q: evil.txt was written to dst", tc.fileName)
			}
			if _, statErr := os.Stat(dst); statErr != nil {
				t.Fatalf("Decompress encrypted %q: dst directory is gone: %v", tc.fileName, statErr)
			}
			if content, readErr := os.ReadFile(marker); readErr != nil || string(content) != "keep me" {
				t.Fatalf("Decompress encrypted %q: dst contents were tampered with (marker read err %v, content %q)", tc.fileName, readErr, string(content))
			}
		})
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

// TestDecompressNormalEntriesStillSucceed is the regression guard for the
// dot/dotdot hardening: ordinary flat and nested entries must keep extracting
// through the full Decompress entry point.
func TestDecompressNormalEntriesStillSucceed(t *testing.T) {
	op := NewFileOp()
	archivePath := writeTarGzToFile(t, func(tw *tar.Writer) {
		if err := addTarEntry(tw, "file.txt", "flat"); err != nil {
			t.Fatalf("write entry: %v", err)
		}
		if err := addTarEntry(tw, "dir/file.txt", "nested"); err != nil {
			t.Fatalf("write entry: %v", err)
		}
	})
	dst := t.TempDir()
	if err := op.Decompress(archivePath, dst, TarGz, ""); err != nil {
		t.Fatalf("Decompress normal archive: unexpected error: %v", err)
	}
	content, err := os.ReadFile(filepath.Join(dst, "file.txt"))
	if err != nil {
		t.Fatalf("read extracted file: %v", err)
	}
	if string(content) != "flat" {
		t.Fatalf("extracted content = %q, want %q", string(content), "flat")
	}
	content, err = os.ReadFile(filepath.Join(dst, "dir", "file.txt"))
	if err != nil {
		t.Fatalf("read extracted nested file: %v", err)
	}
	if string(content) != "nested" {
		t.Fatalf("extracted content = %q, want %q", string(content), "nested")
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

// TestDecompressDepthLimit guards the P2-3 depth cap: archive entries nested
// more than decompressMaxDepth levels below the destination are rejected with
// the unsafe-archive error, while entries at exactly the limit still extract.
// The cap applies to both the SDK extraction path and the encrypted-archive
// validation path (validateArchiveWithSDK), which share archiveEntryPath.
func TestDecompressDepthLimit(t *testing.T) {
	op := NewFileOp()
	depthName := func(dirs int, leaf string) string {
		return strings.Repeat("d/", dirs) + leaf
	}

	t.Run("over limit rejected", func(t *testing.T) {
		archivePath := writeTarGzToFile(t, func(tw *tar.Writer) {
			if err := addTarEntry(tw, depthName(decompressMaxDepth+1, "file.txt"), "deep"); err != nil {
				t.Fatalf("write entry: %v", err)
			}
		})
		dst := t.TempDir()
		err := op.Decompress(archivePath, dst, TarGz, "")
		if err == nil {
			t.Fatal("Decompress archive deeper than the limit: expected error, got nil")
		}
		if !errors.Is(err, errUnsafeArchive) {
			t.Fatalf("Decompress archive deeper than the limit: expected unsafe archive error, got %v", err)
		}
	})

	t.Run("deep directory entry rejected", func(t *testing.T) {
		archivePath := writeTarGzToFile(t, func(tw *tar.Writer) {
			dir := &tar.Header{Name: depthName(decompressMaxDepth+2, ""), Mode: 0755, Typeflag: tar.TypeDir}
			if err := tw.WriteHeader(dir); err != nil {
				t.Fatalf("write dir entry: %v", err)
			}
		})
		dst := t.TempDir()
		err := op.decompressWithSDK(archivePath, dst, SdkTarGz)
		if err == nil {
			t.Fatal("Decompress with too-deep directory entry: expected error, got nil")
		}
		if !errors.Is(err, errUnsafeArchive) {
			t.Fatalf("Decompress with too-deep directory entry: expected unsafe archive error, got %v", err)
		}
	})

	t.Run("at the limit accepted", func(t *testing.T) {
		archivePath := writeTarGzToFile(t, func(tw *tar.Writer) {
			if err := addTarEntry(tw, depthName(decompressMaxDepth, "file.txt"), "ok"); err != nil {
				t.Fatalf("write entry: %v", err)
			}
		})
		dst := t.TempDir()
		if err := op.Decompress(archivePath, dst, TarGz, ""); err != nil {
			t.Fatalf("Decompress archive at the depth limit: unexpected error: %v", err)
		}
		content, err := os.ReadFile(filepath.Join(append([]string{dst}, strings.Split(depthName(decompressMaxDepth, "file.txt"), "/")...)...))
		if err != nil {
			t.Fatalf("read extracted file at the depth limit: %v", err)
		}
		if string(content) != "ok" {
			t.Fatalf("extracted content = %q, want %q", string(content), "ok")
		}
	})

	t.Run("encrypted archive over limit rejected", func(t *testing.T) {
		plainPath := writeTarGzToFile(t, func(tw *tar.Writer) {
			if err := addTarEntry(tw, depthName(decompressMaxDepth+1, "file.txt"), "deep"); err != nil {
				t.Fatalf("write entry: %v", err)
			}
		})
		const secret = "secret for depth test"
		encryptedPath := encryptTarGzForTest(t, plainPath, secret)
		dst := t.TempDir()
		err := op.Decompress(encryptedPath, dst, TarGz, secret)
		if err == nil {
			t.Fatal("Decompress encrypted archive deeper than the limit: expected error, got nil")
		}
		if !errors.Is(err, errUnsafeArchive) {
			t.Fatalf("Decompress encrypted archive deeper than the limit: expected unsafe archive error, got %v", err)
		}
	})
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
// FileOp.Decompress. The payloads must be rejected before an SDK or shell
// extractor can use them.
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
// TestDecompressAllowsDotPrefixEntries is the P1-4 regression guard: archives
// created with "tar -cf x.tar ./src" or "python tarfile.add('./src')" store
// entries like "./src/", "./src/a.txt" and even the archive root "./". These
// are legitimate — filepath.Clean folds them inside dst — and must extract
// successfully. The "./" root entry must be skipped (it maps to dst itself,
// and creating it could chmod dst with an attacker-controlled mode), with dst
// left untouched: no new files, marker preserved and mode unchanged.
func TestDecompressAllowsDotPrefixEntries(t *testing.T) {
	op := NewFileOp()

	t.Run("tar style ./src entries", func(t *testing.T) {
		archivePath := writeTarGzToFile(t, func(tw *tar.Writer) {
			dir := &tar.Header{Name: "./src/", Mode: 0755, Typeflag: tar.TypeDir}
			if err := tw.WriteHeader(dir); err != nil {
				t.Fatalf("write dir entry: %v", err)
			}
			if err := addTarEntry(tw, "./src/a.txt", "dot prefix"); err != nil {
				t.Fatalf("write entry: %v", err)
			}
		})
		dst := t.TempDir()
		if err := op.Decompress(archivePath, dst, TarGz, ""); err != nil {
			t.Fatalf("Decompress tar-style ./ archive: %v", err)
		}
		content, err := os.ReadFile(filepath.Join(dst, "src", "a.txt"))
		if err != nil {
			t.Fatalf("read extracted file: %v", err)
		}
		if string(content) != "dot prefix" {
			t.Fatalf("extracted content = %q, want %q", string(content), "dot prefix")
		}
	})

	t.Run("archive root ./ entry", func(t *testing.T) {
		archivePath := writeTarGzToFile(t, func(tw *tar.Writer) {
			// "tar -cf x.tar ." emits "./" with the current directory's mode.
			dir := &tar.Header{Name: "./", Mode: 0777, Typeflag: tar.TypeDir}
			if err := tw.WriteHeader(dir); err != nil {
				t.Fatalf("write dir entry: %v", err)
			}
			if err := addTarEntry(tw, "./src/a.txt", "root dot"); err != nil {
				t.Fatalf("write entry: %v", err)
			}
		})
		dst := t.TempDir()
		if err := os.Chmod(dst, 0750); err != nil {
			t.Fatalf("chmod dst: %v", err)
		}
		marker := filepath.Join(dst, "marker.txt")
		if err := os.WriteFile(marker, []byte("keep me"), 0644); err != nil {
			t.Fatalf("write marker: %v", err)
		}
		if err := op.Decompress(archivePath, dst, TarGz, ""); err != nil {
			t.Fatalf("Decompress archive with ./ root entry: %v", err)
		}
		// the "./" entry must have been skipped, not applied to dst
		if info, err := os.Stat(dst); err != nil {
			t.Fatalf("stat dst: %v", err)
		} else if info.Mode().Perm() != 0750 {
			t.Fatalf("dst mode = %v, want 0750 (./ entry must not chmod dst)", info.Mode().Perm())
		}
		if content, err := os.ReadFile(marker); err != nil || string(content) != "keep me" {
			t.Fatalf("dst contents were tampered with (read err %v, content %q)", err, string(content))
		}
		content, err := os.ReadFile(filepath.Join(dst, "src", "a.txt"))
		if err != nil {
			t.Fatalf("read extracted file: %v", err)
		}
		if string(content) != "root dot" {
			t.Fatalf("extracted content = %q, want %q", string(content), "root dot")
		}
	})

	t.Run("./evil folds to evil inside dst", func(t *testing.T) {
		archivePath := writeTarGzToFile(t, func(tw *tar.Writer) {
			if err := addTarEntry(tw, "./evil.txt", "evil"); err != nil {
				t.Fatalf("write entry: %v", err)
			}
		})
		dst := t.TempDir()
		if err := op.Decompress(archivePath, dst, TarGz, ""); err != nil {
			t.Fatalf("Decompress ./evil archive: %v", err)
		}
		content, err := os.ReadFile(filepath.Join(dst, "evil.txt"))
		if err != nil {
			t.Fatalf("read extracted file: %v", err)
		}
		if string(content) != "evil" {
			t.Fatalf("extracted content = %q, want %q", string(content), "evil")
		}
	})
}

// TestDecompressZipWithDotEntries checks the zip side of P1-4: an archive with
// "./", "./sub/" and "./sub/a.txt" entries (as produced by "zip -r x.zip .")
// must extract successfully with the "./" root entry skipped.
func TestDecompressZipWithDotEntries(t *testing.T) {
	op := NewFileOp()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range []struct {
		name    string
		dir     bool
		content string
	}{
		{"./", true, ""},
		{"./sub/", true, ""},
		{"./sub/a.txt", false, "zip dot"},
	} {
		hdr := &zip.FileHeader{Name: e.name, Method: zip.Deflate}
		if e.dir {
			hdr.SetMode(0777 | os.ModeDir)
		} else {
			hdr.SetMode(0644)
		}
		w, err := zw.CreateHeader(hdr)
		if err != nil {
			t.Fatalf("create header %q: %v", e.name, err)
		}
		if !e.dir {
			if _, err := io.WriteString(w, e.content); err != nil {
				t.Fatalf("write content: %v", err)
			}
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip writer: %v", err)
	}
	archivePath := filepath.Join(t.TempDir(), "dot.zip")
	if err := os.WriteFile(archivePath, buf.Bytes(), 0644); err != nil {
		t.Fatalf("write archive: %v", err)
	}

	dst := t.TempDir()
	if err := op.Decompress(archivePath, dst, Zip, ""); err != nil {
		t.Fatalf("Decompress zip with ./ entries: %v", err)
	}
	content, err := os.ReadFile(filepath.Join(dst, "sub", "a.txt"))
	if err != nil {
		t.Fatalf("read extracted file: %v", err)
	}
	if string(content) != "zip dot" {
		t.Fatalf("extracted content = %q, want %q", string(content), "zip dot")
	}
}

// TestDecompressEncryptedTarGzWithDotPrefixEntries covers the encrypted
// compatibility path of P1-4: an openssl-encrypted tar.gz whose members carry
// the "./" prefix must decrypt, pass validateArchiveWithSDK and extract.
func TestDecompressEncryptedTarGzWithDotPrefixEntries(t *testing.T) {
	op := NewFileOp()
	plainPath := writeTarGzToFile(t, func(tw *tar.Writer) {
		dir := &tar.Header{Name: "./", Mode: 0755, Typeflag: tar.TypeDir}
		if err := tw.WriteHeader(dir); err != nil {
			t.Fatalf("write dir entry: %v", err)
		}
		dir = &tar.Header{Name: "./src/", Mode: 0755, Typeflag: tar.TypeDir}
		if err := tw.WriteHeader(dir); err != nil {
			t.Fatalf("write dir entry: %v", err)
		}
		if err := addTarEntry(tw, "./src/a.txt", "encrypted dot"); err != nil {
			t.Fatalf("write entry: %v", err)
		}
	})
	const secret = "secret for dot prefix"
	encryptedPath := encryptTarGzForTest(t, plainPath, secret)

	dst := t.TempDir()
	if err := op.Decompress(encryptedPath, dst, TarGz, secret); err != nil {
		t.Fatalf("Decompress encrypted ./ archive: %v", err)
	}
	content, err := os.ReadFile(filepath.Join(dst, "src", "a.txt"))
	if err != nil {
		t.Fatalf("read extracted file: %v", err)
	}
	if string(content) != "encrypted dot" {
		t.Fatalf("extracted content = %q, want %q", string(content), "encrypted dot")
	}
}

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
// validated compatibility path.
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

// TestBuildDecryptCmdHidesSecretFromCmdline guards P2-4: the password must be
// passed to openssl via -pass fd:3, never through -k, so it cannot leak into
// /proc/<pid>/cmdline.
func TestBuildDecryptCmdHidesSecretFromCmdline(t *testing.T) {
	const secret = "super secret phrase 123"
	cmd, passReader, err := buildDecryptCmd("/tmp/src.tar.gz", "/tmp/out.tar.gz", secret)
	if err != nil {
		t.Fatalf("buildDecryptCmd: %v", err)
	}
	defer passReader.Close()
	joined := strings.Join(cmd.Args, " ")
	if strings.Contains(joined, secret) {
		t.Fatalf("openssl cmdline leaks the secret: %q", joined)
	}
	if strings.Contains(joined, "-k") {
		t.Fatalf("openssl cmdline still uses -k: %q", joined)
	}
	if !strings.Contains(joined, "-pass") || !strings.Contains(joined, "fd:3") {
		t.Fatalf("openssl cmdline must pass the secret via -pass fd:3, got: %q", joined)
	}
	if len(cmd.ExtraFiles) != 1 {
		t.Fatalf("expected one ExtraFiles entry (fd 3) carrying the secret, got %d", len(cmd.ExtraFiles))
	}
}

// TestDecryptTarGzWithCorrectSecret decrypts an openssl-encrypted archive with
// the right password and checks the result is a valid tar.gz.
func TestDecryptTarGzWithCorrectSecret(t *testing.T) {
	plainPath := writeTarGzToFile(t, func(tw *tar.Writer) {
		if err := addTarEntry(tw, "file.txt", "encrypted content"); err != nil {
			t.Fatalf("write entry: %v", err)
		}
	})
	const secret = "correct horse battery staple"
	encryptedPath := encryptTarGzForTest(t, plainPath, secret)

	decryptedPath, err := decryptTarGz(encryptedPath, secret)
	if err != nil {
		t.Fatalf("decryptTarGz: %v", err)
	}
	defer os.Remove(decryptedPath)
	f, err := os.Open(decryptedPath)
	if err != nil {
		t.Fatalf("open decrypted archive: %v", err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("decrypted archive is not a valid gzip stream: %v", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	found := false
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("decrypted archive is not a valid tar.gz: %v", err)
		}
		if hdr.Name == "file.txt" {
			content, err := io.ReadAll(tr)
			if err != nil {
				t.Fatalf("read entry: %v", err)
			}
			if string(content) != "encrypted content" {
				t.Fatalf("decrypted content = %q, want %q", string(content), "encrypted content")
			}
			found = true
		}
	}
	if !found {
		t.Fatal("decrypted archive does not contain file.txt")
	}
}

// TestDecryptTarGzWithWrongSecret checks that a wrong password surfaces the
// openssl diagnostic instead of a generic failure.
func TestDecryptTarGzWithWrongSecret(t *testing.T) {
	plainPath := writeTarGzToFile(t, func(tw *tar.Writer) {
		if err := addTarEntry(tw, "file.txt", "encrypted content"); err != nil {
			t.Fatalf("write entry: %v", err)
		}
	})
	encryptedPath := encryptTarGzForTest(t, plainPath, "right secret")

	_, err := decryptTarGz(encryptedPath, "wrong secret")
	if err == nil {
		t.Fatal("decryptTarGz with wrong secret: expected error, got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, "decrypt archive") {
		t.Fatalf("error should mention the decrypt step, got: %v", err)
	}
	if !strings.Contains(msg, "bad decrypt") && !strings.Contains(msg, "digital envelope") {
		t.Fatalf("error should carry the openssl diagnostic, got: %v", err)
	}
}

// TestDecompressEncryptedWrongSecretSurfacesDecryptError guards P2-5: a
// decryption failure must not be masked by the SDK's unsafe-archive error.
func TestDecompressEncryptedWrongSecretSurfacesDecryptError(t *testing.T) {
	plainPath := writeTarGzToFile(t, func(tw *tar.Writer) {
		if err := addTarEntry(tw, "file.txt", "encrypted content"); err != nil {
			t.Fatalf("write entry: %v", err)
		}
	})
	encryptedPath := encryptTarGzForTest(t, plainPath, "right secret")

	err := NewFileOp().Decompress(encryptedPath, t.TempDir(), TarGz, "wrong secret")
	if err == nil {
		t.Fatal("Decompress with wrong secret: expected error, got nil")
	}
	if errors.Is(err, errUnsafeArchive) {
		t.Fatalf("Decompress with wrong secret must not surface the SDK unsafe-archive error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "decrypt") {
		t.Fatalf("Decompress with wrong secret should mention the decrypt step, got: %v", err)
	}
}

// TestDecompressStripsSpecialModeBits guards P3-1: an archive entry carrying
// setuid/setgid/sticky bits must never materialize a file with those bits set.
// The remaining permission bits are preserved (subject to the process umask,
// like every other extraction), so legitimate executable backups still restore
// executable.
func TestDecompressStripsSpecialModeBits(t *testing.T) {
	op := NewFileOp()
	archivePath := writeTarGzToFile(t, func(tw *tar.Writer) {
		// 04755 = setuid | rwxr-xr-x
		hdr := &tar.Header{Name: "suid.sh", Mode: 04755, Size: 3, Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("write suid entry: %v", err)
		}
		if _, err := io.WriteString(tw, "id\n"); err != nil {
			t.Fatalf("write suid content: %v", err)
		}
		// 02755 = setgid | rwxr-xr-x
		hdr = &tar.Header{Name: "sgid.sh", Mode: 02755, Size: 3, Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("write sgid entry: %v", err)
		}
		if _, err := io.WriteString(tw, "id\n"); err != nil {
			t.Fatalf("write sgid content: %v", err)
		}
		// 01777 = sticky | rwxrwxrwx
		hdr = &tar.Header{Name: "sticky.tmp", Mode: 01777, Size: 1, Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("write sticky entry: %v", err)
		}
		if _, err := io.WriteString(tw, "x"); err != nil {
			t.Fatalf("write sticky content: %v", err)
		}
		// a plain executable file must keep its exec bits
		hdr = &tar.Header{Name: "exec.sh", Mode: 0755, Size: 3, Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("write exec entry: %v", err)
		}
		if _, err := io.WriteString(tw, "id\n"); err != nil {
			t.Fatalf("write exec content: %v", err)
		}
		// a plain 0644 file must keep its permissions
		if err := addTarEntry(tw, "plain.txt", "data"); err != nil {
			t.Fatalf("write plain entry: %v", err)
		}
		// a directory carrying setgid must not keep it
		dirHdr := &tar.Header{Name: "sgid-dir/", Mode: 02775, Typeflag: tar.TypeDir}
		if err := tw.WriteHeader(dirHdr); err != nil {
			t.Fatalf("write sgid dir entry: %v", err)
		}
	})
	dst := t.TempDir()
	if err := op.Decompress(archivePath, dst, TarGz, ""); err != nil {
		t.Fatalf("Decompress archive with special mode bits: %v", err)
	}
	perm := func(name string) os.FileMode {
		t.Helper()
		info, err := os.Stat(filepath.Join(dst, name))
		if err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}
		return info.Mode().Perm()
	}
	for _, name := range []string{"suid.sh", "sgid.sh", "sticky.tmp"} {
		if p := perm(name); p != 0755 && p != 0777 {
			t.Errorf("%s: mode after extraction = %04o, want the setuid/setgid/sticky bits stripped (0755/0777 umask-limited)", name, p)
		}
		if info, err := os.Stat(filepath.Join(dst, name)); err == nil {
			if info.Mode()&os.ModeSetuid != 0 {
				t.Errorf("%s: setuid bit survived extraction", name)
			}
			if info.Mode()&os.ModeSetgid != 0 {
				t.Errorf("%s: setgid bit survived extraction", name)
			}
			if info.Mode()&os.ModeSticky != 0 {
				t.Errorf("%s: sticky bit survived extraction", name)
			}
		}
	}
	if p := perm("exec.sh"); p != 0755 {
		t.Errorf("exec.sh: mode = %04o, want 0755 (executable backup must keep exec bits)", p)
	}
	if p := perm("plain.txt"); p != 0644 {
		t.Errorf("plain.txt: mode = %04o, want 0644", p)
	}
	if p := perm("sgid-dir"); p&os.ModeSetgid != 0 {
		t.Errorf("sgid-dir: setgid bit survived directory extraction, mode = %04o", p)
	}
}

// TestDecompressSkipsNulNamedEntries guards P3-2: a zip entry whose name
// contains a NUL byte cannot be materialized (os.OpenFile fails with EINVAL).
// The entry must be skipped and the rest of the archive must still extract —
// previously the NUL name aborted the whole decompression with a raw EINVAL.
func TestDecompressSkipsNulNamedEntries(t *testing.T) {
	op := NewFileOp()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range []struct {
		name    string
		content string
	}{
		{"evil\x00.txt", "nul"},
		{"ok.txt", "fine"},
	} {
		hdr := &zip.FileHeader{Name: e.name, Method: zip.Deflate}
		hdr.SetMode(0644)
		w, err := zw.CreateHeader(hdr)
		if err != nil {
			t.Fatalf("create header %q: %v", e.name, err)
		}
		if _, err := io.WriteString(w, e.content); err != nil {
			t.Fatalf("write content: %v", err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip writer: %v", err)
	}
	archivePath := filepath.Join(t.TempDir(), "nul.zip")
	if err := os.WriteFile(archivePath, buf.Bytes(), 0644); err != nil {
		t.Fatalf("write archive: %v", err)
	}

	dst := t.TempDir()
	if err := op.Decompress(archivePath, dst, Zip, ""); err != nil {
		t.Fatalf("Decompress zip with NUL-named entry: %v", err)
	}
	// the NUL-named entry must not have landed, under any truncated form
	entries, err := os.ReadDir(dst)
	if err != nil {
		t.Fatalf("read dst: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d files in dst, want 1 (NUL-named entry must be skipped, not written)", len(entries))
	}
	if entries[0].Name() != "ok.txt" {
		t.Fatalf("unexpected entry %q in dst, want ok.txt", entries[0].Name())
	}
	content, err := os.ReadFile(filepath.Join(dst, "ok.txt"))
	if err != nil {
		t.Fatalf("read extracted file: %v", err)
	}
	if string(content) != "fine" {
		t.Fatalf("extracted content = %q, want %q", string(content), "fine")
	}
}

// TestArchiveEntryNameNulRejected directly exercises archiveEntryName: a NUL
// name must surface the errUnsafeArchive sentinel (so the handlers skip the
// entry) while a normal name passes through unchanged.
func TestArchiveEntryNameNulRejected(t *testing.T) {
	_, err := archiveEntryName(archiver.File{NameInArchive: "evil\x00.txt"})
	if err == nil {
		t.Fatal("archiveEntryName with NUL name: expected error, got nil")
	}
	if !errors.Is(err, errUnsafeArchive) {
		t.Fatalf("archiveEntryName with NUL name: expected unsafe archive error, got %v", err)
	}
	name, err := archiveEntryName(archiver.File{NameInArchive: "normal.txt"})
	if err != nil {
		t.Fatalf("archiveEntryName with normal name: %v", err)
	}
	if name != "normal.txt" {
		t.Fatalf("archiveEntryName returned %q, want %q", name, "normal.txt")
	}
}

// TestSanitizedEntryMode guards the P3-1 sanitizer directly: the special bits
// (setuid/setgid/sticky, Go's high-bit mode flags) are stripped while ordinary
// permission bits are untouched.
func TestSanitizedEntryMode(t *testing.T) {
	cases := []struct {
		in   os.FileMode
		want os.FileMode
	}{
		{os.ModeSetuid | 0755, 0755},
		{os.ModeSetgid | 0755, 0755},
		{os.ModeSticky | 0777, 0777},
		{os.ModeSetuid | os.ModeSetgid | os.ModeSticky | 0755, 0755},
		{0644, 0644},
		{0755, 0755},
		{os.ModeDir | 0755, os.ModeDir | 0755},
	}
	for _, tc := range cases {
		if got := sanitizedEntryMode(tc.in); got != tc.want {
			t.Errorf("sanitizedEntryMode(%#o) = %#o, want %#o", tc.in, got, tc.want)
		}
	}
}

// TestDecompressImplicitParentDirMode pins the mode of a directory that is
// implied by a file entry (an archive shipping "data/file" without a "data/"
// entry): it must be created as 0755, not with the file entry's mode (0644),
// because a 0644 directory lacks the owner-execute bit and becomes unusable
// for a non-root process inside the extracted tree (e.g. an app container
// that chowns its data dir to uid 1000 and then tries to create files in it).
func TestDecompressImplicitParentDirMode(t *testing.T) {
	op := NewFileOp()
	archivePath := writeTarGzToFile(t, func(tw *tar.Writer) {
		// only the file entry; no "data/" directory entry
		if err := addTarEntry(tw, "data/database.sqlite", "x"); err != nil {
			t.Fatalf("write entry: %v", err)
		}
	})
	dst := t.TempDir()
	if err := op.decompressWithSDK(archivePath, dst, SdkTarGz); err != nil {
		t.Fatalf("decompress failed: %v", err)
	}
	fi, err := os.Stat(filepath.Join(dst, "data"))
	if err != nil {
		t.Fatalf("implied parent dir was not created: %v", err)
	}
	if !fi.IsDir() {
		t.Fatalf("implied parent %q is not a directory", fi.Mode())
	}
	if got := fi.Mode().Perm(); got != 0755 {
		t.Fatalf("implied parent dir mode = %#o, want 0755", got)
	}
}

// TestDecompressExplicitDirEntryModeKeepsArchiveMode verifies that a real
// directory entry keeps its archive-declared mode (sanitized): only implied
// parents switch to 0755.
func TestDecompressExplicitDirEntryModeKeepsArchiveMode(t *testing.T) {
	op := NewFileOp()
	archivePath := writeTarGzToFile(t, func(tw *tar.Writer) {
		if err := addTarDirEntry(tw, "data", 0700); err != nil {
			t.Fatalf("write dir entry: %v", err)
		}
		if err := addTarEntry(tw, "data/f.txt", "x"); err != nil {
			t.Fatalf("write entry: %v", err)
		}
	})
	dst := t.TempDir()
	if err := op.decompressWithSDK(archivePath, dst, SdkTarGz); err != nil {
		t.Fatalf("decompress failed: %v", err)
	}
	fi, err := os.Stat(filepath.Join(dst, "data"))
	if err != nil {
		t.Fatalf("explicit dir was not created: %v", err)
	}
	if got := fi.Mode().Perm(); got != 0700 {
		t.Fatalf("explicit dir mode = %#o, want 0700", got)
	}
}
