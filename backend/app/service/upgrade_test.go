package service

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/app/dto"
	"github.com/1Panel-dev/1Panel/backend/buserr"
	"github.com/1Panel-dev/1Panel/backend/constant"
)

// TestUpgradeVersionWhitelist pins the version charset gate of Upgrade:
// req.Version is interpolated into the package file name, the download URL
// and the tmp paths, so only [0-9A-Za-z.-] may pass, and the gate fires as
// the first statement of Upgrade (before any filesystem or network side
// effect, so the rejected calls below are safe to run against a nil env).
func TestUpgradeVersionWhitelist(t *testing.T) {
	for _, version := range []string{"v1.10.40-lts", "1.10.40", "v2.0.0-beta.1"} {
		if !validUpgradeVersionRegexp.MatchString(version) {
			t.Errorf("validUpgradeVersionRegexp(%q) = false, want true", version)
		}
	}
	for _, version := range []string{"", "../x", "v1;x", "v1 v2", "v1&x", "v1/10"} {
		if validUpgradeVersionRegexp.MatchString(version) {
			t.Errorf("validUpgradeVersionRegexp(%q) = true, want false", version)
		}
	}

	u := &UpgradeService{}
	for _, version := range []string{"../x", "v1;x"} {
		err := u.Upgrade(dto.Upgrade{Version: version})
		if err == nil || !strings.Contains(err.Error(), "invalid upgrade version") {
			t.Errorf("Upgrade(version=%q) error = %v, want invalid upgrade version rejection", version, err)
		}
	}
}

func TestMigrate1pctlParams(t *testing.T) {
	dir := t.TempDir()
	backup := filepath.Join(dir, "1pctl.backup")
	target := filepath.Join(dir, "1pctl.new")
	oldScript := "#!/bin/bash\n" +
		"BASE_DIR=/opt\n" +
		"ORIGINAL_PORT=28080\n" +
		"ORIGINAL_VERSION=v1.10.34-lts-internal\n" +
		"ORIGINAL_ENTRANCE=old_entrance\n" +
		"ORIGINAL_USERNAME=old_admin\n" +
		"ORIGINAL_PASSWORD=p@ss/w0rd#special\n" +
		"LANGUAGE=zh\n" +
		"CHANGE_USER_INFO=abc123\n"
	newScript := "#!/bin/bash\n" +
		"BASE_DIR=directory\n" +
		"ORIGINAL_PORT=port\n" +
		"ORIGINAL_VERSION=v1.10.35-lts\n" +
		"ORIGINAL_ENTRANCE=entrance\n" +
		"ORIGINAL_USERNAME=username\n" +
		"ORIGINAL_PASSWORD=password\n" +
		"LANGUAGE=en\n"
	if err := os.WriteFile(backup, []byte(oldScript), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte(newScript), 0755); err != nil {
		t.Fatal(err)
	}

	u := &UpgradeService{}
	if err := u.migrate1pctlParams(backup, target, "v1.10.35-lts"); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	want := "#!/bin/bash\n" +
		"BASE_DIR=/opt\n" +
		"ORIGINAL_PORT=28080\n" +
		"ORIGINAL_VERSION=v1.10.35-lts\n" +
		"ORIGINAL_ENTRANCE=old_entrance\n" +
		"ORIGINAL_USERNAME=old_admin\n" +
		"LANGUAGE=zh\n" +
		"CHANGE_USER_INFO=abc123\n"
	if string(got) != want {
		t.Fatalf("migrated 1pctl mismatch:\ngot:\n%s\nwant:\n%s", got, want)
	}
}

func TestCheckVersionSemantics(t *testing.T) {
	u := &UpgradeService{}
	cases := []struct {
		name    string
		remote  string
		current string
		expect  string
	}{
		{"newer lts over internal", "v1.10.35-lts", "v1.10.34-lts-internal", "v1.10.35-lts"},
		{"same version no prompt", "v1.10.35-lts", "v1.10.35-lts", ""},
		{"older remote no prompt", "v1.10.34-lts", "v1.10.35-lts", ""},
		{"trailing newline tolerated", "v1.10.36-lts\n", "v1.10.35-lts", "v1.10.36-lts"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := u.checkVersion(c.remote, c.current); got != c.expect {
				t.Fatalf("checkVersion(%q, %q) = %q, want %q", c.remote, c.current, got, c.expect)
			}
		})
	}
}

const testPackageContent = "1panel-fake-upgrade-package-bytes"

// stubPackageChecksum points fetchPackageChecksum at a canned response and
// restores the original when the test finishes.
func stubPackageChecksum(t *testing.T, data []byte, err error) {
	t.Helper()
	orig := fetchPackageChecksum
	fetchPackageChecksum = func(string) ([]byte, error) {
		return data, err
	}
	t.Cleanup(func() { fetchPackageChecksum = orig })
}

func writePackageFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	file := filepath.Join(dir, name)
	if err := os.WriteFile(file, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return file
}

func TestParseChecksum(t *testing.T) {
	digest := "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	cases := []struct {
		name    string
		content string
		expect  string
		wantErr bool
	}{
		{"sha256sum output", digest + "  1panel-v1.10.35-lts-linux-amd64.tar.gz\n", digest, false},
		{"no trailing newline", digest + "  1panel-v1.10.35-lts-linux-amd64.tar.gz", digest, false},
		{"tabs and multiple spaces", digest + "\t\t1panel-v1.10.35-lts-linux-amd64.tar.gz", digest, false},
		{"blank lines and extra whitespace", "\n\n  " + digest + "   1panel-v1.10.35-lts-linux-amd64.tar.gz  \n\n", digest, false},
		{"uppercase digest normalized", strings.ToUpper(digest) + "  pkg.tar.gz\n", digest, false},
		{"trailing entries ignored", digest + "  a.tar.gz\n" + strings.Repeat("a", 64) + "  b.tar.gz\n", digest, false},
		{"digest too short", "9f86d081  pkg.tar.gz\n", "", true},
		{"digest not hex", strings.Repeat("g", 64) + "  pkg.tar.gz\n", "", true},
		{"empty file", "\n  \n", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := parseChecksum(c.content)
			if c.wantErr {
				if err == nil {
					t.Fatalf("parseChecksum(%q) expected error, got %q", c.content, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseChecksum(%q) failed: %v", c.content, err)
			}
			if got != c.expect {
				t.Fatalf("parseChecksum(%q) = %q, want %q", c.content, got, c.expect)
			}
		})
	}
}

func TestVerifyPackageDownloadOK(t *testing.T) {
	dir := t.TempDir()
	pkg := writePackageFile(t, dir, "1panel-v1.10.35-lts-linux-amd64.tar.gz", testPackageContent)
	sum := sha256.Sum256([]byte(testPackageContent))
	checksum := hex.EncodeToString(sum[:]) + "  1panel-v1.10.35-lts-linux-amd64.tar.gz\n"
	stubPackageChecksum(t, []byte(checksum), nil)

	if err := verifyPackageDownload(pkg, "http://localhost/sha256.txt"); err != nil {
		t.Fatalf("expected verification to pass, got %v", err)
	}
}

func TestVerifyPackageDownloadMismatch(t *testing.T) {
	dir := t.TempDir()
	pkg := writePackageFile(t, dir, "1panel-v1.10.35-lts-linux-amd64.tar.gz", testPackageContent)
	badChecksum := strings.Repeat("a", 64) + "  1panel-v1.10.35-lts-linux-amd64.tar.gz\n"
	stubPackageChecksum(t, []byte(badChecksum), nil)

	err := verifyPackageDownload(pkg, "http://localhost/sha256.txt")
	if err == nil {
		t.Fatal("expected mismatched checksum to abort verification")
	}
	var bizErr buserr.BusinessError
	if !errors.As(err, &bizErr) || bizErr.Msg != constant.ErrUpgradeVerifyFailed {
		t.Fatalf("expected business error %s, got %v", constant.ErrUpgradeVerifyFailed, err)
	}
	// the package file must be untouched: verification runs before any
	// untar/execution step in Upgrade
	got, errRead := os.ReadFile(pkg)
	if errRead != nil {
		t.Fatal(errRead)
	}
	if string(got) != testPackageContent {
		t.Fatalf("package file was modified during verification: %q", got)
	}
}

func TestVerifyPackageDownloadMissingChecksum(t *testing.T) {
	dir := t.TempDir()
	pkg := writePackageFile(t, dir, "1panel-v1.10.35-lts-linux-amd64.tar.gz", testPackageContent)

	stubPackageChecksum(t, nil, fmt.Errorf("404 Not Found"))
	if err := verifyPackageDownload(pkg, "http://localhost/sha256.txt"); err == nil {
		t.Fatal("expected unfetchable checksum to abort verification")
	}

	// an empty/garbage sidecar must fail closed as well
	stubPackageChecksum(t, []byte("not-a-digest\n"), nil)
	if err := verifyPackageDownload(pkg, "http://localhost/sha256.txt"); err == nil {
		t.Fatal("expected malformed checksum to abort verification")
	}
}

func TestFileSHA256(t *testing.T) {
	dir := t.TempDir()
	pkg := writePackageFile(t, dir, "pkg.tar.gz", testPackageContent)
	sum := sha256.Sum256([]byte(testPackageContent))
	want := hex.EncodeToString(sum[:])
	got, err := fileSHA256(pkg)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("fileSHA256 = %q, want %q", got, want)
	}
	if _, err := fileSHA256(filepath.Join(dir, "missing.tar.gz")); err == nil {
		t.Fatal("expected error for missing file")
	}
}
