package service

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/app/dto"
	"github.com/1Panel-dev/1Panel/backend/app/model"
	"github.com/1Panel-dev/1Panel/backend/global"
)

// TestPathInsideDir pins the restore-target whitelist primitive: absolute
// paths inside the allowed dir pass, everything else (relative paths, ".."
// escapes, absolute escapes to system roots) is rejected.
func TestPathInsideDir(t *testing.T) {
	dir := "/opt/1panel"

	valid := []string{
		"/opt/1panel",
		"/opt/1panel/backup",
		"/opt/1panel/backup/system_snapshot",
		"/opt/1panel/tmp",
		"/opt/1panel/./backup", // Clean folds the redundant component
	}
	for _, p := range valid {
		if !pathInsideDir(p, dir, true) {
			t.Errorf("pathInsideDir(%q, %q) = false, want true", p, dir)
		}
	}

	invalid := []string{
		"",
		"backup",              // relative
		"./backup",            // relative
		"../etc",              // relative escape
		"/opt",                // parent
		"/",                   // root
		"/etc",                // system dir
		"/usr/local/bin",      // system dir
		"/opt/1panel-backup",  // sibling prefix, not a real child
		"/opt/1panel/../etc",  // ".." folds out
		"/opt/1panel/../../x", // multi-level escape
	}
	for _, p := range invalid {
		if pathInsideDir(p, dir, true) {
			t.Errorf("pathInsideDir(%q, %q) = true, want false", p, dir)
		}
	}

	// allowEqual=false rejects the dir itself but keeps real children.
	if pathInsideDir(dir, dir, false) {
		t.Error("pathInsideDir(dir, dir, false) = true, want false")
	}
	if !pathInsideDir(filepath.Join(dir, "backup"), dir, false) {
		t.Error("pathInsideDir(dir/backup, dir, false) = false, want true")
	}
}

func TestPathHasTraversalComponent(t *testing.T) {
	for _, p := range []string{"../etc", "/opt/1panel/../x", "a/../../b", "/.."} {
		if !pathHasTraversalComponent(p) {
			t.Errorf("pathHasTraversalComponent(%q) = false, want true", p)
		}
	}
	for _, p := range []string{"/opt/1panel", "/opt/1panel/backup", "backup"} {
		if pathHasTraversalComponent(p) {
			t.Errorf("pathHasTraversalComponent(%q) = true, want false", p)
		}
	}
}

// TestValidateSnapshotJsonPaths pins the restore-target whitelist on the real
// panel configuration: BaseDir/BackupDataDir/PanelDataDir must be absolute,
// free of ".." and lie inside DataDir/Backup/TmpDir. These are the fields the
// recovery flow uses verbatim as untar destinations.
func TestValidateSnapshotJsonPaths(t *testing.T) {
	origDataDir, origBackup, origTmpDir := global.CONF.System.DataDir, global.CONF.System.Backup, global.CONF.System.TmpDir
	t.Cleanup(func() {
		global.CONF.System.DataDir, global.CONF.System.Backup, global.CONF.System.TmpDir = origDataDir, origBackup, origTmpDir
	})
	global.CONF.System.DataDir = "/opt/1panel"
	global.CONF.System.Backup = "/opt/1panel/backup"
	global.CONF.System.TmpDir = "/opt/1panel/tmp"

	valid := SnapshotJson{
		BaseDir:       "/opt/1panel", // recovery untars to BaseDir/1panel
		BackupDataDir: "/opt/1panel/backup",
		PanelDataDir:  "/opt/1panel",
	}
	if err := validateSnapshotJsonPaths(valid); err != nil {
		t.Fatalf("validateSnapshotJsonPaths(valid) failed: %v", err)
	}

	// backupDataDir is the restore target of 1panel_backup.tar.gz — a user
	// configured backup dir is fine as long as it is inside the whitelist.
	alt := valid
	alt.BackupDataDir = "/opt/1panel/tmp"
	if err := validateSnapshotJsonPaths(alt); err != nil {
		t.Fatalf("validateSnapshotJsonPaths(alt backup dir) failed: %v", err)
	}

	badCases := []SnapshotJson{
		{BaseDir: "/etc", BackupDataDir: "/opt/1panel/backup", PanelDataDir: "/opt/1panel"},
		{BaseDir: "/opt/1panel", BackupDataDir: "/", PanelDataDir: "/opt/1panel"},
		{BaseDir: "/opt/1panel", BackupDataDir: "/opt/1panel/backup", PanelDataDir: "/usr/local/bin"},
		{BaseDir: "../../etc", BackupDataDir: "/opt/1panel/backup", PanelDataDir: "/opt/1panel"},
		{BaseDir: "/opt/1panel/../etc", BackupDataDir: "/opt/1panel/backup", PanelDataDir: "/opt/1panel"},
		{BaseDir: "relative", BackupDataDir: "/opt/1panel/backup", PanelDataDir: "/opt/1panel"},
		{BaseDir: "/opt/1panel", BackupDataDir: "", PanelDataDir: "/opt/1panel"},
		{BaseDir: "/opt/1panel", BackupDataDir: "/opt/1panel/backup", PanelDataDir: ""},
	}
	for i, bad := range badCases {
		if err := validateSnapshotJsonPaths(bad); err == nil {
			t.Errorf("bad case %d (%+v) passed, want rejection", i, bad)
		}
	}
}

// writeSnapshotPackage writes a tar.gz snapshot package whose snapshot.json
// carries the given paths, and returns the package path.
func writeSnapshotPackage(t *testing.T, jsonItem SnapshotJson, pkgPath string) {
	t.Helper()
	f, err := os.Create(pkgPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()

	content, err := json.Marshal(jsonItem)
	if err != nil {
		t.Fatal(err)
	}
	hdr := &tar.Header{Name: "snapshot.json", Mode: 0644, Size: int64(len(content))}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatal(err)
	}
}

// TestValidateSnapshotPackage verifies the package-level integrity gate: a
// package is only accepted when it is a real gzip/tar archive carrying a
// parseable snapshot.json whose paths pass the whitelist.
func TestValidateSnapshotPackage(t *testing.T) {
	setupSnapshotTest(t)

	origDataDir, origBackup, origTmpDir := global.CONF.System.DataDir, global.CONF.System.Backup, global.CONF.System.TmpDir
	t.Cleanup(func() {
		global.CONF.System.DataDir, global.CONF.System.Backup, global.CONF.System.TmpDir = origDataDir, origBackup, origTmpDir
	})
	global.CONF.System.DataDir = "/opt/1panel"
	global.CONF.System.Backup = "/opt/1panel/backup"
	global.CONF.System.TmpDir = "/opt/1panel/tmp"

	dir := t.TempDir()
	validPkg := filepath.Join(dir, "valid.tar.gz")
	writeSnapshotPackage(t, SnapshotJson{BaseDir: "/opt/1panel", BackupDataDir: "/opt/1panel/backup", PanelDataDir: "/opt/1panel"}, validPkg)
	if err := validateSnapshotPackage(validPkg); err != nil {
		t.Fatalf("valid package rejected: %v", err)
	}

	badPkg := filepath.Join(dir, "bad.tar.gz")
	writeSnapshotPackage(t, SnapshotJson{BaseDir: "/etc", BackupDataDir: "/opt/1panel/backup", PanelDataDir: "/opt/1panel"}, badPkg)
	if err := validateSnapshotPackage(badPkg); err == nil {
		t.Fatal("package with baseDir=/etc accepted, want rejection")
	}

	escapePkg := filepath.Join(dir, "escape.tar.gz")
	writeSnapshotPackage(t, SnapshotJson{BaseDir: "/opt/1panel", BackupDataDir: "../../etc", PanelDataDir: "/opt/1panel"}, escapePkg)
	if err := validateSnapshotPackage(escapePkg); err == nil {
		t.Fatal("package with backupDataDir=../../etc accepted, want rejection")
	}

	// Not a gzip file at all.
	plain := filepath.Join(dir, "plain.tar.gz")
	if err := os.WriteFile(plain, []byte("not a gzip archive"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := validateSnapshotPackage(plain); err == nil {
		t.Fatal("non-gzip file accepted, want rejection")
	}

	// Valid gzip but not a tar stream (garbage after the gzip header).
	gzOnly := filepath.Join(dir, "gzonly.tar.gz")
	gf, err := os.Create(gzOnly)
	if err != nil {
		t.Fatal(err)
	}
	gw := gzip.NewWriter(gf)
	if _, err := gw.Write([]byte("this is not tar")); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	gf.Close()
	if err := validateSnapshotPackage(gzOnly); err == nil {
		t.Fatal("gzip-without-tar accepted, want rejection")
	}

	// Valid archive without snapshot.json.
	noJSON := filepath.Join(dir, "nojson.tar.gz")
	nf, err := os.Create(noJSON)
	if err != nil {
		t.Fatal(err)
	}
	ngz := gzip.NewWriter(nf)
	ntw := tar.NewWriter(ngz)
	other := []byte("something")
	if err := ntw.WriteHeader(&tar.Header{Name: "other.txt", Mode: 0644, Size: int64(len(other))}); err != nil {
		t.Fatal(err)
	}
	if _, err := ntw.Write(other); err != nil {
		t.Fatal(err)
	}
	ntw.Close()
	ngz.Close()
	nf.Close()
	if err := validateSnapshotPackage(noJSON); err == nil {
		t.Fatal("package without snapshot.json accepted, want rejection")
	}
}

// TestSnapshotImportValidatesPackage verifies SnapshotImport refuses a LOCAL
// snapshot package whose snapshot.json escapes the restore-target whitelist
// (the hostile-package gate) and accepts a well-formed one (reaching the
// existing record-existence stage).
func TestSnapshotImportValidatesPackage(t *testing.T) {
	setupSnapshotTest(t)

	origDataDir, origBackup, origTmpDir := global.CONF.System.DataDir, global.CONF.System.Backup, global.CONF.System.TmpDir
	t.Cleanup(func() {
		global.CONF.System.DataDir, global.CONF.System.Backup, global.CONF.System.TmpDir = origDataDir, origBackup, origTmpDir
	})
	global.CONF.System.DataDir = "/opt/1panel"
	global.CONF.System.Backup = "/opt/1panel/backup"
	global.CONF.System.TmpDir = "/opt/1panel/tmp"

	// Seed a LOCAL backup account so loadLocalDir resolves.
	if err := global.DB.AutoMigrate(&model.BackupAccount{}); err != nil {
		t.Fatalf("migrate backup_accounts failed: %v", err)
	}
	backupDir := filepath.Join(t.TempDir(), "backup")
	if err := backupRepo.Create(&model.BackupAccount{
		Type: "LOCAL",
		Vars: fmt.Sprintf(`{"dir":%q}`, backupDir),
	}); err != nil {
		t.Fatalf("seed LOCAL backup account failed: %v", err)
	}
	t.Cleanup(func() {
		// backupRepo is a package-level var; leave it untouched for other tests.
	})

	name := "1panel_v1.10.34-lts_amd64_20260830120000.tar.gz"
	localDir, err := loadLocalDir()
	if err != nil {
		t.Fatalf("loadLocalDir failed: %v", err)
	}
	snapDir := filepath.Join(localDir, "system_snapshot")
	if err := os.MkdirAll(snapDir, 0755); err != nil {
		t.Fatal(err)
	}

	t.Run("malicious baseDir is rejected", func(t *testing.T) {
		writeSnapshotPackage(t, SnapshotJson{BaseDir: "/etc", BackupDataDir: "/opt/1panel/backup", PanelDataDir: "/opt/1panel"}, filepath.Join(snapDir, name))
		err := (&SnapshotService{}).SnapshotImport(dto.SnapshotImport{From: "LOCAL", Names: []string{name}})
		if err == nil || !strings.Contains(err.Error(), "validate imported snapshot package") {
			t.Fatalf("malicious import err = %v, want package validation failure", err)
		}
	})

	t.Run("well-formed package reaches record stage", func(t *testing.T) {
		writeSnapshotPackage(t, SnapshotJson{BaseDir: "/opt/1panel", BackupDataDir: "/opt/1panel/backup", PanelDataDir: "/opt/1panel"}, filepath.Join(snapDir, name))
		err := (&SnapshotService{}).SnapshotImport(dto.SnapshotImport{From: "LOCAL", Names: []string{name}})
		if err != nil {
			t.Fatalf("valid import failed: %v", err)
		}
		// Importing the same name again must hit the existing-record stage.
		err = (&SnapshotService{}).SnapshotImport(dto.SnapshotImport{From: "LOCAL", Names: []string{name}})
		if err == nil || err.Error() != "ErrRecordExist" {
			t.Fatalf("second import err = %v, want record-exists error", err)
		}
	})
}

// TestSnapshotImportNameWhitelist pins the charset gate of SnapshotImport:
// the raw import name is persisted in the snapshot table and later reused to
// locate and restore packages, so only [A-Za-z0-9._-] may pass (covering the
// "snapshot_" prefix and the ".tar.gz" suffix of the real names generated by
// buildSnapshotName); metacharacters, spaces and traversal must be rejected.
func TestSnapshotImportNameWhitelist(t *testing.T) {
	valid := []string{
		"1panel_v1.10.35-lts_linux_amd64_1panel_data.tar.gz",
		"snapshot_1panel_v1.10.35-lts_linux_amd64.tar.gz",
		"snapshot_1panel_v1.10.35-lts_linux_amd64-a1b2.tar.gz",
	}
	invalid := []string{
		"",
		"1panel_v1;x.tar.gz",
		"1panel_v1 10.tar.gz",
		"snapshot_1panel_v1;rm -rf.tar.gz",
		"1panel_v1$(x).tar.gz",
		"1panel_v1'tar.gz",
		"../../1panel_v1.tar.gz",
		"1panel_v1.tar.gz\n",
	}
	for _, name := range valid {
		if !validSnapshotImportName(name) {
			t.Errorf("validSnapshotImportName(%q) = false, want true", name)
		}
	}
	for _, name := range invalid {
		if validSnapshotImportName(name) {
			t.Errorf("validSnapshotImportName(%q) = true, want false", name)
		}
	}
}
