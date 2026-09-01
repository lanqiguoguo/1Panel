package service

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/app/dto"
	"github.com/1Panel-dev/1Panel/backend/app/model"
	"github.com/1Panel-dev/1Panel/backend/constant"
	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/glebarez/sqlite"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

// setupBackupFileNameTest prepares an in-memory sqlite DB with the tables the
// AppBackup / BatchDeleteRecord paths touch, seeds a LOCAL backup account
// rooted at <tmp>/backup and an app ("testapp") with one install
// ("testinstall"), mirroring the harness style of backup_size_test.go /
// app_install_test.go. It returns the local backup root dir.
func setupBackupFileNameTest(t *testing.T) string {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open in-memory sqlite failed: %v", err)
	}
	for _, m := range []interface{}{
		&model.BackupAccount{}, &model.BackupRecord{},
		&model.App{}, &model.AppTag{}, &model.AppInstall{}, &model.AppInstallResource{},
	} {
		if err := db.AutoMigrate(m); err != nil {
			t.Fatalf("migrate %T failed: %v", m, err)
		}
	}
	if global.LOG == nil {
		global.LOG = logrus.New()
	}
	global.DB = db

	tmp := t.TempDir()
	backupDir := filepath.Join(tmp, "backup")
	if err := os.MkdirAll(backupDir, 0755); err != nil {
		t.Fatalf("mkdir backup dir failed: %v", err)
	}
	account := model.BackupAccount{Type: "LOCAL", BackupPath: "", Vars: fmt.Sprintf(`{"dir": %q}`, backupDir)}
	if err := db.Create(&account).Error; err != nil {
		t.Fatalf("seed LOCAL account failed: %v", err)
	}

	app := model.App{Name: "testapp", Key: "testapp", Type: "tool", Resource: constant.AppResourceRemote}
	if err := appRepo.Create(context.Background(), &app); err != nil {
		t.Fatalf("seed app failed: %v", err)
	}
	install := &model.AppInstall{
		Name:          "testinstall",
		AppId:         app.ID,
		AppDetailId:   1,
		Version:       "1.0.0",
		Status:        constant.StatusRunning,
		ContainerName: "testinstall",
		ServiceName:   "testinstall",
	}
	install.App = app
	if err := appInstallRepo.Create(context.Background(), install); err != nil {
		t.Fatalf("seed app install failed: %v", err)
	}
	return backupDir
}

// TestValidateBackupFileName unit-tests the AppBackup entry gate: any name
// that is not a plain ".tar.gz" basename (separators, ".." substrings, wrong
// suffix) must be rejected with an error, while the shapes produced by the
// server-side generators and the legitimate API stay accepted.
func TestValidateBackupFileName(t *testing.T) {
	for _, name := range []string{
		"../../evil.tar.gz",
		"../evil.tar.gz",
		"../../../../etc/cron.d/pwn.tar.gz",
		"/etc/cron.d/pwn.tar.gz",
		"a/b.tar.gz",
		`a\b.tar.gz`,
		"..",
		".",
		"",
		"a..b.tar.gz",
		"....tar.gz",
		".tar.gz",
		"foo.tar",
		"foo.zip",
		"tar.gz/../../x.tar.gz",
	} {
		if err := validateBackupFileName(name); err == nil {
			t.Errorf("validateBackupFileName(%q) = nil error, want rejection", name)
		}
	}
	for _, name := range []string{
		"myapp_20260901.tar.gz",
		"upgrade_backup_wordpress_20260901123040abcde.tar.gz",
		"directory_opt_data_20260901123040abcde.tar.gz",
	} {
		if err := validateBackupFileName(name); err != nil {
			t.Errorf("validateBackupFileName(%q) unexpected error: %v", name, err)
		}
	}
}

// TestAppBackupRejectsMaliciousFileName is the regression test for the
// AppBackup path-traversal bug: a caller-supplied FileName containing ".." or
// separators used to flow into handleAppBackup (arbitrary os.MkdirAll via
// tmpDir, unquoted tar archive target) and into the stored BackupRecord (later
// joined into the LOCAL client's os.RemoveAll). The service must fail the
// request before ANY filesystem operation, leaving the backup root (and its
// parent) untouched and no record row behind.
func TestAppBackupRejectsMaliciousFileName(t *testing.T) {
	backupDir := setupBackupFileNameTest(t)
	tmp := filepath.Dir(backupDir)

	payloads := []string{
		"../../../1panel-pwned/evil.tar.gz",
		"../../etc/cron.d/pwn.tar.gz",
		"../outside.tar.gz",
		"a/b.tar.gz",
		`a\b.tar.gz`,
		"..",
		"a..b.tar.gz",
	}
	for _, payload := range payloads {
		record, err := NewIBackupService().AppBackup(dtoCommonBackup("testapp", "testinstall", payload))
		if err == nil {
			t.Fatalf("AppBackup(fileName=%q) = nil error, want rejection", payload)
		}
		if record != nil {
			t.Fatalf("AppBackup(fileName=%q) returned a record, want nil", payload)
		}
		// No record row may be persisted for a rejected name.
		var count int64
		if err := global.DB.Model(&model.BackupRecord{}).Count(&count).Error; err != nil {
			t.Fatalf("count backup records: %v", err)
		}
		if count != 0 {
			t.Fatalf("AppBackup(fileName=%q) persisted %d record rows, want 0", payload, count)
		}
		// Nothing may be created anywhere: the backup root stays empty and
		// no sibling of it (the escape target) may appear.
		entries, err := os.ReadDir(backupDir)
		if err != nil {
			t.Fatalf("read backup dir: %v", err)
		}
		if len(entries) != 0 {
			t.Fatalf("backup dir polluted after rejecting %q: %v", payload, dirNames(entries))
		}
		siblings, err := os.ReadDir(tmp)
		if err != nil {
			t.Fatalf("read tmp dir: %v", err)
		}
		if len(siblings) != 1 || siblings[0].Name() != "backup" {
			t.Fatalf("escape target created after rejecting %q: %v", payload, dirNames(siblings))
		}
	}
}

// TestAppBackupAcceptsLegalAndGeneratedFileName drives the happy paths end to
// end: an explicit legal file name and an empty one (server-side generation)
// must produce the tarball inside the app backup dir, persist a record whose
// FileDir/FileName re-validate against the delete-side gate, and clean up the
// staging directory.
func TestAppBackupAcceptsLegalAndGeneratedFileName(t *testing.T) {
	backupDir := setupBackupFileNameTest(t)
	// In tests the install path constants resolve relative to the process CWD
	// (global.CONF is zero, so DataDir is ""), so move the CWD into a throwaway
	// dir and create the app source tree there for tar to archive.
	workDir := t.TempDir()
	t.Chdir(workDir)
	appSource := filepath.Join(workDir, "apps", "testapp")
	if err := os.MkdirAll(appSource, 0755); err != nil {
		t.Fatalf("mkdir app source failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(appSource, "index.html"), []byte("ok"), 0644); err != nil {
		t.Fatalf("write app source file failed: %v", err)
	}

	svc := NewIBackupService()

	// Explicit legal file name.
	record, err := svc.AppBackup(dtoCommonBackup("testapp", "testinstall", "myapp_20260901.tar.gz"))
	if err != nil {
		t.Fatalf("AppBackup with legal fileName failed: %v", err)
	}
	if record.FileDir != "app/testapp/testinstall" {
		t.Fatalf("record FileDir = %q, want app/testapp/testinstall", record.FileDir)
	}
	if record.FileName != "myapp_20260901.tar.gz" {
		t.Fatalf("record FileName = %q, want unchanged input", record.FileName)
	}
	assertBackupArtifact(t, backupDir, record.FileDir, record.FileName, true)
	if err := validateBackupRecordPath(*record); err != nil {
		t.Fatalf("stored record must pass the delete-side re-validation: %v", err)
	}

	// Empty file name: server-side generation.
	genRecord, err := svc.AppBackup(dtoCommonBackup("testapp", "testinstall", ""))
	if err != nil {
		t.Fatalf("AppBackup with empty fileName failed: %v", err)
	}
	if !strings.HasPrefix(genRecord.FileName, "testinstall_") || !strings.HasSuffix(genRecord.FileName, ".tar.gz") {
		t.Fatalf("generated FileName = %q, want testinstall_<ts><rand>.tar.gz", genRecord.FileName)
	}
	assertBackupArtifact(t, backupDir, genRecord.FileDir, genRecord.FileName, true)
	if genRecord.FileName == record.FileName {
		t.Fatalf("generated FileName must be unique, got %q twice", record.FileName)
	}

	var count int64
	if err := global.DB.Model(&model.BackupRecord{}).Count(&count).Error; err != nil {
		t.Fatalf("count backup records: %v", err)
	}
	if count != 2 {
		t.Fatalf("backup record rows = %d, want 2", count)
	}
}

// TestBackupRecordBatchDeleteRejectsTraversal seeds a legacy malicious record
// (FileName with ".." stored before the write-side gate existed) and asserts
// BatchDeleteRecord fails the WHOLE batch without deleting anything: the
// legitimate file stays on disk, the escape target outside the backup root is
// untouched, and both DB rows survive. A follow-up batch with only the legal
// record must succeed and remove exactly that file.
func TestBackupRecordBatchDeleteRejectsTraversal(t *testing.T) {
	backupDir := setupBackupFileNameTest(t)
	tmp := filepath.Dir(backupDir)

	itemDir := filepath.Join(backupDir, "app", "testapp", "testinstall")
	if err := os.MkdirAll(itemDir, 0755); err != nil {
		t.Fatalf("mkdir item dir failed: %v", err)
	}
	legalFile := filepath.Join(itemDir, "good.tar.gz")
	if err := os.WriteFile(legalFile, []byte("payload"), 0644); err != nil {
		t.Fatalf("write legal backup file failed: %v", err)
	}
	// What the malicious row would resolve to via
	// os.RemoveAll(path.Join(dir, "app/testapp/testinstall", "../../../cron-pwned")):
	// a directory one level ABOVE the backup root.
	escapeTarget := filepath.Join(tmp, "cron-pwned")
	if err := os.MkdirAll(escapeTarget, 0755); err != nil {
		t.Fatalf("mkdir escape target failed: %v", err)
	}
	escapeMarker := filepath.Join(escapeTarget, "marker.txt")
	if err := os.WriteFile(escapeMarker, []byte("do-not-delete"), 0644); err != nil {
		t.Fatalf("write escape marker failed: %v", err)
	}

	db := global.DB
	legal := model.BackupRecord{Type: "app", Name: "testapp", DetailName: "testinstall", Source: "LOCAL", BackupType: "LOCAL", FileDir: "app/testapp/testinstall", FileName: "good.tar.gz"}
	malicious := model.BackupRecord{Type: "app", Name: "testapp", DetailName: "testinstall", Source: "LOCAL", BackupType: "LOCAL", FileDir: "app/testapp/testinstall", FileName: "../../../cron-pwned.tar.gz"}
	for _, r := range []*model.BackupRecord{&legal, &malicious} {
		if err := db.Create(r).Error; err != nil {
			t.Fatalf("seed record %s failed: %v", r.FileName, err)
		}
	}

	err := NewIBackupService().BatchDeleteRecord([]uint{legal.ID, malicious.ID})
	if err == nil {
		t.Fatal("BatchDeleteRecord with traversal record = nil error, want rejection")
	}
	if _, statErr := os.Stat(legalFile); statErr != nil {
		t.Fatalf("legal backup file must survive the rejected batch: %v", statErr)
	}
	if _, statErr := os.Stat(escapeMarker); statErr != nil {
		t.Fatalf("escape target was deleted outside the backup root: %v", statErr)
	}
	var count int64
	if err := db.Model(&model.BackupRecord{}).Count(&count).Error; err != nil {
		t.Fatalf("count records: %v", err)
	}
	if count != 2 {
		t.Fatalf("record rows after rejected batch = %d, want 2 (no partial delete)", count)
	}

	// Control: the legal record alone deletes cleanly, and the escape target
	// is still untouched afterwards.
	if err := NewIBackupService().BatchDeleteRecord([]uint{legal.ID}); err != nil {
		t.Fatalf("BatchDeleteRecord of legal record failed: %v", err)
	}
	if _, statErr := os.Stat(legalFile); !os.IsNotExist(statErr) {
		t.Fatalf("legal backup file should have been deleted, stat err: %v", statErr)
	}
	if _, statErr := os.Stat(escapeMarker); statErr != nil {
		t.Fatalf("escape target must remain untouched by the legal delete: %v", statErr)
	}
	var remaining int64
	if err := db.Model(&model.BackupRecord{}).Count(&remaining).Error; err != nil {
		t.Fatalf("count records: %v", err)
	}
	if remaining != 1 {
		t.Fatalf("record rows after legal delete = %d, want 1", remaining)
	}
}

func dtoCommonBackup(name, detailName, fileName string) dto.CommonBackup {
	return dto.CommonBackup{Type: "app", Name: name, DetailName: detailName, FileName: fileName}
}

func assertBackupArtifact(t *testing.T, backupDir, fileDir, fileName string, want bool) {
	t.Helper()
	full := filepath.Join(backupDir, filepath.FromSlash(fileDir), fileName)
	_, err := os.Stat(full)
	if want && err != nil {
		t.Fatalf("backup archive %s missing: %v", full, err)
	}
	if !want && err == nil {
		t.Fatalf("backup archive %s should not exist", full)
	}
	if want {
		// The staging directory (fileName without .tar.gz) must be cleaned up.
		staging := filepath.Join(backupDir, filepath.FromSlash(fileDir), strings.TrimSuffix(fileName, ".tar.gz"))
		if _, err := os.Stat(staging); !os.IsNotExist(err) {
			t.Fatalf("staging dir %s was not cleaned up, stat err: %v", staging, err)
		}
	}
}

func dirNames(entries []os.DirEntry) []string {
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}
