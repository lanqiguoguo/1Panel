package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/app/dto"
	"github.com/1Panel-dev/1Panel/backend/app/model"
	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/glebarez/sqlite"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

func setupRemoveDatabaseBackupDirsTest(t *testing.T) {
	t.Helper()
	origLog := global.LOG
	global.LOG = logrus.New()
	t.Cleanup(func() { global.LOG = origLog })
}

// TestRemoveDatabaseBackupDirsDeletesRealTree is the happy path: a regular
// (possibly deep) directory tree under the panel-owned root is removed.
func TestRemoveDatabaseBackupDirsDeletesRealTree(t *testing.T) {
	setupRemoveDatabaseBackupDirsTest(t)
	root := t.TempDir()
	dir := filepath.Join(root, "database", "mysql", "local-mysql", "panel_db")
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "backup.sql.gz"), []byte("data"), 0640); err != nil {
		t.Fatalf("write: %v", err)
	}
	removeDatabaseBackupDirs(dir, filepath.Join(root, "database"), "backup", "panel_db")
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("directory %s still exists after removal", dir)
	}
	// The parent levels stay untouched.
	if _, err := os.Stat(filepath.Join(root, "database", "mysql", "local-mysql")); err != nil {
		t.Fatalf("parent level removed: %v", err)
	}
}

// TestRemoveDatabaseBackupDirsMissingIsNoop pins the compatibility rule: a
// backup directory that does not exist (yet) is simply skipped.
func TestRemoveDatabaseBackupDirsMissingIsNoop(t *testing.T) {
	setupRemoveDatabaseBackupDirsTest(t)
	root := t.TempDir()
	removeDatabaseBackupDirs(filepath.Join(root, "database", "mysql", "local-mysql", "ghost"), filepath.Join(root, "database"), "backup", "ghost")
	if _, err := os.Stat(root); err != nil {
		t.Fatalf("root changed: %v", err)
	}
}

// TestRemoveDatabaseBackupDirsRejectsSymlink is the M9 regression test: a
// symlink planted at the backup directory position must never be followed -
// RemoveAll would otherwise delete the link's target (e.g. /etc or another
// user's data) instead of the link itself.
func TestRemoveDatabaseBackupDirsRejectsSymlink(t *testing.T) {
	setupRemoveDatabaseBackupDirsTest(t)
	root := t.TempDir()
	victim := t.TempDir()
	victimFile := filepath.Join(victim, "keep.txt")
	if err := os.WriteFile(victimFile, []byte("precious"), 0640); err != nil {
		t.Fatalf("write victim: %v", err)
	}
	link := filepath.Join(root, "database", "mysql", "local-mysql", "panel_db")
	if err := os.MkdirAll(filepath.Dir(link), 0750); err != nil {
		t.Fatalf("mkdir parents: %v", err)
	}
	if err := os.Symlink(victim, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	removeDatabaseBackupDirs(link, filepath.Join(root, "database"), "backup", "panel_db")
	if _, err := os.Stat(victimFile); err != nil {
		t.Fatalf("victim content deleted through the symlink: %v", err)
	}
	if _, err := os.Lstat(link); err != nil {
		t.Fatalf("symlink itself was removed: %v", err)
	}
}

// TestRemoveDatabaseBackupDirsRejectsEscape covers the interior-symlink case:
// a symlink in an intermediate component of the backup path redirects the
// removal into an unrelated tree. The resolved target must stay strictly
// inside the panel-owned root.
func TestRemoveDatabaseBackupDirsRejectsEscape(t *testing.T) {
	setupRemoveDatabaseBackupDirsTest(t)
	base := t.TempDir()
	root := filepath.Join(base, "localbackups", "database")
	outside := t.TempDir()
	outsideDir := filepath.Join(outside, "mysql", "local-mysql", "panel_db")
	if err := os.MkdirAll(outsideDir, 0750); err != nil {
		t.Fatalf("mkdir outside: %v", err)
	}
	if err := os.WriteFile(filepath.Join(outsideDir, "backup.sql.gz"), []byte("data"), 0640); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "mysql"), 0750); err != nil {
		t.Fatalf("mkdir root/mysql: %v", err)
	}
	// "local-mysql" inside the root points at the outside tree.
	if err := os.Symlink(outside, filepath.Join(root, "mysql", "local-mysql")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	dir := filepath.Join(root, "mysql", "local-mysql", "panel_db")
	removeDatabaseBackupDirs(dir, root, "backup", "panel_db")
	if _, err := os.Stat(filepath.Join(outsideDir, "backup.sql.gz")); err != nil {
		t.Fatalf("outside content deleted through interior symlink: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, "mysql", "local-mysql")); err != nil {
		t.Fatalf("interior symlink removed: %v", err)
	}
}

// TestMysqlFormatCollation pins the charset->collation map used when the
// mysql recover flow re-creates the target database empty (M8): it must match
// the mapping the mysql Create flow uses (mysql/client formatMap) so the
// rebuilt database keeps the charset the row promises.
func TestMysqlFormatCollation(t *testing.T) {
	cases := map[string]string{
		"utf8":    "utf8_general_ci",
		"utf8mb4": "utf8mb4_general_ci",
		"gbk":     "gbk_chinese_ci",
		"big5":    "big5_chinese_ci",
		"latin1":  "utf8mb4_general_ci", // unknown formats fall back
	}
	for format, want := range cases {
		if got := mysqlFormatCollation(format); got != want {
			t.Errorf("mysqlFormatCollation(%q) = %q, want %q", format, got, want)
		}
	}
}

// TestDbRollbackFileNameUniqueEnough pins the M7/M8 rollback file naming:
// two snapshots taken within the same second (or on hosts whose clock moved
// backwards) must not collide on the bare <db>_<timestamp> name - a
// subsequent recovery would otherwise truncate the earlier rollback file.
// The random 5-char suffix (same style as regular backups) must be present
// and make consecutive calls differ.
func TestDbRollbackFileNameUniqueEnough(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		name := dbRollbackFileName("panel_db", "sql.gz")
		if !strings.HasPrefix(name, "panel_db_") || !strings.HasSuffix(name, ".sql.gz") {
			t.Fatalf("unexpected rollback file name %q", name)
		}
		if seen[name] {
			t.Fatalf("duplicate rollback file name %q within 200 samples", name)
		}
		seen[name] = true
	}
}

// TestValidateMysqlRecoverTarget pins the M8 entry gate of MysqlRecover: only
// a legal database row recorded by the panel (name charset whitelisted, row
// present and not IsDelete-marked) may be used as the recover target, because
// handleMysqlRecover turns the target name into SQL identifiers and the
// rollback backup file name.
func TestValidateMysqlRecoverTarget(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open in-memory sqlite failed: %v", err)
	}
	if err := db.AutoMigrate(&model.Database{}, &model.DatabaseMysql{}, &model.DatabasePostgresql{}); err != nil {
		t.Fatalf("migrate database models failed: %v", err)
	}
	global.DB = db
	origLog := global.LOG
	global.LOG = logrus.New()
	t.Cleanup(func() { global.LOG = origLog })

	if err := global.DB.Create(&model.DatabaseMysql{
		Name: "panel_db", From: "local", MysqlName: "local-mysql",
		Format: "utf8mb4", Username: "u1", Password: "", Permission: "%",
	}).Error; err != nil {
		t.Fatalf("seed row failed: %v", err)
	}

	legalFile := filepath.Join(t.TempDir(), "panel_db_20260902_abcde.sql.gz")
	if err := os.WriteFile(legalFile, []byte("sql"), 0600); err != nil {
		t.Fatalf("write recover file: %v", err)
	}
	legal := dto.CommonRecover{Type: "mysql", Name: "local-mysql", DetailName: "panel_db", File: legalFile}
	if err := validateMysqlRecoverTarget(&legal); err != nil {
		t.Fatalf("legal target rejected: %v", err)
	}
	for _, tc := range []dto.CommonRecover{
		{Type: "mysql", Name: "local-mysql", DetailName: "x'; id; 'y", File: legalFile}, // injection name
		{Type: "mysql", Name: "local-mysql", DetailName: "my$(id)db", File: legalFile},
		{Type: "mysql", Name: "local-mysql", DetailName: "ghost_db", File: legalFile}, // no row
		{Type: "mysql", Name: "other-mysql", DetailName: "panel_db", File: legalFile}, // wrong owner
		{Type: "mysql", Name: "local-mysql", DetailName: "", File: legalFile},
	} {
		if err := validateMysqlRecoverTarget(&tc); err == nil {
			t.Errorf("validateMysqlRecoverTarget(%+v) = nil error, want rejection", tc)
		}
	}

	// An IsDelete-marked row (deleted on the server, kept for re-sync) must
	// not be recoverable either.
	if err := global.DB.Model(&model.DatabaseMysql{}).Where("name = ?", "panel_db").Update("is_delete", true).Error; err != nil {
		t.Fatalf("mark deleted: %v", err)
	}
	if err := validateMysqlRecoverTarget(&legal); err == nil {
		t.Fatal("validateMysqlRecoverTarget accepted an IsDelete row")
	}
}

// TestMysqlDBTypeAndServerFallback pins M9's row-only path resolution: a
// DatabaseMysql row resolves type from the owning databases record, and a
// broken/absent connection record degrades to a mysql-type fallback instead
// of consulting the (untrusted) request.
func TestMysqlDBTypeAndServerFallback(t *testing.T) {
	setupLoadFromRemoteFilterTest(t)
	// No databases table rows: fallback path.
	typ, server := mysqlDBTypeAndServer(model.DatabaseMysql{Name: "db1", MysqlName: "local-mysql"}, "tampered-name")
	if typ != "mysql" || server != "local-mysql" {
		t.Fatalf("fallback = (%q, %q), want (mysql, local-mysql)", typ, server)
	}
	// With the owning record present, its type wins.
	if err := global.DB.Create(&model.Database{Name: "local-mysql", Type: "mariadb", From: "local"}).Error; err != nil {
		t.Fatalf("seed connection row failed: %v", err)
	}
	typ, server = mysqlDBTypeAndServer(model.DatabaseMysql{Name: "db1", MysqlName: "local-mysql"}, "tampered-name")
	if typ != "mariadb" || server != "local-mysql" {
		t.Fatalf("with record = (%q, %q), want (mariadb, local-mysql)", typ, server)
	}
}
