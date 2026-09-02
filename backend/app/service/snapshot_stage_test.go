package service

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/app/model"
	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/glebarez/sqlite"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

func setupSnapshotStageTest(t *testing.T) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"-stage?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open in-memory sqlite failed: %v", err)
	}
	if err := db.AutoMigrate(&model.Snapshot{}, &model.Setting{}); err != nil {
		t.Fatalf("migrate snapshot/setting tables failed: %v", err)
	}
	global.DB = db
	global.LOG = logrus.New()
}

// makeDataPayload writes a real 1panel_data.tar.gz-style payload into
// payloadFile: a valid sqlite database at db/1Panel.db and a settings file,
// compressed like snapPanelData produces (handleSafeUnTar with TarGz).
func makeDataPayload(t *testing.T, payloadFile string) {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "db"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "settings"), 0755); err != nil {
		t.Fatal(err)
	}
	db, err := gorm.Open(sqlite.Open(filepath.Join(root, "db", "1Panel.db")), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("PRAGMA journal_mode = WAL;").Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("CREATE TABLE settings (key TEXT, value TEXT);").Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("INSERT INTO settings VALUES ('SystemStatus', 'Free');").Error; err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	// checkpoint so the payload's main db file is self-contained (like the
	// snapPanelData flow does via checkPointOfWal before packing)
	if err := db.Exec("PRAGMA wal_checkpoint(TRUNCATE);").Error; err != nil {
		t.Fatal(err)
	}
	_ = sqlDB.Close()
	if err := os.WriteFile(filepath.Join(root, "settings", "app.yaml"), []byte("key: value"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "db", "1Panel.db-wal")); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "db", "1Panel.db-shm")); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	tarPayload(t, root, payloadFile)
}

// tarPayload compresses srcDir into dstFile as a tar.gz, mirroring the
// payload layout the snapshot pipeline creates (contents directly under the
// archive root).
func tarPayload(t *testing.T, srcDir, dstFile string) {
	t.Helper()
	if err := handleSnapTar(srcDir, filepath.Dir(dstFile), filepath.Base(dstFile), "", ""); err != nil {
		t.Fatalf("pack test payload failed: %v", err)
	}
}

// TestStageSnapshotPayloadHappyPath verifies the staging pipeline on a real
// payload: it extracts next to the target, the staged db passes the integrity
// check, and the live target stays untouched until the commit.
func TestStageSnapshotPayloadHappyPath(t *testing.T) {
	ensureValidateLogger(t)
	setupSnapshotStageTest(t)

	root := t.TempDir()
	target := filepath.Join(root, "live")
	if err := os.MkdirAll(filepath.Join(target, "db"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "db", "1Panel.db"), []byte("placeholder"), 0640); err != nil {
		t.Fatal(err)
	}
	payload := filepath.Join(root, "1panel_data.tar.gz")
	makeDataPayload(t, payload)

	staging, err := stageSnapshotPayload(payload, target, "")
	if err != nil {
		t.Fatalf("stageSnapshotPayload failed: %v", err)
	}
	defer os.RemoveAll(staging)
	if _, err := os.Stat(filepath.Join(staging, "db", "1Panel.db")); err != nil {
		t.Fatalf("staged db missing: %v", err)
	}
	// live target untouched
	got, err := os.ReadFile(filepath.Join(target, "db", "1Panel.db"))
	if err != nil || string(got) != "placeholder" {
		t.Fatalf("live db = %q err %v, want untouched placeholder", got, err)
	}
}

// TestApplyStagedPanelDataCommit verifies the full apply of a data payload:
// the live directory ends up with the staged db (real content check) and the
// process DB handle is relinked to the new file.
func TestApplyStagedPanelDataCommit(t *testing.T) {
	ensureValidateLogger(t)
	setupSnapshotStageTest(t)

	root := t.TempDir()
	dataDir := filepath.Join(root, "1panel")
	target := dataDir
	dbDir := filepath.Join(target, "db")
	if err := os.MkdirAll(dbDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dbDir, "1Panel.db"), []byte("placeholder"), 0640); err != nil {
		t.Fatal(err)
	}
	// point the process DB path at the target dir so relinkPanelDB lands there
	oldDbPath, oldDbFile := global.CONF.System.DbPath, global.CONF.System.DbFile
	t.Cleanup(func() {
		global.CONF.System.DbPath = oldDbPath
		global.CONF.System.DbFile = oldDbFile
		setupSnapshotStageTest(t)
	})
	global.CONF.System.DbPath = dbDir
	global.CONF.System.DbFile = "1Panel.db"

	payload := filepath.Join(root, "pkg", "1panel_data.tar.gz")
	if err := os.MkdirAll(filepath.Dir(payload), 0755); err != nil {
		t.Fatal(err)
	}
	payloadSrc := t.TempDir()
	// build a payload with a settings table row so the relinked db is queryable
	if err := os.MkdirAll(filepath.Join(payloadSrc, "db"), 0755); err != nil {
		t.Fatal(err)
	}
	db, err := gorm.Open(sqlite.Open(filepath.Join(payloadSrc, "db", "1Panel.db")), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("CREATE TABLE settings (key TEXT, value TEXT);").Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("INSERT INTO settings VALUES ('SystemStatus', 'Recovering');").Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("PRAGMA wal_checkpoint(TRUNCATE);").Error; err != nil {
		t.Fatal(err)
	}
	sqlDB, _ := db.DB()
	_ = sqlDB.Close()
	_ = os.Remove(filepath.Join(payloadSrc, "db", "1Panel.db-wal"))
	_ = os.Remove(filepath.Join(payloadSrc, "db", "1Panel.db-shm"))
	tarPayload(t, payloadSrc, payload)

	if err := applyStagedPanelData(payload, target); err != nil {
		t.Fatalf("applyStagedPanelData failed: %v", err)
	}
	// the relinked handle reads the restored db content
	var count int64
	if err := global.DB.Table("settings").Count(&count).Error; err != nil {
		t.Fatalf("read restored db via relinked handle failed: %v", err)
	}
	if count != 1 {
		t.Fatalf("restored db has %d settings rows, want 1", count)
	}
}

// TestStageSnapshotPayloadBadDBRejectsDamage makes the staged db fail the
// integrity pre-check (header intact, pages corrupted) and verifies the
// staging dir is cleaned up and the live target never touched.
func TestStageSnapshotPayloadBadDBRejectsDamage(t *testing.T) {
	ensureValidateLogger(t)
	setupSnapshotStageTest(t)

	root := t.TempDir()
	target := filepath.Join(root, "live")
	if err := os.MkdirAll(filepath.Join(target, "db"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "db", "1Panel.db"), []byte("precious"), 0640); err != nil {
		t.Fatal(err)
	}

	payload := filepath.Join(root, "1panel_data.tar.gz")
	payloadSrc := t.TempDir()
	if err := os.MkdirAll(filepath.Join(payloadSrc, "db"), 0755); err != nil {
		t.Fatal(err)
	}
	badDB := filepath.Join(payloadSrc, "db", "1Panel.db")
	// build a valid db with a full page of data, then wipe a whole page body
	// in the middle of the file: the header (first 16 bytes) stays intact, but
	// the page structure the quick_check reads is gone.
	db, err := gorm.Open(sqlite.Open(badDB), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		if err := db.Exec("CREATE TABLE t" + fmt.Sprint(i) + " (v TEXT);").Error; err != nil {
			t.Fatal(err)
		}
		if err := db.Exec("INSERT INTO t" + fmt.Sprint(i) + " VALUES ('padding-padding-padding');").Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Exec("PRAGMA wal_checkpoint(TRUNCATE);").Error; err != nil {
		t.Fatal(err)
	}
	sqlDB, _ := db.DB()
	_ = sqlDB.Close()
	_ = os.Remove(badDB + "-wal")
	_ = os.Remove(badDB + "-shm")
	content, err := os.ReadFile(badDB)
	if err != nil {
		t.Fatal(err)
	}
	pageSize := int(content[16])<<8 | int(content[17])
	if pageSize < 512 {
		t.Fatalf("unexpected sqlite page size %d", pageSize)
	}
	// wipe page 2 and 3 entirely (leaving the header page and its b-tree root
	// pointers intact enough that quick_check must still report corruption)
	for p := 2; p <= 3; p++ {
		start := p * pageSize
		for i := start; i < start+pageSize && i < len(content); i++ {
			content[i] = 0
		}
	}
	if err := os.WriteFile(badDB, content, 0640); err != nil {
		t.Fatal(err)
	}
	tarPayload(t, payloadSrc, payload)

	if _, err := stageSnapshotPayload(payload, target, ""); err == nil {
		t.Fatal("stageSnapshotPayload succeeded on a corrupted db, want rejection")
	}
	// live target untouched and no staging residue
	got, err := os.ReadFile(filepath.Join(target, "db", "1Panel.db"))
	if err != nil || string(got) != "precious" {
		t.Fatalf("live db = %q err %v, want untouched", got, err)
	}
	if _, err := os.Stat(filepath.Join(root, ".snapshot-restore-staging")); !os.IsNotExist(err) {
		t.Fatal("staging dir not cleaned up after failed pre-check")
	}
}

// TestStageSnapshotPayloadMissingDBRejects verifies a data payload without
// db/1Panel.db is rejected before anything touches the live directory.
func TestStageSnapshotPayloadMissingDBRejects(t *testing.T) {
	ensureValidateLogger(t)
	setupSnapshotStageTest(t)

	root := t.TempDir()
	target := filepath.Join(root, "live")
	if err := os.MkdirAll(filepath.Join(target, "db"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "db", "1Panel.db"), []byte("precious"), 0640); err != nil {
		t.Fatal(err)
	}

	payload := filepath.Join(root, "backup.tar.gz")
	payloadSrc := t.TempDir()
	if err := os.WriteFile(filepath.Join(payloadSrc, "settings.txt"), []byte("x"), 0640); err != nil {
		t.Fatal(err)
	}
	tarPayload(t, payloadSrc, payload)

	// shared stage helper: no db member present, so the stage itself passes;
	// the data-only guard lives in applyStagedPanelData
	staging, err := stageSnapshotPayload(payload, target, "")
	if err != nil {
		t.Fatalf("stageSnapshotPayload on payload without db failed: %v", err)
	}
	os.RemoveAll(staging)
	if err := applyStagedPanelData(payload, target); err == nil {
		t.Fatal("applyStagedPanelData accepted a payload without db/1Panel.db")
	} else if !strings.Contains(err.Error(), snapshotPayloadDBRel) {
		t.Fatalf("error %q does not mention %s", err, snapshotPayloadDBRel)
	}
	got, err := os.ReadFile(filepath.Join(target, "db", "1Panel.db"))
	if err != nil || string(got) != "precious" {
		t.Fatalf("live db = %q err %v, want untouched", got, err)
	}
}

// TestCheckStagedPayloadDBRejectsGarbage verifies header-based rejection of a
// staged "database" that is not sqlite at all.
func TestCheckStagedPayloadDBRejectsGarbage(t *testing.T) {
	setupSnapshotStageTest(t)
	root := t.TempDir()
	badDir := filepath.Join(root, "stage")
	if err := os.MkdirAll(filepath.Join(badDir, "db"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(badDir, "db", "1Panel.db"), []byte("not a sqlite file at all"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := checkStagedPayloadDB(badDir); err == nil {
		t.Fatal("checkStagedPayloadDB accepted a garbage db file")
	}
}
