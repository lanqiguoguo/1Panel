package service

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/app/model"
	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/glebarez/sqlite"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

// setupLoadSizeTest seeds an in-memory sqlite DB with backup accounts so
// backupRepo.Get resolves inside loadSnapSize / loadRecordSize, mirroring
// setting_test.go. It returns the local dir served by the LOCAL account.
// The UNSUPPORTED account fails in NewCloudStorageClient, BADVARS fails the
// vars unmarshal and NO_ACCOUNT is missing from the DB entirely, covering the
// three per-account error paths.
func setupLoadSizeTest(t *testing.T) string {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open in-memory sqlite failed: %v", err)
	}
	if err := db.AutoMigrate(&model.BackupAccount{}); err != nil {
		t.Fatalf("migrate backup accounts failed: %v", err)
	}
	if global.LOG == nil {
		global.LOG = logrus.New()
	}
	global.DB = db

	backupDir := t.TempDir()
	accounts := []model.BackupAccount{
		{Type: "LOCAL", BackupPath: "", Vars: fmt.Sprintf(`{"dir": %q}`, backupDir)},
		{Type: "UNSUPPORTED", Vars: `{"dir": "/tmp"}`},
		{Type: "BADVARS", Vars: `not-json`},
	}
	for i := range accounts {
		if err := db.Create(&accounts[i]).Error; err != nil {
			t.Fatalf("seed backup account %s failed: %v", accounts[i].Type, err)
		}
	}
	return backupDir
}

func writeSizedFile(t *testing.T, dir, rel string, size int64) {
	t.Helper()
	full := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
		t.Fatalf("mkdir for %s failed: %v", rel, err)
	}
	if err := os.WriteFile(full, make([]byte, size), 0644); err != nil {
		t.Fatalf("write %s failed: %v", rel, err)
	}
}

// TestLoadRecordSize fans out several LOCAL records (the first resolves
// synchronously, the rest in goroutines) mixed with records from broken
// accounts, asserting every size and the identity of each entry.
func TestLoadRecordSize(t *testing.T) {
	backupDir := setupLoadSizeTest(t)

	sizes := make(map[string]int64)
	records := make([]model.BackupRecord, 0, 13)
	for i := 0; i < 4; i++ {
		fileName := fmt.Sprintf("app-%d.tar.gz", i)
		writeSizedFile(t, backupDir, path.Join("app", fileName), int64(100+i))
		sizes[path.Join("app", fileName)] = int64(100 + i)
		records = append(records, model.BackupRecord{Source: "LOCAL", FileDir: "app", FileName: fileName})
	}
	records = append(records,
		model.BackupRecord{Source: "UNSUPPORTED", FileDir: "x", FileName: "missing-1.tar.gz"},
		model.BackupRecord{Source: "UNSUPPORTED", FileDir: "x", FileName: "missing-2.tar.gz"},
		model.BackupRecord{Source: "BADVARS", FileDir: "x", FileName: "missing-3.tar.gz"},
		model.BackupRecord{Source: "NO_ACCOUNT", FileDir: "x", FileName: "missing-4.tar.gz"},
		model.BackupRecord{Source: "NO_ACCOUNT", FileDir: "x", FileName: "missing-5.tar.gz"},
	)

	data, err := (&BackupService{}).loadRecordSize(records)
	if err != nil {
		t.Fatalf("loadRecordSize failed: %v", err)
	}
	if len(data) != len(records) {
		t.Fatalf("loadRecordSize returned %d items, want %d", len(data), len(records))
	}
	for i, item := range data {
		if item.Name != records[i].FileName || item.ID != records[i].ID {
			t.Errorf("data[%d] = {ID:%d Name:%q}, want {ID:%d Name:%q}",
				i, item.ID, item.Name, records[i].ID, records[i].FileName)
		}
		want := int64(0)
		if records[i].Source == "LOCAL" {
			want = sizes[path.Join(records[i].FileDir, records[i].FileName)]
		}
		if item.Size != want {
			t.Errorf("data[%d] (%s/%s) Size = %d, want %d",
				i, records[i].Source, records[i].FileName, item.Size, want)
		}
	}
}

// TestLoadSnapSize does the same for snapshots: several LOCAL snapshot files
// (fan-out path) plus snapshots bound to the broken accounts.
func TestLoadSnapSize(t *testing.T) {
	backupDir := setupLoadSizeTest(t)

	sizes := make(map[string]int64)
	snapshots := make([]model.Snapshot, 0, 13)
	for i := 0; i < 4; i++ {
		name := fmt.Sprintf("snapshot-1.10.%d", i)
		rel := path.Join("system_snapshot", name+".tar.gz")
		writeSizedFile(t, backupDir, rel, int64(200+i))
		sizes[rel] = int64(200 + i)
		snapshots = append(snapshots, model.Snapshot{Name: name, DefaultDownload: "LOCAL"})
	}
	snapshots = append(snapshots,
		model.Snapshot{Name: "snap-unsup-1", DefaultDownload: "UNSUPPORTED"},
		model.Snapshot{Name: "snap-unsup-2", DefaultDownload: "UNSUPPORTED"},
		model.Snapshot{Name: "snap-badvars", DefaultDownload: "BADVARS"},
		model.Snapshot{Name: "snap-noacct-1", DefaultDownload: "NO_ACCOUNT"},
		model.Snapshot{Name: "snap-noacct-2", DefaultDownload: "NO_ACCOUNT"},
	)

	data, err := loadSnapSize(snapshots)
	if err != nil {
		t.Fatalf("loadSnapSize failed: %v", err)
	}
	if len(data) != len(snapshots) {
		t.Fatalf("loadSnapSize returned %d items, want %d", len(data), len(snapshots))
	}
	for i, item := range data {
		if item.Name != snapshots[i].Name || item.ID != snapshots[i].ID {
			t.Errorf("data[%d] = {ID:%d Name:%q}, want {ID:%d Name:%q}",
				i, item.ID, item.Name, snapshots[i].ID, snapshots[i].Name)
		}
		var want int64
		if snapshots[i].DefaultDownload == "LOCAL" {
			want = sizes[path.Join("system_snapshot", snapshots[i].Name+".tar.gz")]
		}
		if item.Size != want {
			t.Errorf("data[%d] (%s/%s) Size = %d, want %d",
				i, snapshots[i].DefaultDownload, snapshots[i].Name, item.Size, want)
		}
	}
}
