package repo

import (
	"context"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/app/model"
	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func setupTestAppInstallDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open in-memory sqlite failed: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("get sql db failed: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&model.AppInstall{}); err != nil {
		t.Fatalf("migrate app_installs failed: %v", err)
	}
	old := global.DB
	global.DB = db
	t.Cleanup(func() { global.DB = old })
	return db
}

func createTestAppInstall(t *testing.T, db *gorm.DB, name, status string) model.AppInstall {
	t.Helper()
	install := model.AppInstall{
		Name:          name,
		Version:       "1.0.0",
		Status:        status,
		ContainerName: "old-container",
		ServiceName:   "service-1",
	}
	if err := db.Create(&install).Error; err != nil {
		t.Fatalf("create app install failed: %v", err)
	}
	return install
}

func TestUpdateStatusByID(t *testing.T) {
	db := setupTestAppInstallDB(t)
	install := createTestAppInstall(t, db, "test-upgrade-status", "Upgrading")

	repo := NewIAppInstallRepo()

	t.Run("status matches and is updated", func(t *testing.T) {
		affected, err := repo.UpdateStatusByID(install.ID, "Upgrading", "Running")
		if err != nil {
			t.Fatalf("UpdateStatusByID failed: %v", err)
		}
		if affected != 1 {
			t.Fatalf("expected 1 affected row, got %d", affected)
		}
		var got model.AppInstall
		if err := db.First(&got, install.ID).Error; err != nil {
			t.Fatalf("reload install failed: %v", err)
		}
		if got.Status != "Running" {
			t.Fatalf("expected status Running, got %s", got.Status)
		}
	})

	t.Run("stale writer with mismatched status is rejected", func(t *testing.T) {
		// simulate a goroutine holding the Upgrading state while the row was
		// already changed to Running by another writer
		affected, err := repo.UpdateStatusByID(install.ID, "Upgrading", "UpgradeErr")
		if err != nil {
			t.Fatalf("UpdateStatusByID failed: %v", err)
		}
		if affected != 0 {
			t.Fatalf("expected 0 affected rows for stale write, got %d", affected)
		}
		var got model.AppInstall
		if err := db.First(&got, install.ID).Error; err != nil {
			t.Fatalf("reload install failed: %v", err)
		}
		if got.Status != "Running" {
			t.Fatalf("stale write must not overwrite status, got %s", got.Status)
		}
	})

	t.Run("nonexistent id updates nothing", func(t *testing.T) {
		affected, err := repo.UpdateStatusByID(99999, "Running", "Stopped")
		if err != nil {
			t.Fatalf("UpdateStatusByID failed: %v", err)
		}
		if affected != 0 {
			t.Fatalf("expected 0 affected rows, got %d", affected)
		}
	})
}

func TestUpdateFieldsByID(t *testing.T) {
	db := setupTestAppInstallDB(t)
	install := createTestAppInstall(t, db, "test-update-fields", "Installing")

	repo := NewIAppInstallRepo()
	affected, err := repo.UpdateFieldsByID(install.ID, map[string]interface{}{
		"status":         "Running",
		"container_name": "app-1,app-2",
	})
	if err != nil {
		t.Fatalf("UpdateFieldsByID failed: %v", err)
	}
	if affected != 1 {
		t.Fatalf("expected 1 affected row, got %d", affected)
	}

	var got model.AppInstall
	if err := db.First(&got, install.ID).Error; err != nil {
		t.Fatalf("reload install failed: %v", err)
	}
	if got.Status != "Running" {
		t.Fatalf("expected status Running, got %s", got.Status)
	}
	if got.ContainerName != "app-1,app-2" {
		t.Fatalf("expected container name app-1,app-2, got %s", got.ContainerName)
	}
	// untouched fields must be preserved, unlike a full-row Save
	if got.Version != "1.0.0" {
		t.Fatalf("version must not be overwritten by UpdateFieldsByID, got %s", got.Version)
	}
	if got.Name != "test-update-fields" {
		t.Fatalf("name must not be overwritten by UpdateFieldsByID, got %s", got.Name)
	}
}

// TestUpdateStatusByIDConcurrentWriters simulates the upgrade race: the HTTP
// sync task and the upgrade goroutine write the same row at the same time. The
// conditional update guarantees the last transition is the only one applied.
func TestUpdateStatusByIDConcurrentWriters(t *testing.T) {
	db := setupTestAppInstallDB(t)
	install := createTestAppInstall(t, db, "test-concurrent", "Upgrading")

	repo := NewIAppInstallRepo()
	ctx := context.Background()

	// the sync task marks the app as Error while the upgrade is still running
	if err := db.WithContext(ctx).Model(&model.AppInstall{}).Where("id = ?", install.ID).Update("status", "Error").Error; err != nil {
		t.Fatalf("simulate sync write failed: %v", err)
	}
	// the stale upgrade goroutine tries to write Running/UpgradeErr afterwards
	for _, status := range []string{"Running", "UpgradeErr"} {
		affected, err := repo.UpdateStatusByID(install.ID, "Upgrading", status)
		if err != nil {
			t.Fatalf("UpdateStatusByID failed: %v", err)
		}
		if affected != 0 {
			t.Fatalf("expected 0 affected rows for stale write of %s, got %d", status, affected)
		}
	}
	var got model.AppInstall
	if err := db.First(&got, install.ID).Error; err != nil {
		t.Fatalf("reload install failed: %v", err)
	}
	if got.Status != "Error" {
		t.Fatalf("sync writer status must be preserved, got %s", got.Status)
	}
}
