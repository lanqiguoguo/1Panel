package migrations

import (
	"strings"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/app/model"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

// TestAddProxyDockerSyncIdempotent verifies the migration never duplicates the
// ProxyDockerSync row even when replayed: the settings table has no unique
// constraint on key, so gormigrate's recorded-ID guard is the only protection
// on the normal path, and it does not survive a lost migration record or a
// manual replay. Running the migration twice must leave exactly one row.
func TestAddProxyDockerSyncIdempotent(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open in-memory sqlite failed: %v", err)
	}
	if err := db.AutoMigrate(&model.Setting{}); err != nil {
		t.Fatalf("migrate settings failed: %v", err)
	}

	if err := AddProxyDockerSync.Migrate(db); err != nil {
		t.Fatalf("first AddProxyDockerSync.Migrate failed: %v", err)
	}
	// Replaying the migration (lost migrations record, manual rerun, ID
	// conflict) must not insert a second row.
	if err := AddProxyDockerSync.Migrate(db); err != nil {
		t.Fatalf("second AddProxyDockerSync.Migrate failed: %v", err)
	}

	var count int64
	if err := db.Model(&model.Setting{}).Where("key = ?", "ProxyDockerSync").Count(&count).Error; err != nil {
		t.Fatalf("count ProxyDockerSync failed: %v", err)
	}
	if count != 1 {
		t.Fatalf("ProxyDockerSync rows = %d, want exactly 1", count)
	}

	var s model.Setting
	if err := db.Where("key = ?", "ProxyDockerSync").First(&s).Error; err != nil {
		t.Fatalf("read ProxyDockerSync failed: %v", err)
	}
	if s.Value != "false" {
		t.Errorf("ProxyDockerSync value = %q, want false", s.Value)
	}
}

// TestAddProxyDockerSyncKeepsExistingRow covers the upgrade-over path: a row
// already present (e.g. the panel was downgraded, the setting edited, or the
// migration replayed after a manual insert) must be kept untouched.
func TestAddProxyDockerSyncKeepsExistingRow(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open in-memory sqlite failed: %v", err)
	}
	if err := db.AutoMigrate(&model.Setting{}); err != nil {
		t.Fatalf("migrate settings failed: %v", err)
	}
	if err := db.Create(&model.Setting{Key: "ProxyDockerSync", Value: "true"}).Error; err != nil {
		t.Fatalf("seed ProxyDockerSync failed: %v", err)
	}

	if err := AddProxyDockerSync.Migrate(db); err != nil {
		t.Fatalf("AddProxyDockerSync.Migrate failed: %v", err)
	}

	var count int64
	if err := db.Model(&model.Setting{}).Where("key = ?", "ProxyDockerSync").Count(&count).Error; err != nil {
		t.Fatalf("count ProxyDockerSync failed: %v", err)
	}
	if count != 1 {
		t.Fatalf("ProxyDockerSync rows = %d, want exactly 1", count)
	}

	var s model.Setting
	if err := db.Where("key = ?", "ProxyDockerSync").First(&s).Error; err != nil {
		t.Fatalf("read ProxyDockerSync failed: %v", err)
	}
	if s.Value != "true" {
		t.Errorf("existing ProxyDockerSync value = %q, want true (must not be overwritten)", s.Value)
	}
	if strings.TrimSpace(s.About) != "" || s.ID == 0 {
		t.Errorf("unexpected mutation of the existing row: id=%d about=%q", s.ID, s.About)
	}
}
