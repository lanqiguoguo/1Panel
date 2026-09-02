package migrations

import (
	"testing"

	"github.com/1Panel-dev/1Panel/backend/app/model"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

// TestAddJWTRefreshVersionIdempotent verifies the migration never duplicates
// the JWTRefreshVersion row even when replayed: the settings table has no
// unique constraint on key, so gormigrate's recorded-ID guard is the only
// protection on the normal path, and it does not survive a lost migration
// record or a manual replay.
func TestAddJWTRefreshVersionIdempotent(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open in-memory sqlite failed: %v", err)
	}
	if err := db.AutoMigrate(&model.Setting{}); err != nil {
		t.Fatalf("migrate settings failed: %v", err)
	}

	if err := AddJWTRefreshVersion.Migrate(db); err != nil {
		t.Fatalf("first AddJWTRefreshVersion.Migrate failed: %v", err)
	}
	if err := AddJWTRefreshVersion.Migrate(db); err != nil {
		t.Fatalf("second AddJWTRefreshVersion.Migrate failed: %v", err)
	}

	var count int64
	if err := db.Model(&model.Setting{}).Where("key = ?", "JWTRefreshVersion").Count(&count).Error; err != nil {
		t.Fatalf("count JWTRefreshVersion failed: %v", err)
	}
	if count != 1 {
		t.Fatalf("JWTRefreshVersion rows = %d, want exactly 1", count)
	}

	var s model.Setting
	if err := db.Where("key = ?", "JWTRefreshVersion").First(&s).Error; err != nil {
		t.Fatalf("read JWTRefreshVersion failed: %v", err)
	}
	if s.Value != "1" {
		t.Errorf("JWTRefreshVersion value = %q, want 1", s.Value)
	}
}

// TestAddJWTRefreshVersionKeepsExistingRow covers the upgrade-over path: a
// row already present (e.g. fresh install seeded by AddTableSetting, or an
// operator bumped the version past the default) must be kept untouched.
func TestAddJWTRefreshVersionKeepsExistingRow(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open in-memory sqlite failed: %v", err)
	}
	if err := db.AutoMigrate(&model.Setting{}); err != nil {
		t.Fatalf("migrate settings failed: %v", err)
	}
	if err := db.Create(&model.Setting{Key: "JWTRefreshVersion", Value: "7"}).Error; err != nil {
		t.Fatalf("seed JWTRefreshVersion failed: %v", err)
	}

	if err := AddJWTRefreshVersion.Migrate(db); err != nil {
		t.Fatalf("AddJWTRefreshVersion.Migrate failed: %v", err)
	}
	var s model.Setting
	if err := db.Where("key = ?", "JWTRefreshVersion").First(&s).Error; err != nil {
		t.Fatalf("read JWTRefreshVersion failed: %v", err)
	}
	if s.Value != "7" {
		t.Errorf("JWTRefreshVersion value = %q after migration, want existing 7", s.Value)
	}
}
