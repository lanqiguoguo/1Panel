package migrations

import (
	"os"
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

// TestUpdateOnedriveClearsHardcodedCredential guards the OneDrive settings
// migration: the row must be cleared instead of seeded with the publicly
// known Azure OAuth client id/secret that earlier releases hardcoded into
// every installation. Fresh installs (init.go AddMfaInterval) and upgrades
// (v_1_10 UpdateOnedrive) must both end up with an empty value; a real
// credential an admin configured themselves must survive untouched.
func TestUpdateOnedriveClearsHardcodedCredential(t *testing.T) {
	t.Run("update-onedrive clears stored hardcoded values", func(t *testing.T) {
		db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
		if err != nil {
			t.Fatalf("open in-memory sqlite failed: %v", err)
		}
		if err := db.AutoMigrate(&model.Setting{}); err != nil {
			t.Fatalf("migrate settings failed: %v", err)
		}
		// rows as an upgraded instance would carry them today
		if err := db.Create(&model.Setting{Key: "OneDriveID", Value: "MDEwOTM1YTktMWFhOS00ODU0LWExZGMtNmU0NWZlNjI4YzZi"}).Error; err != nil {
			t.Fatalf("seed OneDriveID failed: %v", err)
		}
		if err := db.Create(&model.Setting{Key: "OneDriveSc", Value: "bGRlOFF+WEVrR1M0b25Vb1VsRWpMYzE2MW9rTXZEM25KdnZ1MGN6MA=="}).Error; err != nil {
			t.Fatalf("seed OneDriveSc failed: %v", err)
		}

		if err := UpdateOnedrive.Migrate(db); err != nil {
			t.Fatalf("UpdateOnedrive.Migrate failed: %v", err)
		}

		for _, key := range []string{"OneDriveID", "OneDriveSc"} {
			var s model.Setting
			if err := db.Where("key = ?", key).First(&s).Error; err != nil {
				t.Fatalf("read %s failed: %v", key, err)
			}
			if s.Value != "" {
				t.Errorf("%s value = %q after UpdateOnedrive, want empty", key, s.Value)
			}
		}
	})

	t.Run("update-onedrive keeps admin-configured credentials", func(t *testing.T) {
		db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
		if err != nil {
			t.Fatalf("open in-memory sqlite failed: %v", err)
		}
		if err := db.AutoMigrate(&model.Setting{}); err != nil {
			t.Fatalf("migrate settings failed: %v", err)
		}
		if err := db.Create(&model.Setting{Key: "OneDriveID", Value: "b3duLWF6dXJlLWNsaWVudC1pZA=="}).Error; err != nil {
			t.Fatalf("seed OneDriveID failed: %v", err)
		}
		if err := db.Create(&model.Setting{Key: "OneDriveSc", Value: "b3duLWF6dXJlLXNlY3JldA=="}).Error; err != nil {
			t.Fatalf("seed OneDriveSc failed: %v", err)
		}

		if err := UpdateOnedrive.Migrate(db); err != nil {
			t.Fatalf("UpdateOnedrive.Migrate failed: %v", err)
		}

		var s model.Setting
		if err := db.Where("key = ?", "OneDriveID").First(&s).Error; err != nil {
			t.Fatalf("read OneDriveID failed: %v", err)
		}
		if s.Value == "MDEwOTM1YTktMWFhOS00ODU0LWExZGMtNmU0NWZlNjI4YzZi" ||
			s.Value == "NTQ0NmNmZTMtNGM3OS00N2EwLWFlMjUtZmM2NDU0NzhlMmQ5" {
			t.Errorf("OneDriveID was reset to a hardcoded credential: %q", s.Value)
		}
	})

	t.Run("init-migration inserts empty OneDrive settings", func(t *testing.T) {
		db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
		if err != nil {
			t.Fatalf("open in-memory sqlite failed: %v", err)
		}
		if err := db.AutoMigrate(&model.Setting{}); err != nil {
			t.Fatalf("migrate settings failed: %v", err)
		}
		if err := AddMfaInterval.Migrate(db); err != nil {
			t.Fatalf("AddMfaInterval.Migrate failed: %v", err)
		}

		for _, key := range []string{"OneDriveID", "OneDriveSc"} {
			var s model.Setting
			if err := db.Where("key = ?", key).First(&s).Error; err != nil {
				t.Fatalf("read %s failed: %v", key, err)
			}
			if s.Value != "" {
				t.Errorf("%s value = %q after AddMfaInterval, want empty", key, s.Value)
			}
		}
	})
}

// TestMigrationsNoHardcodedOneDriveCredential is a static guard over the
// migration sources: no migration may embed a base64-encoded Azure client
// id/secret as a default value. Fresh installs must never receive a shared,
// public OAuth credential.
func TestMigrationsNoHardcodedOneDriveCredential(t *testing.T) {
	contents := []struct {
		file string
		data string
	}{
		{"init.go", mustReadFile(t, "init.go")},
		{"v_1_9.go", mustReadFile(t, "v_1_9.go")},
		{"v_1_10.go", mustReadFile(t, "v_1_10.go")},
	}
	for _, c := range contents {
		if strings.Contains(c.data, "MDEwOTM1YTktMWFhOS00ODU0LWExZGMtNmU0NWZlNjI4YzZi") ||
			strings.Contains(c.data, "akpuOFF+YkNXOU1OLWRzS1ZSRDdOcG1LT2ZRM0RLNmdvS1RkVWNGRA==") ||
			strings.Contains(c.data, "NTQ0NmNmZTMtNGM3OS00N2EwLWFlMjUtZmM2NDU0NzhlMmQ5") ||
			strings.Contains(c.data, "bGRlOFF+WEVrR1M0b25Vb1VsRWpMYzE2MW9rTXZEM25KdnZ1MGN6MA==") {
			t.Errorf("%s still contains a hardcoded OneDrive credential", c.file)
		}
	}
}

func mustReadFile(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s failed: %v", name, err)
	}
	return string(data)
}
