package service

import (
	"testing"
	"time"

	"github.com/1Panel-dev/1Panel/backend/app/model"
	"github.com/1Panel-dev/1Panel/backend/constant"
	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/glebarez/sqlite"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

// setupAppStoreSyncTest prepares an in-memory sqlite DB with a seeded settings
// table (mirroring setupSettingUpdateTest) so that GetSettingInfo/Update work
// without any external dependency.
func setupAppStoreSyncTest(t *testing.T) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open in-memory sqlite failed: %v", err)
	}
	if err := db.AutoMigrate(&model.Setting{}); err != nil {
		t.Fatalf("migrate settings failed: %v", err)
	}
	if err := db.Create(&model.Setting{Key: "AppStoreSyncStatus", Value: constant.SyncSuccess}).Error; err != nil {
		t.Fatalf("seed AppStoreSyncStatus failed: %v", err)
	}
	if err := db.Create(&model.Setting{Key: "AppStoreLastModified", Value: "0"}).Error; err != nil {
		t.Fatalf("seed AppStoreLastModified failed: %v", err)
	}
	global.DB = db
}

// TestSyncAppListFromRemoteSingleFlight verifies the single-flight gate added
// to SyncAppListFromRemote. A real two-goroutine race cannot be exercised
// deterministically here: the sync body immediately performs network pulls
// (GetAppUpdate/downloadAppAssets) that fail fast offline, so the overlap
// window would be a microsecond race. Instead the test simulates an in-flight
// synchronization by holding the package-level appStoreSyncMu with the DB
// status set to Syncing, then asserts:
//
//  1. A concurrent call BLOCKS on the mutex instead of returning right away —
//     i.e. the gate is checked before the status read, which is the fix. The
//     pre-fix code (check-then-act only) would return immediately here.
//  2. Once the lock is released the waiting call acquires it, sees Syncing
//     and returns nil ("already syncing") without entering the sync body.
func TestSyncAppListFromRemoteSingleFlight(t *testing.T) {
	setupAppStoreSyncTest(t)
	global.LOG = logrus.New()

	// Simulate a synchronization that is currently running: DB status says
	// Syncing and the mutex is held by the running sync.
	if err := global.DB.Model(&model.Setting{}).
		Where("key = ?", "AppStoreSyncStatus").
		Update("value", constant.Syncing).Error; err != nil {
		t.Fatalf("set AppStoreSyncStatus to Syncing failed: %v", err)
	}
	appStoreSyncMu.Lock()

	done := make(chan error, 1)
	go func() { done <- (AppService{}).SyncAppListFromRemote() }()

	// The call must wait for the in-flight sync: with the single-flight gate
	// the mutex is acquired before the status check, so the goroutine cannot
	// finish while the lock is held.
	select {
	case err := <-done:
		t.Fatalf("call returned (%v) while the sync lock is held: the single-flight gate is missing", err)
	case <-time.After(500 * time.Millisecond):
		// expected: the call is queued behind the in-flight sync
	}

	// Let the "in-flight" sync finish; the waiting call then acquires the
	// lock, observes Syncing and must short-circuit with nil.
	appStoreSyncMu.Unlock()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("call after lock release returned error %v, want nil (already syncing)", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("call did not return after the lock was released")
	}

	// Status must still be Syncing: the short-circuited call must not have
	// entered the sync body (which would have failed offline and flipped the
	// status to SyncFailed via the deferred handler).
	setting, err := NewISettingService().GetSettingInfo()
	if err != nil {
		t.Fatalf("read settings failed: %v", err)
	}
	if setting.AppStoreSyncStatus != constant.Syncing {
		t.Fatalf("AppStoreSyncStatus = %s, want %s: the call entered the sync body", setting.AppStoreSyncStatus, constant.Syncing)
	}
}
