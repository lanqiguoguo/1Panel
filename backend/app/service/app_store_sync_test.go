package service

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/1Panel-dev/1Panel/backend/app/model"
	"github.com/1Panel-dev/1Panel/backend/constant"
	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/glebarez/sqlite"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

// captureLogWriter records log output; writes containing trigger panic, which
// simulates a broken log sink so the panic escapes through the sync flow.
type captureLogWriter struct {
	buf     bytes.Buffer
	trigger string
	panics  int
}

func (w *captureLogWriter) Write(p []byte) (int, error) {
	if w.trigger != "" && strings.Contains(string(p), w.trigger) {
		w.panics++
		panic("injected log write failure")
	}
	return w.buf.Write(p)
}

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

// TestSetAppStoreSyncStatusPersistsAndLogs covers the status-flag write helper:
// a successful write must persist the flag, and a failed write must neither
// panic nor vanish — the flag gates the single-flight check of
// SyncAppListFromRemote and the stuck-sync indicator in GetAppUpdate, so a
// failed write silently degrades both and must therefore be logged.
func TestSetAppStoreSyncStatusPersistsAndLogs(t *testing.T) {
	setupAppStoreSyncTest(t)
	capture := &captureLogWriter{}
	logger := logrus.New()
	logger.SetOutput(capture)
	logger.SetLevel(logrus.DebugLevel)
	global.LOG = logger

	svc := NewISettingService()
	setAppStoreSyncStatus(svc, constant.SyncFailed)
	setting, err := svc.GetSettingInfo()
	if err != nil {
		t.Fatalf("read settings failed: %v", err)
	}
	if setting.AppStoreSyncStatus != constant.SyncFailed {
		t.Fatalf("AppStoreSyncStatus = %s, want %s after a successful write", setting.AppStoreSyncStatus, constant.SyncFailed)
	}

	// Break the settings table: the status write now fails. The helper must
	// surface the failure in the logs instead of swallowing it (and must not
	// panic, since the sync keeps running best-effort).
	if err := global.DB.Migrator().DropTable(&model.Setting{}); err != nil {
		t.Fatalf("drop settings table failed: %v", err)
	}
	setAppStoreSyncStatus(svc, constant.Syncing)
	if !strings.Contains(capture.buf.String(), "may not be gated correctly") {
		t.Errorf("failed status write was not logged, log output: %q", capture.buf.String())
	}
}

// TestSyncAppListFromRemoteRecoversPanic verifies the recover added to
// SyncAppListFromRemote: the sync runs in a bare goroutine started by the API
// layer (no gin recovery), so an escaping panic would crash the process and
// leave AppStoreSyncStatus stuck on Syncing forever. The test injects a panic
// via a log sink that fails on the sync's first log line and asserts that the
// panic is converted into a regular error, the failure flag is persisted and
// the panic (with stack) is logged.
func TestSyncAppListFromRemoteRecoversPanic(t *testing.T) {
	setupAppStoreSyncTest(t)
	capture := &captureLogWriter{trigger: "Starting synchronization with App Store"}
	logger := logrus.New()
	logger.SetOutput(capture)
	logger.SetLevel(logrus.DebugLevel)
	global.LOG = logger

	err := (AppService{}).SyncAppListFromRemote()
	if err == nil || !strings.Contains(err.Error(), "panicked") {
		t.Fatalf("err = %v, want the wrapped panic error", err)
	}
	if capture.panics == 0 {
		t.Fatal("the injected log sink failure never panicked: the recover path was not exercised")
	}
	if !strings.Contains(capture.buf.String(), "panic during App Store synchronization") {
		t.Errorf("the panic was not logged, log output: %q", capture.buf.String())
	}

	setting, err := NewISettingService().GetSettingInfo()
	if err != nil {
		t.Fatalf("read settings failed: %v", err)
	}
	if setting.AppStoreSyncStatus != constant.SyncFailed {
		t.Fatalf("AppStoreSyncStatus = %s, want %s: a panic must not leave the flag stuck on Syncing", setting.AppStoreSyncStatus, constant.SyncFailed)
	}
}
