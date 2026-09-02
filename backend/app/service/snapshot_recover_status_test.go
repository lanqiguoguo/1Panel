package service

import (
	"testing"

	"github.com/1Panel-dev/1Panel/backend/app/model"
	"github.com/1Panel-dev/1Panel/backend/constant"
	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/glebarez/sqlite"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

// setupRecoverStatusTest builds an in-memory database carrying the tables that
// updateRecoverStatus touches: snapshots (recover/rollback columns) and
// settings (SystemStatus gate consumed by the GlobalLoading middleware). The
// settings repo update is a silent no-op on a missing row, so every test seeds
// SystemStatus=Recovering exactly like SnapshotRecover does before it spawns
// HandleSnapshotRecover.
func setupRecoverStatusTest(t *testing.T) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"-rec?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open in-memory sqlite failed: %v", err)
	}
	if err := db.AutoMigrate(&model.Snapshot{}, &model.Setting{}); err != nil {
		t.Fatalf("migrate snapshot/setting tables failed: %v", err)
	}
	global.DB = db
	global.LOG = logrus.New()

	if err := settingRepo.Create("SystemStatus", "Recovering"); err != nil {
		t.Fatalf("seed SystemStatus failed: %v", err)
	}
}

func seedRecoverSnap(t *testing.T, fields map[string]interface{}) model.Snapshot {
	t.Helper()
	snap := model.Snapshot{
		Name:            "recover-status-test",
		Status:          constant.StatusSuccess,
		RecoverStatus:   constant.StatusWaiting,
		RecoverMessage:  "pending recover",
		RollbackStatus:  constant.StatusWaiting,
		RollbackMessage: "pending rollback",
	}
	for k, v := range fields {
		switch k {
		case "recover_status":
			snap.RecoverStatus = v.(string)
		case "recover_message":
			snap.RecoverMessage = v.(string)
		case "rollback_status":
			snap.RollbackStatus = v.(string)
		case "rollback_message":
			snap.RollbackMessage = v.(string)
		case "interrupt_step":
			snap.InterruptStep = v.(string)
		}
	}
	if err := snapshotRepo.Create(&snap); err != nil {
		t.Fatalf("seed snapshot failed: %v", err)
	}
	return snap
}

func systemStatus(t *testing.T) string {
	t.Helper()
	item, err := settingRepo.Get(settingRepo.WithByKey("SystemStatus"))
	if err != nil {
		t.Fatalf("read SystemStatus failed: %v", err)
	}
	return item.Value
}

// TestUpdateRecoverStatusRecoverSuccess pins the success-path terminal state of
// a recovery: recover_status must be recorded as StatusSuccess (so the init
// hook no longer mislabels the run as "interrupted due to restart" and the
// frontend shows a success tag) and SystemStatus must return to Free BEFORE the
// process restart. Previously nothing cleared the row, so the restarting hook
// stamped every successful recovery as failed and a failed restart left the
// panel locked in Recovering.
func TestUpdateRecoverStatusRecoverSuccess(t *testing.T) {
	setupRecoverStatusTest(t)
	snap := seedRecoverSnap(t, nil)

	updateRecoverStatus(snap.ID, true, "", constant.StatusSuccess, "")

	row, err := snapshotRepo.Get(commonRepo.WithByID(snap.ID))
	if err != nil {
		t.Fatalf("reload snapshot failed: %v", err)
	}
	if row.RecoverStatus != constant.StatusSuccess {
		t.Fatalf("recover_status = %q, want %q", row.RecoverStatus, constant.StatusSuccess)
	}
	if row.InterruptStep != "" {
		t.Fatalf("interrupt_step = %q, want empty on success", row.InterruptStep)
	}
	if row.LastRecoveredAt == "" {
		t.Fatal("last_recovered_at not recorded on success")
	}
	if got := systemStatus(t); got != "Free" {
		t.Fatalf("SystemStatus = %q, want %q (panel must not stay locked)", got, "Free")
	}
}

// TestUpdateRecoverStatusRecoverFailed verifies the failure path of a recovery:
// the failed step and its message are recorded and SystemStatus is released
// back to Free, so a failed restore can never leave GlobalLoading rejecting
// every API call.
func TestUpdateRecoverStatusRecoverFailed(t *testing.T) {
	setupRecoverStatusTest(t)
	snap := seedRecoverSnap(t, nil)

	updateRecoverStatus(snap.ID, true, "1PanelData", constant.StatusFailed, "boom: untar failed")

	row, err := snapshotRepo.Get(commonRepo.WithByID(snap.ID))
	if err != nil {
		t.Fatalf("reload snapshot failed: %v", err)
	}
	if row.RecoverStatus != constant.StatusFailed {
		t.Fatalf("recover_status = %q, want %q", row.RecoverStatus, constant.StatusFailed)
	}
	if row.RecoverMessage != "boom: untar failed" {
		t.Fatalf("recover_message = %q, want the failure reason", row.RecoverMessage)
	}
	if row.InterruptStep != "1PanelData" {
		t.Fatalf("interrupt_step = %q, want %q for resumable retry", row.InterruptStep, "1PanelData")
	}
	if got := systemStatus(t); got != "Free" {
		t.Fatalf("SystemStatus = %q, want %q after a failed recovery", got, "Free")
	}
}

// TestUpdateRecoverStatusRollbackSuccess pins the terminal state of a
// successful rollback (isRecover=false): both the rollback and the earlier
// failed recover markers must be cleared so the snapshot can be recovered
// again, and SystemStatus must be Free.
func TestUpdateRecoverStatusRollbackSuccess(t *testing.T) {
	setupRecoverStatusTest(t)
	snap := seedRecoverSnap(t, map[string]interface{}{
		"recover_status":   constant.StatusFailed,
		"recover_message":  "first recover attempt failed",
		"interrupt_step":   "1PanelData",
		"rollback_status":  constant.StatusWaiting,
		"rollback_message": "pending rollback",
	})

	updateRecoverStatus(snap.ID, false, "", constant.StatusSuccess, "")

	row, err := snapshotRepo.Get(commonRepo.WithByID(snap.ID))
	if err != nil {
		t.Fatalf("reload snapshot failed: %v", err)
	}
	for field, got := range map[string]string{
		"recover_status":   row.RecoverStatus,
		"recover_message":  row.RecoverMessage,
		"interrupt_step":   row.InterruptStep,
		"rollback_status":  row.RollbackStatus,
		"rollback_message": row.RollbackMessage,
	} {
		if got != "" {
			t.Fatalf("%s = %q, want empty after a successful rollback", field, got)
		}
	}
	if row.LastRollbackedAt == "" {
		t.Fatal("last_rollbacked_at not recorded on rollback success")
	}
	if got := systemStatus(t); got != "Free" {
		t.Fatalf("SystemStatus = %q, want %q", got, "Free")
	}
}

// TestUpdateRecoverStatusRollbackFailed verifies a failed rollback: only the
// rollback fields are marked failed (the recover history stays untouched so
// the frontend still shows why the rollback was offered) and SystemStatus is
// released.
func TestUpdateRecoverStatusRollbackFailed(t *testing.T) {
	setupRecoverStatusTest(t)
	snap := seedRecoverSnap(t, map[string]interface{}{
		"recover_status":  constant.StatusFailed,
		"recover_message": "boom",
	})

	updateRecoverStatus(snap.ID, false, "", constant.StatusFailed, "rollback exploded")

	row, err := snapshotRepo.Get(commonRepo.WithByID(snap.ID))
	if err != nil {
		t.Fatalf("reload snapshot failed: %v", err)
	}
	if row.RollbackStatus != constant.StatusFailed {
		t.Fatalf("rollback_status = %q, want %q", row.RollbackStatus, constant.StatusFailed)
	}
	if row.RollbackMessage != "rollback exploded" {
		t.Fatalf("rollback_message = %q, want the failure reason", row.RollbackMessage)
	}
	if row.RecoverStatus != constant.StatusFailed || row.RecoverMessage != "boom" {
		t.Fatalf("recover history was clobbered: recover_status=%q recover_message=%q", row.RecoverStatus, row.RecoverMessage)
	}
	if got := systemStatus(t); got != "Free" {
		t.Fatalf("SystemStatus = %q, want %q after a failed rollback", got, "Free")
	}
}
