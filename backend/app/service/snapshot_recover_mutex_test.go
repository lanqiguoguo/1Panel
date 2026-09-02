package service

import (
	"sync"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/app/dto"
	"github.com/1Panel-dev/1Panel/backend/app/model"
	"github.com/1Panel-dev/1Panel/backend/constant"
)

// seedIdleRecoverSnap creates a snapshot row with no recover/rollback
// history — the state a fresh snapshot (or one whose rollback cleared the
// row) is in, which is the only state a claim may start from.
func seedIdleRecoverSnap(t *testing.T) model.Snapshot {
	t.Helper()
	snap := model.Snapshot{Name: "idle-mutex-snap", Status: constant.StatusSuccess}
	if err := snapshotRepo.Create(&snap); err != nil {
		t.Fatalf("seed idle snapshot failed: %v", err)
	}
	return snap
}

// settleRecoverRow emulates the terminal status write the real async flow
// performs (updateRecoverStatus) after a claim was released: it clears the
// Waiting marker the claim left, so the row is claimable again.
func settleRecoverRow(t *testing.T, id uint) {
	t.Helper()
	if err := snapshotRepo.Update(id, map[string]interface{}{"recover_status": "", "rollback_status": ""}); err != nil {
		t.Fatalf("settle snapshot row failed: %v", err)
	}
}

// TestClaimRecoverOpConcurrent verifies the per-snapshot claim under real
// concurrency: of N parallel claims on the same idle snapshot exactly one
// wins, every loser gets the busy error, and after the winner's flow settled
// (row marker cleared) a later claim succeeds again.
func TestClaimRecoverOpConcurrent(t *testing.T) {
	setupRecoverStatusTest(t)
	snap := seedIdleRecoverSnap(t)

	const workers = 8
	var wg sync.WaitGroup
	wins := make([]bool, workers)
	errs := make([]error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			release, err := claimRecoverOp(snap.ID)
			if err != nil {
				errs[i] = err
				return
			}
			wins[i] = true
			// Hold the claim briefly like a real restore would, then release.
			defer release()
		}(i)
	}
	wg.Wait()

	winnerCount := 0
	for i := 0; i < workers; i++ {
		if wins[i] {
			winnerCount++
		}
		if errs[i] != nil && errs[i].Error() == "" {
			t.Fatalf("worker %d got an empty busy error", i)
		}
	}
	if winnerCount != 1 {
		t.Fatalf("%d of %d concurrent claims won, want exactly 1", winnerCount, workers)
	}

	// the winning claim left the row Waiting (its in-flight marker); settle it
	settleRecoverRow(t, snap.ID)
	release, err := claimRecoverOp(snap.ID)
	if err != nil {
		t.Fatalf("claim after release failed: %v", err)
	}
	release()
}

// TestRecoverRollbackMutualExclusion verifies that recover and rollback of
// the same snapshot cannot overlap: while a recover claim is held (row
// recover_status Waiting), both a second recover and a rollback must be
// rejected, and vice versa.
func TestRecoverRollbackMutualExclusion(t *testing.T) {
	setupRecoverStatusTest(t)
	snap := seedIdleRecoverSnap(t)

	release, err := claimRecoverOp(snap.ID)
	if err != nil {
		t.Fatalf("first recover claim failed: %v", err)
	}
	// second recover is rejected by the in-process claim / Waiting row
	if _, err := claimRecoverOp(snap.ID); err == nil {
		t.Fatal("second recover claim succeeded while one is in flight")
	}
	// rollback is rejected while the recover runs
	if _, err := claimRollbackOp(snap.ID); err == nil {
		t.Fatal("rollback claim succeeded while a recover is in flight")
	}
	release()
	settleRecoverRow(t, snap.ID)

	// After the recover settled, a rollback claim succeeds...
	relRoll, err := claimRollbackOp(snap.ID)
	if err != nil {
		t.Fatalf("rollback claim after recover failed: %v", err)
	}
	// ...and now a recover is rejected while the rollback runs.
	if _, err := claimRecoverOp(snap.ID); err == nil {
		t.Fatal("recover claim succeeded while a rollback is in flight")
	}
	relRoll()
}

// TestSnapshotRecoverRejectsInFlight verifies the entry point rejects a
// request whose row already carries the in-flight Waiting marker (set by the
// CAS of a previous winner) without spawning the async flow — the
// fire-and-forget handler must never start twice for the same snapshot.
func TestSnapshotRecoverRejectsInFlight(t *testing.T) {
	setupRecoverStatusTest(t)
	snap := seedRecoverSnap(t, map[string]interface{}{
		"recover_status": constant.StatusWaiting,
	})

	svc := &SnapshotService{}
	err := svc.SnapshotRecover(dto.SnapshotRecover{ID: snap.ID, IsNew: true})
	if err == nil {
		t.Fatal("SnapshotRecover accepted a snapshot whose recover_status is Waiting")
	}
	if err.Error() == "" {
		t.Fatal("SnapshotRecover returned an empty busy error")
	}
	row, err := snapshotRepo.Get(commonRepo.WithByID(snap.ID))
	if err != nil {
		t.Fatalf("reload snapshot failed: %v", err)
	}
	if row.RecoverStatus != constant.StatusWaiting {
		t.Fatalf("row recover_status = %q after rejected entry, want untouched Waiting", row.RecoverStatus)
	}
}

// TestSnapshotRollbackRejectsInFlight mirrors the recover entry check for the
// rollback side.
func TestSnapshotRollbackRejectsInFlight(t *testing.T) {
	setupRecoverStatusTest(t)
	snap := seedRecoverSnap(t, map[string]interface{}{
		"recover_status":  constant.StatusFailed,
		"rollback_status": constant.StatusWaiting,
	})

	svc := &SnapshotService{}
	if err := svc.SnapshotRollback(dto.SnapshotRecover{ID: snap.ID}); err == nil {
		t.Fatal("SnapshotRollback accepted a snapshot whose rollback_status is Waiting")
	}
}

// TestSnapshotRecoverRejectsClaimedInProcess verifies the entry point loses
// to an in-process claim even when the DB row is still idle (the window
// between the CAS winner starting and the row being persisted — covered by
// the in-process lock, which the entry checks through claimRecoverOp).
func TestSnapshotRecoverRejectsClaimedInProcess(t *testing.T) {
	setupRecoverStatusTest(t)
	snap := seedIdleRecoverSnap(t)

	release := claimSnapshotOpLock(snap.ID)
	if release == nil {
		t.Fatal("first claim failed")
	}
	defer release()

	svc := &SnapshotService{}
	if err := svc.SnapshotRecover(dto.SnapshotRecover{ID: snap.ID, IsNew: true}); err == nil {
		t.Fatal("SnapshotRecover succeeded while another flow holds the in-process claim")
	}
	// the row must stay idle (the losing entry must not touch it)
	row, err := snapshotRepo.Get(commonRepo.WithByID(snap.ID))
	if err != nil {
		t.Fatalf("reload snapshot failed: %v", err)
	}
	if row.RecoverStatus != "" {
		t.Fatalf("row recover_status = %q after rejected entry, want empty", row.RecoverStatus)
	}
}

// TestSnapshotDeleteRejectsInFlight verifies Delete refuses a snapshot that
// is being recovered/rolled back (Waiting marker) or claimed in-process, and
// leaves both the row and its local artifacts untouched.
func TestSnapshotDeleteRejectsInFlight(t *testing.T) {
	t.Run("waiting marker row is refused", func(t *testing.T) {
		setupRecoverStatusTest(t)
		snap := seedRecoverSnap(t, map[string]interface{}{
			"recover_status": constant.StatusWaiting,
		})
		svc := &SnapshotService{}
		if err := svc.Delete(dto.SnapshotBatchDelete{Ids: []uint{snap.ID}}); err == nil {
			t.Fatal("Delete accepted a snapshot whose recover_status is Waiting")
		}
		if _, err := snapshotRepo.Get(commonRepo.WithByID(snap.ID)); err != nil {
			t.Fatalf("snapshot row was deleted despite the rejected delete: %v", err)
		}
	})

	t.Run("claimed in-process row is refused", func(t *testing.T) {
		setupRecoverStatusTest(t)
		snap := seedIdleRecoverSnap(t)
		release := claimSnapshotOpLock(snap.ID)
		if release == nil {
			t.Fatal("first claim failed")
		}
		defer release()
		svc := &SnapshotService{}
		if err := svc.Delete(dto.SnapshotBatchDelete{Ids: []uint{snap.ID}}); err == nil {
			t.Fatal("Delete succeeded while a flow holds the in-process claim")
		}
		if _, err := snapshotRepo.Get(commonRepo.WithByID(snap.ID)); err != nil {
			t.Fatalf("snapshot row was deleted despite the rejected delete: %v", err)
		}
	})

	t.Run("rollback waiting marker row is refused", func(t *testing.T) {
		setupRecoverStatusTest(t)
		snap := seedRecoverSnap(t, map[string]interface{}{
			"rollback_status": constant.StatusWaiting,
		})
		svc := &SnapshotService{}
		if err := svc.Delete(dto.SnapshotBatchDelete{Ids: []uint{snap.ID}}); err == nil {
			t.Fatal("Delete accepted a snapshot whose rollback_status is Waiting")
		}
		if _, err := snapshotRepo.Get(commonRepo.WithByID(snap.ID)); err != nil {
			t.Fatalf("snapshot row was deleted despite the rejected delete: %v", err)
		}
	})
}

// TestRecoverAfterTerminalStatesStillAllowed pins that the mutual exclusion
// does not lock a settled snapshot forever: a snapshot whose recover failed
// (terminal Failed state, no rollback in flight) can be claimed again — the
// UI retry path.
func TestRecoverAfterTerminalStatesStillAllowed(t *testing.T) {
	setupRecoverStatusTest(t)
	snap := seedRecoverSnap(t, map[string]interface{}{
		"recover_status":   constant.StatusFailed,
		"recover_message":  "boom",
		"rollback_status":  "",
		"rollback_message": "",
	})
	release, err := claimRecoverOp(snap.ID)
	if err != nil {
		t.Fatalf("recover claim after a failed recover failed: %v", err)
	}
	release()
	settleRecoverRow(t, snap.ID)
	release, err = claimRecoverOp(snap.ID)
	if err != nil {
		t.Fatalf("re-claim after settled failed recover failed: %v", err)
	}
	release()
}
