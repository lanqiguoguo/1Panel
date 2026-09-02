package service

import (
	"os"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/app/dto"
	"github.com/1Panel-dev/1Panel/backend/app/model"
	"github.com/1Panel-dev/1Panel/backend/constant"
	"github.com/1Panel-dev/1Panel/backend/global"
)

// TestDeleteRunRaceNoOrphanRecord reproduces the delete-vs-start race: a job
// body starting while Delete cleans the records must insert its record before
// the wipe, never after it. Delete holds cronjobRunMu across CleanRecord +
// row delete and HandleJob inserts the record under the same lock after
// re-loading the row, so once the delete settles no JobRecords row and no
// cronjob row of that job may exist — and a still-running body that finishes
// later must not error or recreate anything (EndRecords on a wiped record
// matches zero rows and is tolerated).
func TestDeleteRunRaceNoOrphanRecord(t *testing.T) {
	setupCronjobUpdateTestDB(t)
	// Delete's IsDelete branch detaches backup records of the job; migrate
	// the table so the query succeeds in the in-memory DB.
	if err := global.DB.AutoMigrate(&model.BackupRecord{}); err != nil {
		t.Fatalf("migrate backup_records: %v", err)
	}
	svc := &CronjobService{}

	job := model.Cronjob{Name: "race-job", Type: "shell", Spec: "* * * * *", Status: constant.StatusEnable, Script: "sleep 0.1"}
	if err := global.DB.Create(&job).Error; err != nil {
		t.Fatalf("seed cronjob: %v", err)
	}

	// A body that already holds the record-insertion lock (exactly the
	// HandleJob critical section): its record lands before the wipe.
	cronjobRunMu.Lock()
	record := cronjobRepo.StartRecords(job.ID, job.KeepLocal, "")
	cronjobRunMu.Unlock()
	if record.ID == 0 {
		t.Fatal("StartRecords returned a zero record")
	}

	// The delete runs now; it must wipe both the record and the row.
	if err := svc.Delete(dto.CronjobBatchDelete{IDs: []uint{job.ID}}); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	var count int64
	if err := global.DB.Model(&model.Cronjob{}).Where("id = ?", job.ID).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("cronjob row still exists after Delete")
	}
	if err := global.DB.Model(&model.JobRecords{}).Where("cronjob_id = ?", job.ID).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("%d JobRecords rows still exist after Delete", count)
	}

	// The in-flight body finishing now must be tolerated (zero-row update)
	// and must not recreate a record.
	svc.body(&job, record)
	if err := global.DB.Model(&model.JobRecords{}).Where("cronjob_id = ?", job.ID).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("body finishing after Delete re-created a JobRecords row")
	}
}

// TestHandleJobSkipsDeletedJob verifies that a HandleJob call racing a
// completed Delete skips the run instead of recreating task artifacts: the
// row reload inside HandleJob fails and the body never executes.
func TestHandleJobSkipsDeletedJob(t *testing.T) {
	setupCronjobUpdateTestDB(t)
	marker := "/tmp/1p-deleted-job-marker-zz"
	_ = os.Remove(marker)
	defer os.Remove(marker)

	job := model.Cronjob{Name: "deleted-race", Type: "shell", Spec: "* * * * *", Status: constant.StatusEnable, Script: "touch " + marker}
	if err := global.DB.Create(&job).Error; err != nil {
		t.Fatalf("seed cronjob: %v", err)
	}
	// Delete already ran: no cronjob row left, but the stale pointer a tick
	// callback would have held still points at the removed job.
	if err := global.DB.Delete(&model.Cronjob{}, job.ID).Error; err != nil {
		t.Fatal(err)
	}
	svc := &CronjobService{}
	svc.HandleJob(&job)

	if _, err := os.Stat(marker); err == nil {
		t.Fatalf("deleted job body executed and created %s", marker)
	}
	var count int64
	if err := global.DB.Model(&model.JobRecords{}).Where("cronjob_id = ?", job.ID).Count(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("HandleJob of a deleted job inserted %d JobRecords rows", count)
	}
}
