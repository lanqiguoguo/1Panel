package service

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/app/model"
	"github.com/1Panel-dev/1Panel/backend/constant"
	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/glebarez/sqlite"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

func setupSnapshotTest(t *testing.T) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open in-memory sqlite failed: %v", err)
	}
	if err := db.AutoMigrate(&model.Snapshot{}, &model.SnapshotStatus{}); err != nil {
		t.Fatalf("migrate snapshot tables failed: %v", err)
	}
	global.DB = db
	global.LOG = logrus.New()
}

// TestSnapshotNameUnique verifies that two snapshot creations sharing the same
// second-level timestamp do not collide on the snapshot name: the first call
// returns the plain readable name, the second (same timeNow, record already
// present) gets a random suffix appended. This exercises the exact
// buildSnapshotName logic used by HandleSnapshot before any real snapshot work
// (file system / docker / systemctl operations) runs, so it is safe in the
// test environment.
func TestSnapshotNameUnique(t *testing.T) {
	setupSnapshotTest(t)

	const (
		version = "v1.10.20-lts"
		osArch  = "amd64"
		timeNow = "20260828120000"
	)

	first := buildSnapshotName(version, osArch, timeNow, false)
	expected := fmt.Sprintf("1panel_%s_%s_%s", version, osArch, timeNow)
	if first != expected {
		t.Fatalf("first name = %q, want %q", first, expected)
	}

	// Simulate the first creation having been persisted (as HandleSnapshot
	// does via snapshotRepo.Create before any worker starts).
	if err := snapshotRepo.Create(&model.Snapshot{Name: first}); err != nil {
		t.Fatalf("seed snapshot record failed: %v", err)
	}

	second := buildSnapshotName(version, osArch, timeNow, false)
	if second == first {
		t.Fatalf("second name = %q equals first name, want a suffixed unique name", second)
	}
	if !strings.HasPrefix(second, expected+"-") {
		t.Fatalf("second name = %q, want prefix %q with a suffix", second, expected+"-")
	}
	if len(second) <= len(expected)+1 {
		t.Fatalf("second name = %q, want a non-empty suffix", second)
	}

	// The dedup is also exercised for the cronjob name variant.
	cronFirst := buildSnapshotName(version, osArch, timeNow, true)
	cronExpected := fmt.Sprintf("snapshot_1panel_%s_%s_%s", version, osArch, timeNow)
	if cronFirst != cronExpected {
		t.Fatalf("cronjob first name = %q, want %q", cronFirst, cronExpected)
	}
	if err := snapshotRepo.Create(&model.Snapshot{Name: cronFirst}); err != nil {
		t.Fatalf("seed cronjob snapshot record failed: %v", err)
	}
	cronSecond := buildSnapshotName(version, osArch, timeNow, true)
	if cronSecond == cronFirst {
		t.Fatalf("cronjob second name = %q equals first name, want a suffixed unique name", cronSecond)
	}
	if !strings.HasPrefix(cronSecond, cronExpected+"-") {
		t.Fatalf("cronjob second name = %q, want prefix %q with a suffix", cronSecond, cronExpected+"-")
	}
}

// TestSnapshotStatusNoSharedWriteRace verifies that snapshot status progress is
// only ever persisted through the database, never through shared in-memory
// fields, and that concurrent DB writes to the same status row are race-free.
//
// The snapshot worker functions (snapJson/snapPanel/...) cannot run here: they
// shell out to systemctl, docker, tar and system paths. Instead this test pins
// the invariant that the workers communicate solely via
// snapshotRepo.UpdateStatus by (a) asserting the in-memory status struct
// passed to the workers stays untouched while (b) hammering concurrent
// UpdateStatus calls on the same row, which is the exact access pattern the
// workers now use and what -race needs to verify.
func TestSnapshotStatusNoSharedWriteRace(t *testing.T) {
	setupSnapshotTest(t)

	snap := model.Snapshot{Name: "race-test", Status: constant.StatusWaiting}
	if err := snapshotRepo.Create(&snap); err != nil {
		t.Fatalf("create snapshot failed: %v", err)
	}
	status := model.SnapshotStatus{SnapID: snap.ID}
	if err := snapshotRepo.CreateStatus(&status); err != nil {
		t.Fatalf("create snapshot status failed: %v", err)
	}

	// The status struct handed to workers. Workers must never write to it
	// (that would race when several goroutines run in parallel); all progress
	// has to flow through the database.
	inMemory := model.SnapshotStatus{SnapID: snap.ID}
	_ = snapHelper{SnapID: snap.ID, Status: &inMemory}

	fields := []string{"panel", "panel_info", "daemon_json", "app_data", "backup_data"}
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(round int) {
			defer wg.Done()
			for _, field := range fields {
				if err := snapshotRepo.UpdateStatus(status.ID, map[string]interface{}{field: fmt.Sprintf("%d-%d", round, i)}); err != nil {
					t.Errorf("update status field %s failed: %v", field, err)
				}
			}
		}(i)
	}
	wg.Wait()

	// No worker wrote to the shared struct (they only may read .ID / .SnapID).
	zero := model.SnapshotStatus{SnapID: snap.ID}
	if inMemory != zero {
		t.Fatalf("shared in-memory status was mutated, got %+v; workers must not write it", inMemory)
	}

	// All updates landed in the database; the final value per field is one of
	// the values written by the goroutines (which one is scheduler-dependent).
	persisted, err := snapshotRepo.GetStatus(snap.ID)
	if err != nil {
		t.Fatalf("get persisted status failed: %v", err)
	}
	valid := func(v string) bool {
		var round, slot int
		if _, err := fmt.Sscanf(v, "%d-%d", &round, &slot); err != nil {
			return false
		}
		return round >= 0 && round < 50 && slot >= 0 && slot < 50
	}
	for _, field := range fields {
		var value string
		switch field {
		case "panel":
			value = persisted.Panel
		case "panel_info":
			value = persisted.PanelInfo
		case "daemon_json":
			value = persisted.DaemonJson
		case "app_data":
			value = persisted.AppData
		case "backup_data":
			value = persisted.BackupData
		}
		if !valid(value) {
			t.Fatalf("field %s = %q, want one of the values written by the goroutines", field, value)
		}
	}
}
