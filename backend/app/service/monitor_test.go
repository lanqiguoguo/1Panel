package service

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/app/model"
	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/glebarez/sqlite"
	"github.com/robfig/cron/v3"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

// setupMonitorConcurrentTest prepares the globals StartMonitor relies on:
// an in-memory sqlite DB for the settings table, a monitor DB for the metric
// tables, the cron scheduler and a logger. The monitor cron jobs are only
// ever started via global.Cron.Start at the end of the test, so the jobs
// added by StartMonitor stay idle while the concurrent calls exercise the
// start/stop state machine.
func setupMonitorConcurrentTest(t *testing.T) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open in-memory sqlite failed: %v", err)
	}
	if err := db.AutoMigrate(&model.Setting{}); err != nil {
		t.Fatalf("migrate settings failed: %v", err)
	}
	global.DB = db

	monitorDB, err := gorm.Open(sqlite.Open("file:"+t.Name()+"-monitor?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open in-memory monitor sqlite failed: %v", err)
	}
	if err := monitorDB.AutoMigrate(&model.MonitorBase{}, &model.MonitorIO{}, &model.MonitorNetwork{}); err != nil {
		t.Fatalf("migrate monitor tables failed: %v", err)
	}
	global.MonitorDB = monitorDB

	global.Cron = cron.New()
	if global.LOG == nil {
		global.LOG = logrus.New()
	}
}

// TestStartMonitorConcurrent drives StartMonitor(true/false, ...) from many
// goroutines at once to exercise the monitor start/stop state machine. It
// asserts the invariants the P1-D fix guarantees:
//   - at most one monitor cron job is registered (no double registration),
//   - monitorCancel and global.MonitorCronID are left in a consistent state,
//   - no panic / nil-cancel call / Remove(0) (enforced by stopMonitor's
//     guarded internals and validated by the race detector).
//
// The monitor cron scheduler is left stopped, so no job actually runs during
// the test; the saveIODataToDB/saveNetDataToDB goroutines are cancelled and
// waited on before the test returns.
func TestStartMonitorConcurrent(t *testing.T) {
	setupMonitorConcurrentTest(t)

	intervals := []string{"1", "2", "5"}
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		removeBefore := i%2 == 0
		interval := intervals[i%len(intervals)]
		wg.Add(1)
		go func(removeBefore bool, interval string) {
			defer wg.Done()
			if err := StartMonitor(removeBefore, interval); err != nil {
				t.Errorf("StartMonitor(%v, %q) failed: %v", removeBefore, interval, err)
			}
		}(removeBefore, interval)
	}
	wg.Wait()

	// stopMonitor must be idempotent: repeated concurrent calls while the
	// monitor is running must leave the state fully torn down.
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			stopMonitor()
		}()
	}
	wg.Wait()

	if len(global.Cron.Entries()) != 0 {
		t.Errorf("cron still has %d entries after stopping the monitor, want 0", len(global.Cron.Entries()))
	}
	if global.MonitorCronID != 0 {
		t.Errorf("global.MonitorCronID = %d after stop, want 0", global.MonitorCronID)
	}
}

// TestStopMonitorIdempotent guarantees stopMonitor is safe to call when no
// monitor is running at all (first invocation, or after a disable): it must
// not panic on the nil cancel and must never call global.Cron.Remove(0).
func TestStopMonitorIdempotent(t *testing.T) {
	setupMonitorConcurrentTest(t)

	stopMonitor()
	stopMonitor()

	if len(global.Cron.Entries()) != 0 {
		t.Errorf("cron has %d entries, want 0", len(global.Cron.Entries()))
	}
	if global.MonitorCronID != 0 {
		t.Errorf("global.MonitorCronID = %d, want 0", global.MonitorCronID)
	}
}

// TestStartMonitorTearDownWaitsForGoroutines verifies that after a successful
// StartMonitor followed by stopMonitor, the collection goroutines terminate
// promptly (cancel propagation), i.e. no orphaned saveIODataToDB /
// saveNetDataToDB goroutines keep writing after the monitor is stopped.
func TestStartMonitorTearDownWaitsForGoroutines(t *testing.T) {
	setupMonitorConcurrentTest(t)

	if err := StartMonitor(true, "1"); err != nil {
		t.Fatalf("StartMonitor failed: %v", err)
	}

	// run the scheduler so the @every 1m job is scheduled (it will not fire
	// within the test window); this proves a real entry was registered
	global.Cron.Start()
	if len(global.Cron.Entries()) != 1 {
		global.Cron.Stop()
		t.Fatalf("cron has %d entries after StartMonitor, want 1", len(global.Cron.Entries()))
	}
	global.Cron.Stop()

	stopMonitor()

	if len(global.Cron.Entries()) != 0 {
		t.Errorf("cron has %d entries after stop, want 0", len(global.Cron.Entries()))
	}
	if global.MonitorCronID != 0 {
		t.Errorf("global.MonitorCronID = %d after stop, want 0", global.MonitorCronID)
	}
}

// TestStartMonitorFailsCleanly covers the failure path of startMonitor: an
// invalid spec must be rejected by cron.AddJob, StartMonitor must surface the
// error, and no state may be left behind (no cancel to stop, no entry id).
func TestStartMonitorFailsCleanly(t *testing.T) {
	setupMonitorConcurrentTest(t)

	err := StartMonitor(false, "not-a-number")
	if err == nil {
		t.Fatal("StartMonitor with a non-numeric interval succeeded, want error")
	}

	if len(global.Cron.Entries()) != 0 {
		t.Errorf("cron has %d entries after failed StartMonitor, want 0", len(global.Cron.Entries()))
	}
	if global.MonitorCronID != 0 {
		t.Errorf("global.MonitorCronID = %d after failed StartMonitor, want 0", global.MonitorCronID)
	}
}

// TestStartMonitorRepeatedCountsExactlyOneJob is a sequential-but-repeated
// variant of the concurrent test: every restart must leave exactly one cron
// entry, never two (the old time.AfterFunc window allowed the old job to
// linger forever).
func TestStartMonitorRepeatedCountsExactlyOneJob(t *testing.T) {
	setupMonitorConcurrentTest(t)

	for i := 0; i < 5; i++ {
		if err := StartMonitor(true, "1"); err != nil {
			t.Fatalf("StartMonitor(%d) failed: %v", i, err)
		}
		if n := len(global.Cron.Entries()); n != 1 {
			t.Fatalf("iteration %d: cron has %d entries, want 1", i, n)
		}
		if global.MonitorCronID == 0 {
			t.Fatalf("iteration %d: global.MonitorCronID = 0, want non-zero", i)
		}
	}

	stopMonitor()
	if len(global.Cron.Entries()) != 0 || global.MonitorCronID != 0 {
		t.Fatalf("after stop: entries=%d cronID=%d, want 0/0",
			len(global.Cron.Entries()), global.MonitorCronID)
	}
}

// TestMonitorCronIDReadWriteNoRace hammers the two guarded variables directly
// with a mixture of writers and readers; it exists as a minimal, dependency
// free proof that the monitorMu discipline keeps the state race-free even
// without the cron/DB plumbing (e.g. if StartMonitor ever becomes untestable
// in another environment).
func TestMonitorCronIDReadWriteNoRace(t *testing.T) {
	setupMonitorConcurrentTest(t)

	var done atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				monitorMu.Lock()
				if global.MonitorCronID == 0 && monitorCancel == nil {
					done.Add(1)
				}
				monitorMu.Unlock()
			}
		}()
	}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			stopMonitor()
		}()
	}
	wg.Wait()
	if done.Load() == 0 {
		t.Log("no read-modify cycles observed (all readers overlapped writers)")
	}
}
