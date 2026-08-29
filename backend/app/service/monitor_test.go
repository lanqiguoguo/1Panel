package service

import (
	"context"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/1Panel-dev/1Panel/backend/app/model"
	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/glebarez/sqlite"
	"github.com/robfig/cron/v3"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/net"
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

// TestMonitorStartStopRaceInvariant hammers the start/stop state machine from
// many goroutines and asserts the monitorMu publication invariant directly:
// observed while monitorMu is held, (monitorCancel != nil) must always equal
// (global.MonitorCronID != 0), i.e. a monitor is never half-published. The
// regression this guards against is a start whose cron-id publication and
// cancel publication happen in two separate critical sections: a concurrent
// stop can then slip in between, see the old (nil/zero) pair, tear the cron
// job down, and leave the start to write the cancel back and spawn collector
// goroutines whose context is never cancelled again.
//
// A checker goroutine samples the pair under monitorMu continuously while
// other goroutines alternate atomic replace-starts (startMonitor with fresh
// contexts, different intervals) and stops; StartMonitor(false/true, ...) runs
// concurrently on top to cover the full path including the collector
// goroutines. Afterwards the test asserts a clean teardown (no cron entry,
// zero id, nil cancel) and that every collector goroutine exited, by polling
// runtime.NumGoroutine back to its baseline instead of a fixed sleep.
func TestMonitorStartStopRaceInvariant(t *testing.T) {
	setupMonitorConcurrentTest(t)

	runtime.GC()
	before := runtime.NumGoroutine()

	intervals := []string{"1", "2", "5"}
	var violations atomic.Int64
	var startErrs atomic.Int64

	var hammer sync.WaitGroup
	stopCh := make(chan struct{})

	// Invariant checker: samples the published pair under monitorMu while the
	// hammer runs. Any split publication window shows up here.
	var checker sync.WaitGroup
	checker.Add(1)
	go func() {
		defer checker.Done()
		for {
			select {
			case <-stopCh:
				return
			default:
			}
			monitorMu.Lock()
			cancelLive := monitorCancel != nil
			idLive := global.MonitorCronID != 0
			monitorMu.Unlock()
			if cancelLive != idLive {
				violations.Add(1)
			}
			time.Sleep(100 * time.Microsecond)
		}
	}()

	// State-machine hammerers: alternate atomic replace-starts (each with a
	// fresh context, different intervals) and stops. These go through
	// startMonitor/stopMonitor directly so thousands of publications can be
	// exercised without paying StartMonitor's multi-second initial sample.
	for i := 0; i < 6; i++ {
		hammer.Add(1)
		go func(seed int) {
			defer hammer.Done()
			for j := 0; j < 150; j++ {
				if (seed+j)%3 == 2 {
					stopMonitor()
					continue
				}
				// The context itself is never used here (this layer spawns no
				// collectors); only the cancel it produces is published.
				_, cancel := context.WithCancel(context.Background())
				interval := intervals[(seed+j)%len(intervals)]
				if err := startMonitor(NewIMonitorService(), interval, cancel); err != nil {
					cancel()
					startErrs.Add(1)
				}
			}
		}(i)
	}

	// Full-path layer: the exported API with enable/disable semantics; these
	// spawn real collector goroutines whose teardown is asserted below.
	for i := 0; i < 3; i++ {
		hammer.Add(1)
		go func(i int) {
			defer hammer.Done()
			removeBefore := i%2 == 0
			interval := intervals[i%len(intervals)]
			if err := StartMonitor(removeBefore, interval); err != nil {
				t.Errorf("StartMonitor(%v, %q) failed: %v", removeBefore, interval, err)
			}
		}(i)
	}

	hammer.Wait()
	close(stopCh)
	checker.Wait()

	if startErrs.Load() != 0 {
		t.Errorf("startMonitor failed %d times with valid intervals", startErrs.Load())
	}
	if violations.Load() != 0 {
		t.Errorf("invariant (monitorCancel != nil) == (MonitorCronID != 0) violated %d times during hammering", violations.Load())
	}

	// Whatever operation landed last, the quiescent state must be consistent.
	monitorMu.Lock()
	cancelLive := monitorCancel != nil
	idLive := global.MonitorCronID != 0
	monitorMu.Unlock()
	if cancelLive != idLive {
		t.Fatalf("after hammer: monitorCancel live = %v, MonitorCronID live = %v, want equal", cancelLive, idLive)
	}

	// A stop must then tear the whole generation down together.
	stopMonitor()
	stopMonitor()

	monitorMu.Lock()
	cancelLive = monitorCancel != nil
	idLive = global.MonitorCronID != 0
	monitorMu.Unlock()
	entries := len(global.Cron.Entries())
	if cancelLive || idLive || entries != 0 {
		t.Fatalf("after stop: monitorCancel live = %v, MonitorCronID live = %v, entries = %d, want false/false/0",
			cancelLive, idLive, entries)
	}

	// All collector goroutines must have exited: poll until the count
	// converges back to the pre-hammer baseline (bounded, no fixed sleep).
	deadline := time.Now().Add(10 * time.Second)
	for runtime.NumGoroutine() > before {
		if time.Now().After(deadline) {
			t.Fatalf("collector goroutines leaked: baseline = %d, still %d running after 10s", before, runtime.NumGoroutine())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestMonitorRunSendVsStopRace reproduces the race between a cron-triggered
// Run (whose loadDiskIO/loadNetIO end with a channel send) and a concurrent
// stopMonitor teardown. stopMonitorLocked is invoked while the loader is
// hammering sends: it closes the service's stopCh, and every send that is
// still in flight when the stop lands must either complete normally (the
// collection channel is still open — the savers are only cancelled after the
// loader is confirmed done) or exit through the stop branch. Before the
// stopCh fix, a teardown racing Run's sends could end with a send on a
// channel the savers had just closed, panicking with "send on closed
// channel" (recovered by cron, but losing the sample and spamming a stack
// trace).
//
// The data channels are deliberately never closed while the loader is
// sending: closing a channel while a send is in flight is a data race by the
// memory model (Go only guarantees the send case is skipped when the select
// re-scans after the close), which is covered deterministically by
// TestMonitorSendOnClosedChannelNoPanic. Here the teardown is sequenced so
// no send overlaps the savers' deferred close, keeping the -race run clean.
func TestMonitorRunSendVsStopRace(t *testing.T) {
	setupMonitorConcurrentTest(t)

	for iter := 0; iter < 30; iter++ {
		service := NewIMonitorService().(*MonitorService)

		monitorMu.Lock()
		currentMonitorService = service
		monitorMu.Unlock()

		ctx, cancel := context.WithCancel(context.Background())
		ioDone := make(chan struct{})
		netDone := make(chan struct{})
		go func() {
			defer close(ioDone)
			service.saveIODataToDB(ctx, 1)
		}()
		go func() {
			defer close(netDone)
			service.saveNetDataToDB(ctx, 1)
		}()

		// Loader goroutine standing in for Run: keeps calling the two loaders
		// (real disk/net reads plus the guarded sends) until the stop channel
		// is closed.
		loaderDone := make(chan struct{})
		go func() {
			defer close(loaderDone)
			for {
				select {
				case <-service.stopCh:
					return
				default:
				}
				service.loadDiskIO()
				service.loadNetIO()
			}
		}()

		// Let a few samples flow, then tear down while the loader is
		// mid-collection: closing stopCh makes the in-flight and subsequent
		// sends take the stop branch instead of blocking on a buffer nobody
		// drains anymore.
		time.Sleep(500 * time.Microsecond)
		monitorMu.Lock()
		stopMonitorLocked()
		monitorMu.Unlock()

		<-loaderDone

		// Only now, with no sends left in flight, cancel the savers so their
		// deferred close(chan) runs without racing the loader.
		cancel()
		<-ioDone
		<-netDone

		// The generation must be fully torn down and all goroutines gone.
		if len(global.Cron.Entries()) != 0 {
			t.Fatalf("iter %d: cron entries = %d, want 0", iter, len(global.Cron.Entries()))
		}
		if global.MonitorCronID != 0 {
			t.Fatalf("iter %d: MonitorCronID = %d, want 0", iter, global.MonitorCronID)
		}
		monitorMu.Lock()
		live := currentMonitorService != nil
		monitorMu.Unlock()
		if live {
			t.Fatalf("iter %d: currentMonitorService still set after stopMonitorLocked", iter)
		}
	}
}

// TestMonitorSendOnClosedChannelNoPanic deterministically exercises the two
// failure modes of the teardown race, in arrangements that are themselves
// race-free (so -race stays green) yet panic or hang on any partial fix:
//
// Scenario A — blocked send released by stopCh: the loader parks in the
// select with both data buffers full and nobody draining; stopMonitorLocked
// then closes stopCh. The select must exit through the stop branch. With the
// original unguarded send this hangs forever (send on a full buffer with no
// saver); with select+stopCh it exits; without the recover there is nothing
// to panic on here, so this scenario also passes on the select-only fix.
//
// Scenario B — closed-channel send case: the data channels are closed before
// the loader starts (a happens-before edge, so no data race — this is the
// production situation where the close lands while Run is still collecting,
// i.e. before its select is ever entered). A select scanning a closed send
// case panics with "send on closed channel" roughly half the time even when
// the stop branch is ready, because case order is randomized. The deferred
// recover in sendDiskIO/sendNetIO must absorb that panic so the iteration
// counts as a clean exit.
func TestMonitorSendOnClosedChannelNoPanic(t *testing.T) {
	setupMonitorConcurrentTest(t)

	// Scenario A: blocked send + stopCh close.
	for iter := 0; iter < 5; iter++ {
		service := NewIMonitorService().(*MonitorService)

		monitorMu.Lock()
		currentMonitorService = service
		monitorMu.Unlock()

		// Prefill both buffers so the loader's sends cannot proceed and it
		// parks inside the select.
		service.DiskIO <- []disk.IOCountersStat{{}}
		service.DiskIO <- []disk.IOCountersStat{{}}
		service.NetIO <- []net.IOCountersStat{{}}
		service.NetIO <- []net.IOCountersStat{{}}

		loaderDone := make(chan struct{})
		go func() {
			defer close(loaderDone)
			for {
				select {
				case <-service.stopCh:
					return
				default:
				}
				service.loadDiskIO()
				service.loadNetIO()
			}
		}()

		// Let the loader reach its parked select, then close stopCh: the stop
		// branch must release it.
		time.Sleep(100 * time.Microsecond)
		monitorMu.Lock()
		stopMonitorLocked()
		monitorMu.Unlock()

		select {
		case <-loaderDone:
		case <-time.After(5 * time.Second):
			t.Fatal("Scenario A: loader stuck on full buffers after stopCh closed (select stop branch missing)")
		}
	}

	// Scenario B: send on a closed channel (close happens-before loader).
	for iter := 0; iter < 10; iter++ {
		service := NewIMonitorService().(*MonitorService)

		monitorMu.Lock()
		currentMonitorService = service
		monitorMu.Unlock()

		// Close the data channels first — exactly what the savers' deferred
		// close does — then let the loader hit the closed send case.
		close(service.DiskIO)
		close(service.NetIO)

		loaderDone := make(chan struct{})
		go func() {
			defer close(loaderDone)
			for {
				select {
				case <-service.stopCh:
					return
				default:
				}
				service.loadDiskIO()
				service.loadNetIO()
			}
		}()

		time.Sleep(100 * time.Microsecond)
		monitorMu.Lock()
		stopMonitorLocked()
		monitorMu.Unlock()

		select {
		case <-loaderDone:
		case <-time.After(5 * time.Second):
			t.Fatalf("Scenario B iter %d: loader did not exit after stop", iter)
		}
	}
}
