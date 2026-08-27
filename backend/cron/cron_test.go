package cron

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/robfig/cron/v3"
)

// newProductionStyleCron builds a cron instance with the exact same job chain
// as production (jobWrappers), without touching global.Cron or any DB state.
func newProductionStyleCron() *cron.Cron {
	return cron.New(cron.WithChain(jobWrappers()...))
}

// fastSchedule fires at fixed sub-second intervals. It exists because
// "@every 50ms" and cron.Every are clamped up to 1 second by robfig/cron v3,
// which would make these tests too slow.
type fastSchedule time.Duration

func (d fastSchedule) Next(t time.Time) time.Time {
	return t.Add(time.Duration(d))
}

// waitFor polls cond until it returns true, failing the test on timeout.
func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("condition not met within %s", timeout)
}

// TestPanicRecoveryAndLiveness proves the Recover wrapper is active: a
// panicking job must not crash the test process, and the scheduler must keep
// firing a second job afterwards. Before the fix the two WithChain calls
// overwrote each other, so Recover was silently dropped and this panic would
// have terminated the whole process (and this test with it).
func TestPanicRecoveryAndLiveness(t *testing.T) {
	c := newProductionStyleCron()

	var panicked, other int32
	// The deferred counter runs while the panic unwinds, before the Recover
	// wrapper sees it, so it counts real firings of the panicking job.
	c.Schedule(fastSchedule(50*time.Millisecond), panicCounterJob{panicked: &panicked})
	c.Schedule(fastSchedule(50*time.Millisecond), cron.FuncJob(func() {
		atomic.AddInt32(&other, 1)
	}))

	c.Start()
	defer c.Stop()

	waitFor(t, time.Second, func() bool {
		return atomic.LoadInt32(&panicked) >= 2 && atomic.LoadInt32(&other) >= 2
	})
	if n := atomic.LoadInt32(&panicked); n < 2 {
		t.Fatalf("panicking job fired %d times, want >= 2", n)
	}
	if n := atomic.LoadInt32(&other); n < 2 {
		t.Fatalf("second job fired only %d times after panics, want >= 2", n)
	}
}

// panicCounterJob panics on every run while counting how often it fired.
type panicCounterJob struct {
	panicked *int32
}

func (j panicCounterJob) Run() {
	defer atomic.AddInt32(j.panicked, 1)
	panic("boom: must be absorbed by the Recover wrapper")
}

// TestDelayIfStillRunningSerializes proves the DelayIfStillRunning wrapper is
// active: a slow job fired on a fast schedule must never overlap with itself.
func TestDelayIfStillRunningSerializes(t *testing.T) {
	c := newProductionStyleCron()

	var (
		mu       sync.Mutex
		current  int32
		maxSeen  int32
		finished int32
	)
	// 300ms runtime on a 50ms schedule: every tick that arrives while a run is
	// still active must be skipped by DelayIfStillRunning.
	c.Schedule(fastSchedule(50*time.Millisecond), &slowJob{
		current:  &current,
		maxSeen:  &maxSeen,
		finished: &finished,
	})

	c.Start()
	defer c.Stop()

	// Two sequential runs need ~700ms (300ms each, second starts only after
	// the first finished); 1500ms leaves a comfortable margin.
	waitFor(t, 1500*time.Millisecond, func() bool {
		return atomic.LoadInt32(&finished) >= 2
	})

	mu.Lock()
	defer mu.Unlock()
	if n := atomic.LoadInt32(&finished); n < 2 {
		t.Fatalf("slow job ran %d times, want >= 2", n)
	}
	if maxSeen != 1 {
		t.Fatalf("job executions overlapped: max observed concurrency = %d, want 1", maxSeen)
	}
}

// slowJob tracks its own concurrency: how many Runs are active at once and how
// many have finished.
type slowJob struct {
	current  *int32
	maxSeen  *int32
	finished *int32
	mu       sync.Mutex
}

func (j *slowJob) Run() {
	cur := atomic.AddInt32(j.current, 1)
	j.mu.Lock()
	if cur > *j.maxSeen {
		*j.maxSeen = cur
	}
	j.mu.Unlock()
	time.Sleep(300 * time.Millisecond)
	atomic.AddInt32(j.current, -1)
	atomic.AddInt32(j.finished, 1)
}
