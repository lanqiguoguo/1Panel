package service

import (
	"strings"
	"sync/atomic"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/sirupsen/logrus"
)

// logCapture collects log messages emitted through global.LOG so tests can
// assert on the guard's skip and panic log entries.
type logCapture struct {
	messages chan string
}

func (c *logCapture) Levels() []logrus.Level {
	return []logrus.Level{logrus.InfoLevel, logrus.ErrorLevel}
}

func (c *logCapture) Fire(entry *logrus.Entry) error {
	select {
	case c.messages <- entry.Message:
	default:
	}
	return nil
}

func (c *logCapture) drain() []string {
	var msgs []string
	for {
		select {
		case m := <-c.messages:
			msgs = append(msgs, m)
		default:
			return msgs
		}
	}
}

func containsMessage(msgs []string, substr string) bool {
	for _, m := range msgs {
		if strings.Contains(m, substr) {
			return true
		}
	}
	return false
}

// swapLog installs a logger wired to the given capture and restores the
// previous global logger when the test finishes, mirroring the global.LOG
// setup in backup_size_test.go.
func swapLog(t *testing.T, capture *logCapture) {
	t.Helper()
	old := global.LOG
	logger := logrus.New()
	logger.AddHook(capture)
	global.LOG = logger
	t.Cleanup(func() { global.LOG = old })
}

// TestRunJobBodyOverlapGuard verifies the per-job running guard: while a body
// is still running, a second invocation of the same job is skipped with a log
// entry, other jobs are unaffected, the guard is released after completion and
// a later run of the same job executes again.
func TestRunJobBodyOverlapGuard(t *testing.T) {
	const (
		jobID   = 410001
		jobName = "overlap-guard-test"
	)
	capture := &logCapture{messages: make(chan string, 16)}
	swapLog(t, capture)
	t.Cleanup(func() { runningJobs.Delete(jobID) })

	var calls, otherCalls int32
	started := make(chan struct{})
	release := make(chan struct{})

	firstDone := make(chan struct{})
	go func() {
		defer close(firstDone)
		runJobBody(jobID, jobName, func() {
			atomic.AddInt32(&calls, 1)
			close(started)
			<-release
		})
	}()
	<-started // first body holds the guard from here on

	secondDone := make(chan struct{})
	go func() {
		defer close(secondDone)
		runJobBody(jobID, jobName, func() {
			atomic.AddInt32(&calls, 1)
			t.Error("second invocation of a running job must be skipped")
		})
	}()
	<-secondDone // returns immediately: the second run is skipped

	// A different job must not be blocked by the running guard of jobID.
	otherDone := make(chan struct{})
	go func() {
		defer close(otherDone)
		runJobBody(jobID+1, jobName+"-other", func() {
			atomic.AddInt32(&otherCalls, 1)
		})
	}()
	<-otherDone

	if got := atomic.LoadInt32(&otherCalls); got != 1 {
		t.Fatalf("unrelated job executed %d times, want 1", got)
	}

	close(release)
	<-firstDone

	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("overlapping runs of job %d executed %d times, want exactly 1", jobID, got)
	}
	if _, busy := runningJobs.Load(jobID); busy {
		t.Fatalf("running guard for job %d was not released after completion", jobID)
	}
	if msgs := capture.drain(); !containsMessage(msgs, "is still running, skip") {
		t.Fatalf("expected a skip log entry, got %v", msgs)
	}

	// The guard is free again, so a third invocation must execute.
	runJobBody(jobID, jobName, func() {
		atomic.AddInt32(&calls, 1)
	})
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("third invocation did not execute, calls = %d", got)
	}
}

// TestRunJobBodyRecoversPanic verifies that a panicking job body neither
// crashes the process nor leaves the running guard held, and that the panic is
// logged.
func TestRunJobBodyRecoversPanic(t *testing.T) {
	const (
		jobID   = 410002
		jobName = "panic-test"
	)
	capture := &logCapture{messages: make(chan string, 16)}
	swapLog(t, capture)
	t.Cleanup(func() { runningJobs.Delete(jobID) })

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic escaped runJobBody: %v", r)
		}
	}()

	runJobBody(jobID, jobName, func() {
		panic("boom: job body bug")
	})

	if _, busy := runningJobs.Load(jobID); busy {
		t.Fatalf("running guard for job %d was not released after a recovered panic", jobID)
	}
	msgs := capture.drain()
	if !containsMessage(msgs, "panic in job "+jobName) {
		t.Fatalf("expected the panic to be logged, got %v", msgs)
	}
}
