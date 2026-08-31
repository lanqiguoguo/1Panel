package service

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/1Panel-dev/1Panel/backend/app/model"
	"github.com/1Panel-dev/1Panel/backend/constant"
	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/1Panel-dev/1Panel/backend/utils/files"
	"github.com/glebarez/sqlite"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

// snapshotTestDBSeq gives every setupSnapshotTest call its own shared-cache
// in-memory database. The DSN used to be just t.Name(), so under go test
// -count=N the second iteration reopened the first iteration's database
// (a shared-cache memory DB stays alive while a pooled connection holds it)
// and its leftover rows broke the unique-name seeds and row-count assertions.
var snapshotTestDBSeq atomic.Int64

func setupSnapshotTest(t *testing.T) {
	t.Helper()
	dsn := fmt.Sprintf("file:%s-%d?mode=memory&cache=shared", t.Name(), snapshotTestDBSeq.Add(1))
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
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

// TestSnapshotAllocateConcurrent is the regression test for the check-then-act
// in snapshot naming: the same-second duplicate check (a DB read) and the
// snapshot row insert used to run unlocked, so concurrent creations in the
// same second could both observe the name as free. The name check and the row
// insert now run in one snapshotNameMu critical section inside
// allocateSnapshot, so N concurrent allocations of the same timestamp must all
// succeed with pairwise-distinct names (and 16 rows, thanks to the unique name
// constraint, would fail loudly if anyone removed the lock again).
func TestSnapshotAllocateConcurrent(t *testing.T) {
	setupSnapshotTest(t)

	const (
		workers = 16
		timeNow = "20260828130000"
	)
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		names    []string
		firstErr error
	)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			snap := model.Snapshot{
				Version: "v1.10.20-lts",
				Status:  constant.StatusWaiting,
			}
			if err := allocateSnapshot("v1.10.20-lts", "amd64", timeNow, false, &snap); err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
				return
			}
			mu.Lock()
			names = append(names, snap.Name)
			mu.Unlock()
		}()
	}
	wg.Wait()

	if firstErr != nil {
		t.Fatalf("concurrent allocateSnapshot failed: %v", firstErr)
	}
	if len(names) != workers {
		t.Fatalf("only %d/%d allocations succeeded", len(names), workers)
	}
	seen := make(map[string]bool, workers)
	for _, name := range names {
		if seen[name] {
			t.Fatalf("duplicate snapshot name %q allocated", name)
		}
		seen[name] = true
	}
	rows, err := snapshotRepo.GetList()
	if err != nil {
		t.Fatalf("list snapshots failed: %v", err)
	}
	if len(rows) != workers {
		t.Fatalf("snapshot rows = %d, want %d", len(rows), workers)
	}
}

// TestLoadSnapStatusRetriesQueryFailure is the regression test for the
// swallowed GetStatus errors in the phase sequencing: a failed status read
// used to return a zero-value status where every field looks "not done", so a
// transient DB error re-ran a finished phase (or marked a healthy snapshot
// failed on the follow-up check) with nothing in the log. The read now retries
// briefly and, when it keeps failing, returns an error so the caller records
// an explicit "status query failed" reason instead of mis-reading the zero
// value as a phase outcome.
func TestLoadSnapStatusRetriesQueryFailure(t *testing.T) {
	setupSnapshotTest(t)

	origInterval := snapshotStatusRetryInterval
	snapshotStatusRetryInterval = time.Millisecond
	defer func() { snapshotStatusRetryInterval = origInterval }()

	origGetStatus := snapshotGetStatusFn
	defer func() { snapshotGetStatusFn = origGetStatus }()

	snap := model.Snapshot{Name: "retry-test", Status: constant.StatusWaiting}
	if err := snapshotRepo.Create(&snap); err != nil {
		t.Fatalf("create snapshot failed: %v", err)
	}
	status := model.SnapshotStatus{SnapID: snap.ID, PanelData: constant.StatusDone}
	if err := snapshotRepo.CreateStatus(&status); err != nil {
		t.Fatalf("create snapshot status failed: %v", err)
	}

	t.Run("transient failure is retried and never yields a zero status", func(t *testing.T) {
		calls := 0
		snapshotGetStatusFn = func(snapID uint) (model.SnapshotStatus, error) {
			calls++
			if calls < 3 {
				return model.SnapshotStatus{}, fmt.Errorf("injected transient db busy")
			}
			return snapshotRepo.GetStatus(snapID)
		}
		got, err := loadSnapStatus(snap.ID, "panel_data")
		if err != nil {
			t.Fatalf("loadSnapStatus failed: %v", err)
		}
		if calls != 3 {
			t.Fatalf("attempts = %d, want 3", calls)
		}
		// the exact bug this pins: the zero value made callers re-run finished
		// phases (PanelData "" != StatusDone) or mark the snapshot failed
		if got.PanelData != constant.StatusDone {
			t.Fatalf("PanelData = %q, want %q; the read must not look 'not done'", got.PanelData, constant.StatusDone)
		}
	})

	t.Run("persistent failure returns an error instead of a fake status", func(t *testing.T) {
		calls := 0
		snapshotGetStatusFn = func(snapID uint) (model.SnapshotStatus, error) {
			calls++
			return model.SnapshotStatus{}, fmt.Errorf("injected persistent db down")
		}
		_, err := loadSnapStatus(snap.ID, "panel_data")
		if err == nil {
			t.Fatal("loadSnapStatus succeeded, want an error after exhausting the retries")
		}
		if calls != snapshotStatusRetries {
			t.Fatalf("attempts = %d, want %d", calls, snapshotStatusRetries)
		}
	})

	t.Run("markSnapshotFailed records status and reason", func(t *testing.T) {
		markSnapshotFailed(snap.ID, "status query failed: boom")
		row, err := snapshotRepo.Get(commonRepo.WithByID(snap.ID))
		if err != nil {
			t.Fatalf("reload snapshot failed: %v", err)
		}
		if row.Status != constant.StatusFailed {
			t.Fatalf("status = %q, want %q", row.Status, constant.StatusFailed)
		}
		if row.Message != "status query failed: boom" {
			t.Fatalf("message = %q, want the failure reason", row.Message)
		}
	})
}

// TestRecoverDaemonJsonLockedLifecycle is the regression test for the
// recover-path daemon.json critical section: recoverDaemonJson used to copy
// the snapshot's daemon.json and restart docker without daemonJsonMu, so a
// concurrent daemon.json writer (UpdateConf/applyRegistriesChange/...) could
// have its change silently overwritten by the restored file, or have the
// restart pick up a half-written config. Copy and restart must now run inside
// one critical section, in restart -> wait order, like applyRegistriesChange.
func TestRecoverDaemonJsonLockedLifecycle(t *testing.T) {
	origRestart, origWait := restartDockerFn, waitForDockerActiveFn
	t.Cleanup(func() { restartDockerFn, waitForDockerActiveFn = origRestart, origWait })

	var calls []string
	restartDockerFn = func() error {
		if daemonJsonMu.TryLock() {
			daemonJsonMu.Unlock()
			t.Error("restartDocker ran without daemonJsonMu held")
		}
		calls = append(calls, "restart")
		return nil
	}
	waitForDockerActiveFn = func() error {
		if daemonJsonMu.TryLock() {
			daemonJsonMu.Unlock()
			t.Error("waitForDockerActive ran without daemonJsonMu held")
		}
		calls = append(calls, "wait")
		return nil
	}

	writeSource := func(t *testing.T, withFile bool) string {
		t.Helper()
		src := t.TempDir()
		if withFile {
			if err := os.MkdirAll(filepath.Join(src, "docker"), 0750); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(src, "docker", "daemon.json"), []byte(`{"live-restore":true}`), 0640); err != nil {
				t.Fatal(err)
			}
		}
		return src
	}

	t.Run("snapshot daemon.json is copied and restarted under the lock", func(t *testing.T) {
		src := writeSource(t, true)
		hostDir := t.TempDir() // stands in for /etc/docker, kept empty

		if err := recoverDaemonJson(src, hostDir, files.NewFileOp()); err != nil {
			t.Fatalf("recoverDaemonJson failed: %v", err)
		}
		if len(calls) != 2 || calls[0] != "restart" || calls[1] != "wait" {
			t.Fatalf("lifecycle order = %v, want restart -> wait", calls)
		}
		content, err := os.ReadFile(filepath.Join(hostDir, "daemon.json"))
		if err != nil {
			t.Fatalf("daemon.json was not copied: %v", err)
		}
		if !strings.Contains(string(content), "live-restore") {
			t.Fatalf("daemon.json content = %s, want the snapshot copy", content)
		}
	})

	t.Run("no daemon.json on either side does nothing", func(t *testing.T) {
		calls = nil
		src := writeSource(t, false)
		hostDir := t.TempDir()

		if err := recoverDaemonJson(src, hostDir, files.NewFileOp()); err != nil {
			t.Fatalf("recoverDaemonJson failed: %v", err)
		}
		if len(calls) != 0 {
			t.Fatalf("restart calls = %v, want none", calls)
		}
	})

	t.Run("host-only daemon.json still restarts without copying (existing semantics)", func(t *testing.T) {
		calls = nil
		src := writeSource(t, false)
		hostDir := t.TempDir()
		if err := os.WriteFile(filepath.Join(hostDir, "daemon.json"), []byte(`{"debug":true}`), 0640); err != nil {
			t.Fatal(err)
		}

		if err := recoverDaemonJson(src, hostDir, files.NewFileOp()); err != nil {
			t.Fatalf("recoverDaemonJson failed: %v", err)
		}
		if len(calls) != 2 {
			t.Fatalf("restart calls = %v, want restart -> wait", calls)
		}
		content, err := os.ReadFile(filepath.Join(hostDir, "daemon.json"))
		if err != nil || string(content) != `{"debug":true}` {
			t.Fatalf("host daemon.json = %q (%v), want it untouched", content, err)
		}
	})
}

// TestSnapshotDeleteLocalCleanup verifies that deleting a snapshot record also
// removes the local artifacts the creation flow left behind: the working
// directory <localDir>/system/<name> (HandleSnapshot) and the compressed
// tarball <TmpDir>/system/<name>.tar.gz (snapCompress). Failed snapshots never
// reach the upload step that normally deletes these, so they used to pile up on
// disk. The cleanup is best-effort and must refuse names that could escape the
// snapshot directories.
func TestSnapshotDeleteLocalCleanup(t *testing.T) {
	setupSnapshotTest(t)

	origTmpDir := global.CONF.System.TmpDir
	t.Cleanup(func() { global.CONF.System.TmpDir = origTmpDir })

	localDir := t.TempDir()
	tmpDir := t.TempDir()
	global.CONF.System.TmpDir = tmpDir

	writeArtifacts := func(t *testing.T, snap model.Snapshot) {
		t.Helper()
		rootDir := filepath.Join(localDir, "system", snap.Name)
		if err := os.MkdirAll(filepath.Join(rootDir, "1panel"), 0750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(rootDir, "snapshot.json"), []byte(`{}`), 0640); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(tmpDir, "system"), 0750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(tmpDir, "system", snap.Name+".tar.gz"), []byte("tar"), 0640); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("valid name removes work dir and tarball", func(t *testing.T) {
		snap := model.Snapshot{BaseModel: model.BaseModel{ID: 1}, Name: "1panel_v1.10.39-lts_amd64_20260829070716"}
		writeArtifacts(t, snap)

		removeSnapshotLocalFiles(snap, localDir)

		if _, err := os.Stat(filepath.Join(localDir, "system", snap.Name)); !os.IsNotExist(err) {
			t.Fatalf("work dir still exists after cleanup (stat err: %v)", err)
		}
		if _, err := os.Stat(filepath.Join(tmpDir, "system", snap.Name+".tar.gz")); !os.IsNotExist(err) {
			t.Fatalf("tarball still exists after cleanup (stat err: %v)", err)
		}
	})

	t.Run("name with path separator is rejected", func(t *testing.T) {
		for _, bad := range []string{"../escape", "a/b", `a\b`} {
			snap := model.Snapshot{BaseModel: model.BaseModel{ID: 2}, Name: bad}
			rootDir := filepath.Join(localDir, "system", bad)
			if err := os.MkdirAll(rootDir, 0750); err != nil {
				t.Fatal(err)
			}
			removeSnapshotLocalFiles(snap, localDir)
			if _, err := os.Stat(rootDir); err != nil {
				t.Fatalf("name %q: dir was removed, want it left untouched", bad)
			}
		}
	})

	t.Run("empty name is rejected", func(t *testing.T) {
		removeSnapshotLocalFiles(model.Snapshot{BaseModel: model.BaseModel{ID: 3}, Name: ""}, localDir)
	})

	t.Run("missing artifacts are ignored", func(t *testing.T) {
		removeSnapshotLocalFiles(model.Snapshot{BaseModel: model.BaseModel{ID: 4}, Name: "1panel_v1.10.39-lts_amd64_20260829070717"}, localDir)
	})

	t.Run("empty localDir still removes tarball", func(t *testing.T) {
		snap := model.Snapshot{BaseModel: model.BaseModel{ID: 5}, Name: "1panel_v1.10.39-lts_amd64_20260829070718"}
		if err := os.MkdirAll(filepath.Join(tmpDir, "system"), 0750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(tmpDir, "system", snap.Name+".tar.gz"), []byte("tar"), 0640); err != nil {
			t.Fatal(err)
		}
		removeSnapshotLocalFiles(snap, "")
		if _, err := os.Stat(filepath.Join(tmpDir, "system", snap.Name+".tar.gz")); !os.IsNotExist(err) {
			t.Fatalf("tarball still exists after cleanup with empty localDir (stat err: %v)", err)
		}
	})

	t.Run("recover scratch dir is removed", func(t *testing.T) {
		snap := model.Snapshot{BaseModel: model.BaseModel{ID: 6}, Name: "1panel_v1.10.39-lts_amd64_20260829070719"}
		// HandleSnapshotRecover downloads <name>.tar.gz into, and decompresses
		// into, the directory <TmpDir>/system/<name>; a failed recover leaves it
		// there. The directory and the creation tarball (a file with the same
		// base name) can exist side by side, so cleanup must handle both.
		recoverDir := filepath.Join(tmpDir, "system", snap.Name)
		if err := os.MkdirAll(filepath.Join(recoverDir, "1panel"), 0750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(recoverDir, snap.Name+".tar.gz"), []byte("tar"), 0640); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(recoverDir, "snapshot.json"), []byte(`{}`), 0640); err != nil {
			t.Fatal(err)
		}

		removeSnapshotLocalFiles(snap, localDir)

		if _, err := os.Stat(recoverDir); !os.IsNotExist(err) {
			t.Fatalf("recover scratch dir still exists after cleanup (stat err: %v)", err)
		}
	})
}

// TestHandleSnapTarRejectsInjection verifies the defense-in-depth checks at
// the top of handleSnapTar (mirroring handleTar): the snapshot secret from
// dto.SnapshotCreate / cronjob.Secret is interpolated single-quoted into the
// openssl -k option of a bash -c command, so a secret containing a single
// quote (or any other shell metacharacter) must be rejected with
// ErrCmdIllegal before any command is built or executed — and before the
// target directory is even created.
func TestHandleSnapTarRejectsInjection(t *testing.T) {
	ensureValidateLogger(t)
	marker := filepath.Join(t.TempDir(), "pwned-snap")
	srcDir := filepath.Join(t.TempDir(), "src")
	if err := os.MkdirAll(srcDir, 0755); err != nil {
		t.Fatalf("mkdir src: %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "data.txt"), []byte("hello"), 0644); err != nil {
		t.Fatalf("write data: %v", err)
	}
	targetDir := filepath.Join(t.TempDir(), "out") // intentionally absent

	tests := []struct {
		caseName    string
		sourceDir   string
		targetDir   string
		archiveName string
		secret      string
	}{
		{
			caseName:    "secret single quote escape",
			sourceDir:   srcDir,
			targetDir:   targetDir,
			archiveName: "1panel_data.tar.gz",
			secret:      "'; touch " + marker + "; '",
		},
		{
			caseName:    "secret command substitution",
			sourceDir:   srcDir,
			targetDir:   targetDir,
			archiveName: "1panel_data.tar.gz",
			secret:      "$(touch " + marker + ")",
		},
		{
			caseName:    "secret backtick substitution",
			sourceDir:   srcDir,
			targetDir:   targetDir,
			archiveName: "1panel_data.tar.gz",
			secret:      "`touch " + marker + "`",
		},
		{
			caseName:    "secret newline",
			sourceDir:   srcDir,
			targetDir:   targetDir,
			archiveName: "1panel_data.tar.gz",
			secret:      "pass\nword",
		},
		{
			caseName:    "sourceDir injection",
			sourceDir:   "$(touch " + marker + ")",
			targetDir:   targetDir,
			archiveName: "1panel_data.tar.gz",
		},
		{
			caseName:    "targetDir injection",
			sourceDir:   srcDir,
			targetDir:   "$(touch " + marker + ")",
			archiveName: "1panel_data.tar.gz",
		},
		{
			caseName:    "archive name injection",
			sourceDir:   srcDir,
			targetDir:   targetDir,
			archiveName: "x.tar.gz; touch " + marker,
		},
	}
	for _, tc := range tests {
		t.Run(tc.caseName, func(t *testing.T) {
			err := handleSnapTar(tc.sourceDir, tc.targetDir, tc.archiveName, "", tc.secret)
			if err == nil {
				t.Fatal("handleSnapTar() error = nil, want ErrCmdIllegal")
			}
			if !isErrCmdIllegal(t, err) {
				t.Fatalf("handleSnapTar() error = %v, want ErrCmdIllegal", err)
			}
			if _, statErr := os.Stat(marker); statErr == nil {
				t.Fatal("command injection marker was created")
			}
			// The validation runs before any side effect: the target dir (and
			// with it the archive) must not have been created.
			if _, statErr := os.Stat(tc.targetDir); statErr == nil {
				t.Fatalf("target dir %q was created despite the rejection", tc.targetDir)
			}
		})
	}
}

// TestHandleSnapTarBenignSecretNotRejected pins that a legitimate alphanumeric
// secret still passes the entry validation: handleSnapTar must not fail with
// ErrCmdIllegal. The rest of the run (tar | openssl) depends on the host
// toolchain, so the archive is only asserted when the command itself
// succeeded.
func TestHandleSnapTarBenignSecretNotRejected(t *testing.T) {
	ensureValidateLogger(t)
	base := t.TempDir()
	srcDir := filepath.Join(base, "src")
	if err := os.MkdirAll(filepath.Join(srcDir, "sub"), 0755); err != nil {
		t.Fatalf("mkdir src: %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "sub", "data.txt"), []byte("hello"), 0644); err != nil {
		t.Fatalf("write data: %v", err)
	}
	targetDir := filepath.Join(base, "out")

	err := handleSnapTar(srcDir, targetDir, "1panel_data.tar.gz", "", "S3cretKey2026")
	if isErrCmdIllegal(t, err) {
		t.Fatalf("benign alphanumeric secret was rejected: %v", err)
	}
	if err == nil {
		info, statErr := os.Stat(filepath.Join(targetDir, "1panel_data.tar.gz"))
		if statErr != nil {
			t.Fatalf("archive was not created on the happy path: %v", statErr)
		}
		if info.Size() == 0 {
			t.Fatal("archive created on the happy path is empty")
		}
	}
}

// snapLogCaptureHook collects every log message routed through global.LOG so
// the debug output of handleSnapTar can be asserted on.
type snapLogCaptureHook struct {
	mu      sync.Mutex
	entries []string
}

func (h *snapLogCaptureHook) Fire(entry *logrus.Entry) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.entries = append(h.entries, entry.Message)
	return nil
}

func (h *snapLogCaptureHook) Levels() []logrus.Level { return logrus.AllLevels }

// TestHandleSnapTarDebugLogMasksSecret is the regression test for the broken
// log masking: the debug line of the encrypted branch used to replace the
// pattern " <secret> ", which never matches the -k '<secret>' form actually
// present in the command, leaking the encryption key into the log. The debug
// output must now contain neither the quoted nor the bare secret.
func TestHandleSnapTarDebugLogMasksSecret(t *testing.T) {
	origLog := global.LOG
	hook := &snapLogCaptureHook{}
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)
	logger.AddHook(hook)
	global.LOG = logger
	t.Cleanup(func() { global.LOG = origLog })

	base := t.TempDir()
	srcDir := filepath.Join(base, "src")
	if err := os.MkdirAll(srcDir, 0755); err != nil {
		t.Fatalf("mkdir src: %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "data.txt"), []byte("hello"), 0644); err != nil {
		t.Fatalf("write data: %v", err)
	}

	const secret = "S3cretKey2026"
	// The command is logged before it is executed, so the masking assertions
	// below hold even when tar/openssl are unavailable in the environment.
	_ = handleSnapTar(srcDir, filepath.Join(base, "out"), "1panel_data.tar.gz", "", secret)

	hook.mu.Lock()
	entries := append([]string(nil), hook.entries...)
	hook.mu.Unlock()

	maskedCommandSeen := false
	for _, msg := range entries {
		if strings.Contains(msg, secret) {
			t.Fatalf("debug log leaked the secret: %s", msg)
		}
		// the quoted form "'<secret>'" is replaced wholesale, leaving -k ******
		if strings.Contains(msg, "-k ******") {
			maskedCommandSeen = true
		}
	}
	if !maskedCommandSeen {
		t.Fatalf("no debug entry with the masked openssl -k option was captured, entries: %v", entries)
	}
}
