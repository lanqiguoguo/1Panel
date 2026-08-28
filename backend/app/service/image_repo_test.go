package service

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/app/model"
	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/glebarez/sqlite"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

// seedDaemonJson writes an initial daemon.json to a temp file.
func seedDaemonJson(t *testing.T, values map[string]interface{}) string {
	t.Helper()
	file := filepath.Join(t.TempDir(), "daemon.json")
	raw, err := json.MarshalIndent(values, "", "\t")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, raw, 0640); err != nil {
		t.Fatal(err)
	}
	return file
}

func readDaemonJson(t *testing.T, file string) map[string]interface{} {
	t.Helper()
	content, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("read daemon.json failed: %v", err)
	}
	got := make(map[string]interface{})
	if err := json.Unmarshal(content, &got); err != nil {
		t.Fatalf("daemon.json is not valid JSON: %v\n%s", err, content)
	}
	return got
}

// TestApplyRegistriesChangeLockedLifecycle is the regression test for the
// incomplete critical section on the create/update path: the daemon.json
// read-modify-write was serialized by daemonJsonMu, but validateDockerConfig
// and restartDocker ran outside the lock, so another writer could interleave
// between our write and our restart and have its changes validated/applied
// (or ours silently raced). The whole lifecycle must run inside one critical
// section, in write -> validate -> restart -> wait order.
func TestApplyRegistriesChangeLockedLifecycle(t *testing.T) {
	file := seedDaemonJson(t, map[string]interface{}{"live-restore": false})

	var calls []string
	validateContent := make(chan []byte, 1)
	origValidate, origRestart, origWait := validateDockerConfigFn, restartDockerFn, waitForDockerActiveFn
	validateDockerConfigFn = func() error {
		if daemonJsonMu.TryLock() {
			daemonJsonMu.Unlock()
			t.Error("validateDockerConfig ran without daemonJsonMu held")
		}
		content, err := os.ReadFile(file)
		if err != nil {
			t.Errorf("validate could not read daemon.json: %v", err)
		}
		select {
		case validateContent <- content:
		default:
		}
		calls = append(calls, "validate")
		return nil
	}
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
	t.Cleanup(func() {
		validateDockerConfigFn, restartDockerFn, waitForDockerActiveFn = origValidate, origRestart, origWait
	})

	if err := (&ImageRepoService{}).applyRegistriesChange(file, "10.0.0.5:5000", "", "create"); err != nil {
		t.Fatalf("applyRegistriesChange failed: %v", err)
	}

	if len(calls) != 3 || calls[0] != "validate" || calls[1] != "restart" || calls[2] != "wait" {
		t.Fatalf("lifecycle order = %v, want validate -> restart -> wait", calls)
	}
	// the validation must observe the already-written registry, not the
	// pre-change content
	seen := <-validateContent
	if !strings.Contains(string(seen), "10.0.0.5:5000") {
		t.Errorf("validateDockerConfig ran before the registry was written, observed: %s", seen)
	}

	got := readDaemonJson(t, file)
	if want := []interface{}{"10.0.0.5:5000"}; !jsonEqual(got["insecure-registries"], want) {
		t.Errorf("insecure-registries = %v, want %v", got["insecure-registries"], want)
	}
	if got["live-restore"] != false {
		t.Errorf("live-restore = %v, want the untouched existing key preserved", got["live-restore"])
	}
}

// TestRemoveInsecureRegistryDeletePath covers the Delete path: the row is
// removed inside the critical section and a failed restart must not fail the
// already-committed deletion, but it must be logged instead of swallowed.
func TestRemoveInsecureRegistryDeletePath(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open in-memory sqlite failed: %v", err)
	}
	if err := db.AutoMigrate(&model.ImageRepo{}); err != nil {
		t.Fatalf("migrate image_repos failed: %v", err)
	}
	global.DB = db
	row := &model.ImageRepo{Name: "reg", DownloadUrl: "reg.local:5000", Protocol: "http"}
	if err := imageRepoRepo.Create(row); err != nil {
		t.Fatalf("seed image repo failed: %v", err)
	}

	file := seedDaemonJson(t, map[string]interface{}{
		"insecure-registries": []interface{}{"reg.local:5000"},
	})

	var calls []string
	origValidate, origRestart, origWait := validateDockerConfigFn, restartDockerFn, waitForDockerActiveFn
	validateDockerConfigFn = func() error {
		if daemonJsonMu.TryLock() {
			daemonJsonMu.Unlock()
			t.Error("validateDockerConfig ran without daemonJsonMu held")
		}
		calls = append(calls, "validate")
		return nil
	}
	restartDockerFn = func() error {
		if daemonJsonMu.TryLock() {
			daemonJsonMu.Unlock()
			t.Error("restartDocker ran without daemonJsonMu held")
		}
		calls = append(calls, "restart")
		return gorm.ErrInvalidDB // any restart failure
	}
	waitForDockerActiveFn = func() error {
		calls = append(calls, "wait")
		return nil
	}
	t.Cleanup(func() {
		validateDockerConfigFn, restartDockerFn, waitForDockerActiveFn = origValidate, origRestart, origWait
	})

	capture := &captureLogWriter{}
	logger := logrus.New()
	logger.SetOutput(capture)
	logger.SetLevel(logrus.DebugLevel)
	global.LOG = logger

	if err := (&ImageRepoService{}).removeInsecureRegistry(file, "reg.local:5000", row.ID); err != nil {
		t.Fatalf("removeInsecureRegistry failed: %v (a failed restart must not fail the committed deletion)", err)
	}

	if len(calls) != 2 || calls[0] != "validate" || calls[1] != "restart" {
		t.Fatalf("lifecycle order = %v, want validate -> restart (no wait on the delete path)", calls)
	}
	got := readDaemonJson(t, file)
	if _, exists := got["insecure-registries"]; exists {
		t.Errorf("insecure-registries = %v, want the key removed", got["insecure-registries"])
	}
	var remaining int64
	if err := db.Model(&model.ImageRepo{}).Count(&remaining).Error; err != nil {
		t.Fatalf("count image repos failed: %v", err)
	}
	if remaining != 0 {
		t.Fatalf("%d image repo rows remain, want the row deleted", remaining)
	}
	if !strings.Contains(capture.buf.String(), "restart docker after deleting insecure registry reg.local:5000 failed") {
		t.Errorf("failed restart was not logged, log output: %q", capture.buf.String())
	}
}

// TestApplyRegistriesChangeSerializes hammers the registries change paths
// concurrently: under daemonJsonMu no update may be lost, i.e. the final
// daemon.json must hold every goroutine's registry.
func TestApplyRegistriesChangeSerializes(t *testing.T) {
	file := seedDaemonJson(t, map[string]interface{}{})

	var (
		mu    sync.Mutex
		calls []string
	)
	origValidate, origRestart, origWait := validateDockerConfigFn, restartDockerFn, waitForDockerActiveFn
	validateDockerConfigFn = func() error {
		if daemonJsonMu.TryLock() {
			daemonJsonMu.Unlock()
			t.Error("validateDockerConfig ran without daemonJsonMu held")
		}
		mu.Lock()
		calls = append(calls, "validate")
		mu.Unlock()
		return nil
	}
	restartDockerFn = func() error {
		mu.Lock()
		calls = append(calls, "restart")
		mu.Unlock()
		return nil
	}
	waitForDockerActiveFn = func() error {
		mu.Lock()
		calls = append(calls, "wait")
		mu.Unlock()
		return nil
	}
	t.Cleanup(func() {
		validateDockerConfigFn, restartDockerFn, waitForDockerActiveFn = origValidate, origRestart, origWait
	})

	const iterations = 30
	var wg sync.WaitGroup
	apply := func(host string) {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			if err := (&ImageRepoService{}).applyRegistriesChange(file, host, "", "create"); err != nil {
				t.Errorf("applyRegistriesChange(%s) failed: %v", host, err)
				return
			}
		}
	}
	wg.Add(2)
	go apply("10.0.0.5:5000")
	go apply("10.0.0.6:5000")
	wg.Wait()

	got := readDaemonJson(t, file)
	// The locked write path only collapses consecutive duplicates
	// (common.RemoveRepeatElement), so the final list may interleave hosts;
	// what must never happen is a lost update: every entry must be one of the
	// two writers' hosts and both must be present at the end.
	registries, _ := got["insecure-registries"].([]interface{})
	seen := make(map[string]bool, 2)
	for _, r := range registries {
		s, _ := r.(string)
		if s != "10.0.0.5:5000" && s != "10.0.0.6:5000" {
			t.Errorf("unexpected registry %q in final list %v", s, registries)
		}
		seen[s] = true
	}
	if !seen["10.0.0.5:5000"] || !seen["10.0.0.6:5000"] {
		t.Errorf("insecure-registries = %v, want both concurrent writers preserved (lost update)", registries)
	}
}

func TestCreateIfNotExistDaemonJsonFileSeedsEmptyObject(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "sub", "daemon.json")
	if err := createIfNotExistDaemonJsonFile(filePath); err != nil {
		t.Fatalf("create failed: %v", err)
	}
	content, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("read back failed: %v", err)
	}
	if strings.TrimSpace(string(content)) != "{}" {
		t.Fatalf("fresh daemon.json must be seeded with {}, got %q", string(content))
	}
	var daemonMap map[string]interface{}
	if err := json.Unmarshal(content, &daemonMap); err != nil {
		t.Fatalf("fresh daemon.json must unmarshal: %v", err)
	}
	if err := createIfNotExistDaemonJsonFile(filePath); err != nil {
		t.Fatalf("second call must not rewrite: %v", err)
	}
	content2, _ := os.ReadFile(filePath)
	if string(content) != string(content2) {
		t.Fatalf("second call overwrote existing file")
	}
}

func TestCreateIfNotExistDaemonJsonFileReseedsZeroByteFile(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "daemon.json")
	if err := os.WriteFile(filePath, nil, 0644); err != nil {
		t.Fatalf("seed empty file failed: %v", err)
	}
	if err := createIfNotExistDaemonJsonFile(filePath); err != nil {
		t.Fatalf("call failed: %v", err)
	}
	content, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("read back failed: %v", err)
	}
	var daemonMap map[string]interface{}
	if err := json.Unmarshal(content, &daemonMap); err != nil {
		t.Fatalf("zero-byte daemon.json must be reseeded to unmarshalable JSON: %v (content %q)", err, string(content))
	}
}
