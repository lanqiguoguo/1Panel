package service

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// TestDaemonJsonWritersSerialized verifies daemonJsonMu serializes the
// read-modify-write critical section shared by all five daemon.json writers
// (UpdateConf / UpdateLogOption / UpdateIpv6Option / UpdateConfByFile /
// applyDaemonJsonProxies). The real functions cannot run here because they end
// in restartDocker (systemctl, unavailable in the test environment), so this
// test hammers the lock itself with the same "read file -> modify map -> write
// file" sequence those writers perform: under daemonJsonMu no update may be
// lost, i.e. the final file must hold every goroutine's complete result, and
// the whole run must be clean under -race.
func TestDaemonJsonWritersSerialized(t *testing.T) {
	file := filepath.Join(t.TempDir(), "daemon.json")
	raw, err := json.MarshalIndent(map[string]interface{}{"live-restore": false}, "", "\t")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, raw, 0640); err != nil {
		t.Fatal(err)
	}

	const iterations = 50
	var wg sync.WaitGroup
	write := func(key string, value interface{}) {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			daemonJsonMu.Lock()
			content, err := os.ReadFile(file)
			if err != nil {
				t.Errorf("read failed: %v", err)
				daemonJsonMu.Unlock()
				return
			}
			daemonMap := make(map[string]interface{})
			if err := json.Unmarshal(content, &daemonMap); err != nil {
				t.Errorf("parse failed: %v", err)
				daemonJsonMu.Unlock()
				return
			}
			daemonMap[key] = value
			out, err := json.MarshalIndent(daemonMap, "", "\t")
			if err != nil {
				t.Errorf("marshal failed: %v", err)
				daemonJsonMu.Unlock()
				return
			}
			if err := os.WriteFile(file, out, 0640); err != nil {
				t.Errorf("write failed: %v", err)
				daemonJsonMu.Unlock()
				return
			}
			daemonJsonMu.Unlock()
		}
	}

	wg.Add(2)
	go write("registry-mirrors", []string{"https://mirror-a.example.com"})
	go write("insecure-registries", []string{"10.0.0.5:5000"})
	wg.Wait()

	content, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]interface{}
	if err := json.Unmarshal(content, &got); err != nil {
		t.Fatalf("final daemon.json is not valid JSON: %v\n%s", err, content)
	}
	// With serialization every writer's change lands; a missing key means a
	// read-modify-write pair interleaved with the other writer (lost update).
	if want := []interface{}{"https://mirror-a.example.com"}; !jsonEqual(got["registry-mirrors"], want) {
		t.Errorf("registry-mirrors = %v, want %v (lost update under contention)", got["registry-mirrors"], want)
	}
	if want := []interface{}{"10.0.0.5:5000"}; !jsonEqual(got["insecure-registries"], want) {
		t.Errorf("insecure-registries = %v, want %v (lost update under contention)", got["insecure-registries"], want)
	}
}
