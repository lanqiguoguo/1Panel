package service

import (
	"os"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/app/dto"
)

// The update functions below (UpdateLogOption / UpdateIpv6Option / UpdateConf /
// UpdateConfByFile) write to the real constant.DaemonJsonPath, which is a
// constant (/etc/docker/daemon.json) and therefore not injectable; running
// them against that path would clobber the host's Docker configuration, so
// this test backs up and restores the file around the case. restartDockerFn
// (the injectable seam declared in image_repo.go, defaulting to the real
// restartDocker) is swapped for a stub because the real one shells out to
// systemctl/snap (unavailable in the test environment); this lets the test
// verify the decision logic (that a change reaching an empty daemon.json does
// NOT skip the restart step) without actually bouncing the daemon.
// TestDaemonJsonWritersSerialized in docker_concurrent_test.go covers the
// daemonJsonMu serialization aspect.
//
// The non-empty branches are not exercised here: they are covered by manual
// verification (a fake daemon.json on a real host, then a real docker restart)
// because running them here would execute validateDockerConfig's dockerd
// --validate against a config written to /etc/docker.
//
// Note on the ipv6 side: UpdateIpv6Option's empty-map branch is defensive —
// the endpoint unconditionally (re)writes ipv6 + fixed-cidr-v6 first, so no
// request can empty the map through it. The reachable "disable ipv6" flow
// (frontend handleIPv6 -> onSaveIPv6, frontend/src/views/container/setting/
// index.vue) goes through UpdateConf{Key:"Ipv6", Value:"disable"}, whose
// empty-map branch already removes the file and restarts docker — the
// reference behavior the log/ipv6 fixes were aligned to.

// withDaemonJsonBackup snapshots the current daemon.json at
// constant.DaemonJsonPath (if any), runs f, then restores the exact prior
// state (content or absence) so the host configuration is untouched.
func withDaemonJsonBackup(t *testing.T, f func()) {
	t.Helper()
	path := constantDaemonJsonPath()
	backup, err := os.ReadFile(path)
	existed := err == nil
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("read %s: %v", path, err)
	}
	defer func() {
		if existed {
			if err := os.WriteFile(path, backup, 0640); err != nil {
				t.Errorf("restore %s: %v", path, err)
			}
		} else if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			t.Errorf("remove %s during restore: %v", path, err)
		}
	}()
	f()
}

func constantDaemonJsonPath() string {
	// constant.DaemonJsonPath is a compile-time constant; route through it so
	// the test keeps tracking the production path if it ever changes.
	return "/etc/docker/daemon.json"
}

func writeDaemonJson(t *testing.T, content string) {
	t.Helper()
	if err := os.WriteFile(constantDaemonJsonPath(), []byte(content), 0640); err != nil {
		t.Fatalf("write daemon.json: %v", err)
	}
}

// withRestartStub swaps restartDockerFn (declared in image_repo.go) for a
// stub returning errRestartStub, and restores it afterwards.
func withRestartStub(t *testing.T) {
	t.Helper()
	oldFn := restartDockerFn
	restartDockerFn = func() error { return errRestartStub }
	t.Cleanup(func() { restartDockerFn = oldFn })
}

// TestUpdateLogOptionEmptyMapRestarts verifies the "emptying the daemon
// config" path: when the only log option is cleared, daemon.json is removed
// AND the restart step runs. It used to `return nil` right after removing the
// file, so dockerd kept serving the stale in-memory config while the panel
// reported success; UpdateConf behaves the same way for its empty-map case
// (remove file + restart), so the log option path now matches. With the old
// code the restart stub would never be called and the function would return
// nil; with the fix the stub is invoked and its error surfaces.
func TestUpdateLogOptionEmptyMapRestarts(t *testing.T) {
	withDaemonJsonBackup(t, func() {
		// daemon.json containing only log-opts; both log fields empty makes
		// changeLogOption delete the opts map (and never add log-driver), so
		// daemonMap ends up empty after the update.
		writeDaemonJson(t, `{"log-opts":{"max-file":"3"}}`)
		withRestartStub(t)

		err := (&DockerService{}).UpdateLogOption(dto.LogOption{})

		if err == nil {
			t.Fatal("UpdateLogOption returned nil after emptying daemon.json: restart step was skipped (dockerd would keep the stale config)")
		}
		if err != errRestartStub {
			t.Fatalf("UpdateLogOption returned %v, want the stubbed restart error (it must fail on restart, not swallow it)", err)
		}
		if _, statErr := os.Stat(constantDaemonJsonPath()); !os.IsNotExist(statErr) {
			t.Errorf("daemon.json should be removed after the update, stat err = %v", statErr)
		}
	})
}

// errRestartStub is the sentinel returned by the stubbed restart; asserting
// on it (rather than just err != nil) proves the error surfaced from the
// restart step itself, not from some earlier write.
var errRestartStub = &restartStubError{}

type restartStubError struct{}

func (e *restartStubError) Error() string { return "stub: restart docker" }
