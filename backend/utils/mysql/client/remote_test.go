package client

import (
	"os"
	"strings"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/1Panel-dev/1Panel/backend/utils/cmd"
)

// TestRemoteRunCommandArgvLeakFree is the regression test for the root
// password argv leak in remote Backup/Recover: the `docker run ... bash -c`
// command used to carry `-p<password>`, exposing the credential in the host
// bash argv, the docker run argv and the container-side mysqldump/mysql argv
// (all world-readable under /proc/<pid>/cmdline). The password must now travel
// only via MYSQL_PWD from a 0600 --env-file, and the network/stdin flags and
// client invocation shape must stay untouched.
func TestRemoteRunCommandArgvLeakFree(t *testing.T) {
	origTmp := global.CONF.System.TmpDir
	global.CONF.System.TmpDir = t.TempDir()
	defer func() { global.CONF.System.TmpDir = origTmp }()

	const password = "S3cr3t-P@ss"
	envFile, err := cmd.WriteDockerEnvFile(global.CONF.System.TmpDir, map[string]string{"MYSQL_PWD": password})
	if err != nil {
		t.Fatalf("WriteDockerEnvFile failed: %v", err)
	}

	cases := []struct {
		name      string
		clientBin string
		extraArgs string
		sslFlag   string
	}{
		{"backup-mysql", "mysqldump", "--routines", "--ssl-mode=DISABLED"},
		{"backup-mariadb", "mariadb-dump", "--routines", "--skip-ssl"},
		{"recover-mysql", "mysql", "", "--ssl-mode=DISABLED"},
		{"recover-mariadb", "mariadb", "", "--skip-ssl"},
	}
	for _, tc := range cases {
		cmdStr := remoteRunCommand(envFile, "mysql:8.2.0", tc.clientBin, tc.extraArgs, "10.0.0.5", 3306, "root", tc.sslFlag, "utf8mb4", "panel_db")
		if strings.Contains(cmdStr, password) {
			t.Fatalf("%s: password leaked into docker run command: %s", tc.name, cmdStr)
		}
		if !strings.Contains(cmdStr, "--env-file") {
			t.Fatalf("%s: docker run command has no --env-file: %s", tc.name, cmdStr)
		}
		// The container-side client invocation must not carry any -p option
		// (MYSQL_PWD replaces it for mysqldump and mysql alike); the check is
		// case-sensitive so the uppercase -P <port> flag is not a match.
		inner := cmdStr[strings.Index(cmdStr, "/bin/bash -c '")+len("/bin/bash -c '"):]
		for _, field := range strings.Fields(inner) {
			if strings.HasPrefix(field, "-p") {
				t.Fatalf("%s: inner client command still uses -p: %s", tc.name, inner)
			}
		}
		// Behavior invariants: network, stdin, host/port/user and charset
		// handling must be identical to the pre-fix invocation.
		for _, want := range []string{"docker run", "--rm", "--net=host", "-i", "/bin/bash -c", "-h 10.0.0.5", "-P 3306", "-uroot", "--default-character-set=utf8mb4 panel_db'"} {
			if !strings.Contains(cmdStr, want) {
				t.Fatalf("%s: docker run command missing %q: %s", tc.name, want, cmdStr)
			}
		}
	}

	// The env file itself must be 0600 and hold MYSQL_PWD, and must be
	// removable once the operation is done (callers defer os.Remove).
	info, err := os.Stat(envFile)
	if err != nil {
		t.Fatalf("stat env file: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("env file mode = %v, want 0600", info.Mode().Perm())
	}
	data, err := os.ReadFile(envFile)
	if err != nil {
		t.Fatalf("read env file: %v", err)
	}
	if !strings.Contains(string(data), "MYSQL_PWD="+password) {
		t.Fatalf("env file missing MYSQL_PWD: %q", string(data))
	}
	if err := os.Remove(envFile); err != nil {
		t.Fatalf("remove env file: %v", err)
	}
	if _, err := os.Stat(envFile); !os.IsNotExist(err) {
		t.Fatalf("env file still present after removal: %v", err)
	}
}
