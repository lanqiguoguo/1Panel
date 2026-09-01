package client

import (
	"os"
	"strings"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/utils/cmd"
)

// TestRemoteRunCommandArgvLeakFree is the regression test for the P2-1
// password leak in remote Backup/Recover: the `docker run ... bash -c` command
// used to carry `-e PGPASSWORD=<password>`, exposing the credential in the
// host bash argv, which is world-readable under /proc/<pid>/cmdline (0444).
// The password must now travel only via PGPASSWORD from a 0600 --env-file,
// and the docker run shape (flags, client invocation, redirect) must stay
// identical to the pre-fix one.
func TestRemoteRunCommandArgvLeakFree(t *testing.T) {
	const password = "S3cr3t-P@ss"
	dir := t.TempDir()
	envFile, err := cmd.WriteDockerEnvFile(dir, map[string]string{"PGPASSWORD": password})
	if err != nil {
		t.Fatalf("WriteDockerEnvFile failed: %v", err)
	}
	defer os.Remove(envFile)

	backupCmd := remoteBackupCommand(envFile, "postgres:16.1-alpine", "10.0.0.5", 5432, "postgres", "panel_db", "/var/backups/panel_db.sql")
	recoverCmd := remoteRecoverCommand(envFile, "postgres:16.1-alpine", "10.0.0.5", 5432, "postgres", "panel_db", "postgres", "/var/backups/panel_db.sql")
	for name, cmdStr := range map[string]string{"backup": backupCmd, "recover": recoverCmd} {
		if strings.Contains(cmdStr, password) {
			t.Fatalf("%s: password leaked into docker run command: %s", name, cmdStr)
		}
		if strings.Contains(cmdStr, "PGPASSWORD=") {
			t.Fatalf("%s: PGPASSWORD still interpolated into the command: %s", name, cmdStr)
		}
		// The password must only be referenced through the env file.
		if !strings.Contains(cmdStr, "--env-file") {
			t.Fatalf("%s: docker run command has no --env-file: %s", name, cmdStr)
		}
		if !strings.Contains(cmdStr, `--env-file "`+envFile+`"`) {
			t.Fatalf("%s: --env-file path not quoted with %%q: %s", name, cmdStr)
		}
		// Behavior invariants: flags and the container-side client invocation
		// must be identical to the pre-fix invocation.
		for _, want := range []string{
			"docker run", "--rm", "--net=host", "-i", "/bin/bash -c",
		} {
			if !strings.Contains(cmdStr, want) {
				t.Fatalf("%s: docker run command missing %q: %s", name, want, cmdStr)
			}
		}
	}
	for _, want := range []string{
		"pg_dump -h 10.0.0.5 -p 5432 --no-owner -Fc -U postgres panel_db",
		"' > " + shellquote("/var/backups/panel_db.sql"),
	} {
		if !strings.Contains(backupCmd, want) {
			t.Fatalf("backup command missing %q: %s", want, backupCmd)
		}
	}
	for _, want := range []string{
		"pg_restore -h 10.0.0.5 -p 5432 --verbose --clean --no-privileges --no-owner -Fc -U postgres -d panel_db --role=postgres",
		"' < " + shellquote("/var/backups/panel_db.sql"),
	} {
		if !strings.Contains(recoverCmd, want) {
			t.Fatalf("recover command missing %q: %s", want, recoverCmd)
		}
	}
}

// TestRemoteRunCommandSpecialCharPassword runs the exact Backup flow's env
// handling against a password full of shell metacharacters: the env file
// carries it verbatim (KEY=value, no quoting needed for docker's env-file
// parser) while the constructed command string must not contain it anywhere.
func TestRemoteRunCommandSpecialCharPassword(t *testing.T) {
	const password = `p@ss'w"d`
	dir := t.TempDir()
	envFile, err := cmd.WriteDockerEnvFile(dir, map[string]string{"PGPASSWORD": password})
	if err != nil {
		t.Fatalf("WriteDockerEnvFile failed: %v", err)
	}
	defer os.Remove(envFile)

	backupCmd := remoteBackupCommand(envFile, "postgres:16.1-alpine", "10.0.0.5", 5432, "postgres", "panel_db", "/var/backups/panel_db.sql")
	if strings.Contains(backupCmd, password) {
		t.Fatalf("special-char password leaked into backup command: %s", backupCmd)
	}
	// shellquote is no longer applied to the password, but it still guards the
	// redirect target; pin its escaping so the metacharacter handling stays.
	if got := shellquote(`p@ss'w"d`); got != `'p@ss'\''w"d'` {
		t.Errorf("shellquote(p@ss'w\"d) = %q, want 'p@ss'\\''w\"d'", got)
	}

	// The env file must be 0600 and hold the raw value: docker's env-file
	// format is KEY=value with no quoting, so the password must be written
	// verbatim on a single line and must still be removable afterwards.
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
	if string(data) != "PGPASSWORD="+password+"\n" {
		t.Fatalf("env file content = %q, want %q", string(data), "PGPASSWORD="+password+"\n")
	}
	if err := os.Remove(envFile); err != nil {
		t.Fatalf("remove env file: %v", err)
	}
	if _, err := os.Stat(envFile); !os.IsNotExist(err) {
		t.Fatalf("env file still present after removal: %v", err)
	}
}

// TestRemoteRunCommandNewlinePassword pins the newline handling of
// WriteDockerEnvFile as-is: values are written verbatim, so a password
// containing \n terminates the line early and docker would only read up to
// it. This matches the mysql/redis usage exactly (no extra reject/escape
// layer introduced for the pg fix); the assertion documents the behavior so
// a future hardening of WriteDockerEnvFile is a conscious change.
func TestRemoteRunCommandNewlinePassword(t *testing.T) {
	dir := t.TempDir()
	envFile, err := cmd.WriteDockerEnvFile(dir, map[string]string{"PGPASSWORD": "line1\nline2"})
	if err != nil {
		t.Fatalf("WriteDockerEnvFile failed: %v", err)
	}
	defer os.Remove(envFile)
	data, err := os.ReadFile(envFile)
	if err != nil {
		t.Fatalf("read env file: %v", err)
	}
	want := "PGPASSWORD=line1\nline2\n"
	if string(data) != want {
		t.Fatalf("env file content = %q, want %q", string(data), want)
	}
}
