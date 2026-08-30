package client

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/global"
)

// TestExecWithEnvFileArgvLeakFree is the regression test for the password
// argv leak in mysql docker exec invocations: after building the command the
// full argv must not contain the password anywhere, and it must carry the
// --env-file path (whose file is 0600 and cleaned up by the returned
// cleanup function).
func TestExecWithEnvFileArgvLeakFree(t *testing.T) {
	global.CONF.System.TmpDir = t.TempDir()
	r := &Local{
		Type:          "mysql",
		PrefixCommand: []string{"exec", "mysql-ct", "mysql", "-uroot", "-e"},
		Password:      "S3cr3t-P@ss",
		ContainerName: "mysql-ct",
	}

	cmdItem, cleanup, err := r.execWithEnvFile(context.Background(), append([]string{"exec", "mysql-ct", "mysql", "-uroot", "-e"}, "select 1"))
	if err != nil {
		t.Fatalf("execWithEnvFile failed: %v", err)
	}
	defer cleanup()

	joined := strings.Join(cmdItem.Args, " ")
	if strings.Contains(joined, "S3cr3t-P@ss") {
		t.Fatalf("password leaked into docker exec argv: %s", joined)
	}
	if !strings.Contains(joined, "--env-file") {
		t.Fatalf("docker exec argv has no --env-file: %s", joined)
	}

	// The env file itself must be 0600 and hold MYSQL_PWD.
	envFile := ""
	for i, arg := range cmdItem.Args {
		if arg == "--env-file" && i+1 < len(cmdItem.Args) {
			envFile = cmdItem.Args[i+1]
		}
	}
	if envFile == "" {
		t.Fatal("no env file path in argv")
	}
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
	if !strings.Contains(string(data), "MYSQL_PWD=S3cr3t-P@ss") {
		t.Fatalf("env file missing MYSQL_PWD: %q", string(data))
	}

	cleanup()
	if _, err := os.Stat(envFile); !os.IsNotExist(err) {
		t.Fatalf("env file not removed by cleanup: %v", err)
	}
}

// TestExecWithEnvFileEmptyCommand guards the length check in execWithEnvFile.
func TestExecWithEnvFileEmptyCommand(t *testing.T) {
	global.CONF.System.TmpDir = t.TempDir()
	r := &Local{Password: "x"}
	if _, _, err := r.execWithEnvFile(context.Background(), nil); err == nil {
		t.Fatal("execWithEnvFile(nil) = nil error, want rejection")
	}
	if _, _, err := r.execWithEnvFile(context.Background(), []string{}); err == nil {
		t.Fatal("execWithEnvFile(empty) = nil error, want rejection")
	}
	// non-exec prefix (no "exec" word at index 0) still builds fine
	cmdItem, cleanup, err := r.execWithEnvFile(context.Background(), []string{"exec", "ct", "mysql", "-e", "select 1"})
	if err != nil {
		t.Fatalf("execWithEnvFile failed: %v", err)
	}
	defer cleanup()
	if len(cmdItem.Args) < 3 || cmdItem.Args[2] != "--env-file" {
		t.Fatalf("unexpected argv: %v", cmdItem.Args)
	}
}
