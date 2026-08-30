package service

import (
	"os"
	"strings"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/global"
)

// TestRedisExecArgvLeakFree is the regression test for the redis password
// argv leak: `redis-cli -a <password>` showed the credential in the
// world-readable process argv; the password must now travel through the
// REDISCLI_AUTH env var via a 0600 --env-file instead.
func TestRedisExecArgvLeakFree(t *testing.T) {
	origTmp := global.CONF.System.TmpDir
	global.CONF.System.TmpDir = t.TempDir()
	defer func() { global.CONF.System.TmpDir = origTmp }()

	commands := append(redisExec("redis-ct", "S3cr3t-P@ss"), "info")
	fullArgs, cleanup, err := redisExecEnvFile(commands, "S3cr3t-P@ss")
	if err != nil {
		t.Fatalf("redisExecEnvFile failed: %v", err)
	}
	defer cleanup()

	joined := strings.Join(fullArgs, " ")
	if strings.Contains(joined, "S3cr3t-P@ss") {
		t.Fatalf("redis password leaked into docker exec argv: %s", joined)
	}
	if strings.Contains(joined, "-a ") {
		t.Fatalf("redis argv still uses -a: %s", joined)
	}
	if !strings.Contains(joined, "--env-file") {
		t.Fatalf("redis argv has no --env-file: %s", joined)
	}

	envFile := ""
	for i, arg := range fullArgs {
		if arg == "--env-file" && i+1 < len(fullArgs) {
			envFile = fullArgs[i+1]
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
	if !strings.Contains(string(data), "REDISCLI_AUTH=S3cr3t-P@ss") {
		t.Fatalf("env file missing REDISCLI_AUTH: %q", string(data))
	}

	cleanup()
	if _, err := os.Stat(envFile); !os.IsNotExist(err) {
		t.Fatalf("env file not removed by cleanup: %v", err)
	}
}

// TestRedisExecNoPasswordStaysPlain guards the empty-password branch.
func TestRedisExecNoPasswordStaysPlain(t *testing.T) {
	commands := redisExec("redis-ct", "")
	joined := strings.Join(commands, " ")
	if strings.Contains(joined, "-a ") || strings.Contains(joined, "--no-auth-warning") {
		t.Fatalf("empty password must produce a plain redis-cli argv: %s", joined)
	}
	commands = redisExec("redis-ct", "pw")
	if !strings.Contains(strings.Join(commands, " "), "--no-auth-warning") {
		t.Fatalf("password branch must keep --no-auth-warning: %v", commands)
	}
}
