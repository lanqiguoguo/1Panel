package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/constant"
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

// TestValidateRedisConfValue rejects newline / directive injection. Values are
// written verbatim onto a redis.conf line, so "100mb\nrequirepass evil" must
// never reach the file.
func TestValidateRedisConfValueRejectsInjection(t *testing.T) {
	payloads := []struct {
		key   string
		value string
	}{
		{"maxmemory", "100mb\nrequirepass evil"},
		{"maxmemory", "100mb\rrequirepass evil"},
		{"maxclients", "1000\nrequirepass evil"},
		{"timeout", "0\nrequirepass evil"},
		{"save", "900 1\nrequirepass evil"},
		{"appendonly", "yes\nrequirepass evil"},
		{"appendfsync", "always\nrequirepass evil"},
		{"maxmemory", "100mb\n\nrequirepass evil"},
		{"maxmemory", "100mb\n# comment"},
		{"maxclients", "abc"},
		{"maxclients", "10.5"},
		{"maxmemory", "100tb"},
		{"maxmemory", "1.5gb"},
		{"maxmemory", "mb"},
		{"maxmemory", "100 mb"},
		{"save", "900"},
		{"save", "900 1 300"},
		{"save", "900,1"},
		{"appendonly", "1"},
		{"appendfsync", "EverySec"},
		{"timeout", "-1"},
		{"timeout", "900; drop table"},
	}
	seen := 0
	for _, p := range payloads {
		var err error
		switch p.key {
		case "timeout", "maxclients":
			err = validateRedisConfValue(p.value, redisConfValueInt)
		case "maxmemory":
			err = validateRedisConfValue(p.value, redisConfValueMemory)
		case "save":
			err = validateRedisConfValue(p.value, redisConfValueSave)
		case "appendonly":
			err = validateRedisConfValue(p.value, redisConfValueEnum, "yes", "no")
		case "appendfsync":
			err = validateRedisConfValue(p.value, redisConfValueEnum, "always", "everysec", "no")
		}
		if err == nil {
			t.Errorf("validateRedisConfValue(%s=%q): injection accepted", p.key, p.value)
		}
		seen++
	}
	if seen == 0 {
		t.Fatal("no injection payloads were exercised")
	}
}

// TestValidateRedisConfValueAcceptsLegalValues guards against over-tightening:
// the exact values the frontend produces must keep passing.
func TestValidateRedisConfValueAcceptsLegalValues(t *testing.T) {
	valid := []struct {
		key   string
		value string
	}{
		{"timeout", "900"},
		{"timeout", "0"},
		{"timeout", ""},
		{"maxclients", "65504"},
		{"maxclients", "0"},
		{"maxclients", ""},
		{"maxmemory", "100mb"},
		{"maxmemory", "1gb"},
		{"maxmemory", "512kb"},
		{"maxmemory", "0"},
		{"maxmemory", ""},
		{"save", "900 1"},
		{"save", "900 1,300 10"},
		{"save", "900 1, 300 10"},
		{"save", "60 10000"},
		{"save", ""},
		{"appendonly", "yes"},
		{"appendonly", "no"},
		{"appendonly", ""},
		{"appendfsync", "always"},
		{"appendfsync", "everysec"},
		{"appendfsync", "no"},
		{"appendfsync", ""},
	}
	for _, item := range valid {
		var err error
		switch item.key {
		case "timeout", "maxclients":
			err = validateRedisConfValue(item.value, redisConfValueInt)
		case "maxmemory":
			err = validateRedisConfValue(item.value, redisConfValueMemory)
		case "save":
			err = validateRedisConfValue(item.value, redisConfValueSave)
		case "appendonly":
			err = validateRedisConfValue(item.value, redisConfValueEnum, "yes", "no")
		case "appendfsync":
			err = validateRedisConfValue(item.value, redisConfValueEnum, "always", "everysec", "no")
		}
		if err != nil {
			t.Errorf("validateRedisConfValue(%s=%q): legal value rejected: %v", item.key, item.value, err)
		}
	}
}

// TestConfSetRejectsInjectedValues proves the write path itself is guarded: a
// payload that would previously append "requirepass evil" on its own line must
// be rejected before the file is rewritten.
func TestConfSetRejectsInjectedValues(t *testing.T) {
	origDir := constant.AppInstallDir
	constant.AppInstallDir = t.TempDir()
	defer func() { constant.AppInstallDir = origDir }()

	redisDir := filepath.Join(constant.AppInstallDir, "redis", "redis-1")
	confDir := filepath.Join(redisDir, "conf")
	if err := os.MkdirAll(confDir, 0755); err != nil {
		t.Fatalf("mkdir conf dir: %v", err)
	}
	confPath := filepath.Join(confDir, "redis.conf")
	base := "# Redis configuration rewrite by 1Panel\nmaxmemory 100mb\n# End Redis configuration rewrite by 1Panel\n"
	if err := os.WriteFile(confPath, []byte(base), 0600); err != nil {
		t.Fatalf("write redis.conf: %v", err)
	}

	err := confSet("redis-1", "", []redisConfig{{key: "maxmemory", value: "100mb\nrequirepass evil"}})
	if err == nil {
		t.Fatal("confSet accepted an injected value")
	}
	data, readErr := os.ReadFile(confPath)
	if readErr != nil {
		t.Fatalf("re-read redis.conf: %v", readErr)
	}
	if strings.Contains(string(data), "requirepass") {
		t.Fatalf("injected directive reached the conf file: %q", string(data))
	}
	if !strings.Contains(string(data), "maxmemory 100mb") {
		t.Fatalf("conf file was modified by a rejected value: %q", string(data))
	}
}
