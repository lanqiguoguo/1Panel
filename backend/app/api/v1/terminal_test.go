package v1

import (
	"os"
	"strings"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/global"
)

// TestKillablePid guards killBash's pid gate: the pid value reaching
// kill -9 comes from `docker top` output. It must be a plain positive
// integer so it can only be passed to kill(1) as a parameter; anything
// else (shell metacharacters, negative values, garbage) is refused and
// can never be interpolated into a shell command line.
func TestKillablePid(t *testing.T) {
	cases := []struct {
		name string
		pid  string
		want bool
	}{
		{"normal pid", "1234", true},
		{"zero is not a process", "0", false},
		{"negative pid", "-5", false},
		{"plus sign", "+5", false},
		{"leading zero", "0123", true},
		{"semicolon injection", "1; id", false},
		{"command substitution", "1$(id)", false},
		{"pipe injection", "1 | id", false},
		{"ampersand injection", "1 & id", false},
		{"backtick injection", "1`id`", false},
		{"whitespace padding", " 123", false},
		{"non numeric", "abc", false},
		{"decimal point", "1.5", false},
		{"empty", "", false},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if got := killablePid(tt.pid); got != tt.want {
				t.Errorf("killablePid(%q) = %v, want %v", tt.pid, got, tt.want)
			}
		})
	}
}

// TestRedisExecEnvFileArgv is the regression test for the redis terminal
// password argv leak: the ws initCmd used `redis-cli -a <password>`, which
// exposed the credential in the world-readable process argv of the docker
// exec command. The password must now travel through a 0600 --env-file
// (REDISCLI_AUTH) and the returned cleanup must remove the file.
func TestRedisExecEnvFileArgv(t *testing.T) {
	origTmp := global.CONF.System.TmpDir
	global.CONF.System.TmpDir = t.TempDir()
	defer func() { global.CONF.System.TmpDir = origTmp }()

	password := "S3cr3t-P@ss"
	baseCmds := []string{"exec", "-it", "1Panel-redis-ct", "redis-cli", "-h", "127.0.0.1", "-p", "6379", "--no-auth-warning"}
	fullArgs, cleanup, err := redisExecEnvFile(baseCmds, password)
	if err != nil {
		t.Fatalf("redisExecEnvFile failed: %v", err)
	}

	joined := strings.Join(fullArgs, " ")
	if strings.Contains(joined, password) {
		t.Fatalf("redis password leaked into docker exec argv: %s", joined)
	}
	if strings.Contains(joined, "-a ") {
		t.Fatalf("redis argv still uses -a: %s", joined)
	}
	if !strings.Contains(joined, "--env-file") {
		t.Fatalf("redis argv has no --env-file: %s", joined)
	}
	if fullArgs[0] != "exec" {
		t.Fatalf("argv must start with exec: %v", fullArgs)
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
	if !strings.Contains(string(data), "REDISCLI_AUTH="+password) {
		t.Fatalf("env file missing REDISCLI_AUTH: %q", string(data))
	}

	// The in-container command line seen by killBash must stay the plain
	// redis-cli argv: no docker options, container name or env file path.
	comm := dockerExecComm("1Panel-redis-ct", fullArgs)
	if comm != "redis-cli -h 127.0.0.1 -p 6379 --no-auth-warning" {
		t.Fatalf("dockerExecComm = %q, want the plain redis-cli command line", comm)
	}
	if strings.Contains(comm, envFile) {
		t.Fatalf("env file path leaked into killBash comm: %q", comm)
	}

	cleanup()
	if _, err := os.Stat(envFile); !os.IsNotExist(err) {
		t.Fatalf("env file not removed by cleanup: %v", err)
	}
}

// TestDockerExecComm guards the killBash command extraction for every ws
// terminal source: everything after the container name/id is the in-container
// command line, docker-side options are not part of it.
func TestDockerExecComm(t *testing.T) {
	cases := []struct {
		name        string
		containerID string
		initCmd     []string
		want        string
	}{
		{
			name:        "redis with env file",
			containerID: "1Panel-redis-ct",
			initCmd:     []string{"exec", "--env-file", "/opt/1panel/tmp/docker-env-1", "-it", "1Panel-redis-ct", "redis-cli", "--no-auth-warning"},
			want:        "redis-cli --no-auth-warning",
		},
		{
			name:        "redis without password",
			containerID: "1Panel-redis-ct",
			initCmd:     []string{"exec", "-it", "1Panel-redis-ct", "redis-cli"},
			want:        "redis-cli",
		},
		{
			name:        "ollama",
			containerID: "1Panel-ollama-ct",
			initCmd:     []string{"exec", "-it", "1Panel-ollama-ct", "ollama", "run", "llama3"},
			want:        "ollama run llama3",
		},
		{
			name:        "container with user",
			containerID: "ct-1",
			initCmd:     []string{"exec", "-it", "-u", "www", "ct-1", "sh"},
			want:        "sh",
		},
		{
			name:        "container plain",
			containerID: "ct-1",
			initCmd:     []string{"exec", "-it", "ct-1", "sh"},
			want:        "sh",
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if got := dockerExecComm(tt.containerID, tt.initCmd); got != tt.want {
				t.Errorf("dockerExecComm(%q, %v) = %q, want %q", tt.containerID, tt.initCmd, got, tt.want)
			}
		})
	}
}
