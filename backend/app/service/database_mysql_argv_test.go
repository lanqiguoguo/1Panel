package service

import (
	"os"
	"strings"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/1Panel-dev/1Panel/backend/utils/cmd"
)

// TestMysqlExecArgvLeakFree is the regression test for the mysql root
// password argv leak: `docker exec <ct> mysql -uroot -p<password> -e ...`
// exposed the credential in the world-readable process argv. The password
// must now travel via MYSQL_PWD from a 0600 --env-file and never appear in
// the docker exec argv.
func TestMysqlExecArgvLeakFree(t *testing.T) {
	origTmp := global.CONF.System.TmpDir
	global.CONF.System.TmpDir = t.TempDir()
	defer func() { global.CONF.System.TmpDir = origTmp }()

	password := "S3cr3t-P@ssw0rd"
	envFile, err := cmd.WriteDockerEnvFile(global.CONF.System.TmpDir, map[string]string{"MYSQL_PWD": password})
	if err != nil {
		t.Fatalf("WriteDockerEnvFile failed: %v", err)
	}
	defer os.Remove(envFile)

	for _, dbType := range []string{"mysql", "mariadb"} {
		fullArgs := mysqlExecArgs(envFile, "mysql-ct", dbType, "show global status;")
		joined := strings.Join(fullArgs, " ")
		if strings.Contains(joined, password) {
			t.Fatalf("%s password leaked into docker exec argv: %s", dbType, joined)
		}
		if strings.Contains(joined, "-p") {
			t.Fatalf("%s argv still uses -p: %s", dbType, joined)
		}
		if !strings.Contains(joined, "--env-file") {
			t.Fatalf("%s argv has no --env-file: %s", dbType, joined)
		}
		if joined != strings.Join([]string{"docker", "exec", "--env-file", envFile, "mysql-ct", dbType, "-uroot", "-e", "show global status;"}, " ") {
			t.Fatalf("unexpected argv shape: %s", joined)
		}
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
	if !strings.Contains(string(data), "MYSQL_PWD="+password) {
		t.Fatalf("env file missing MYSQL_PWD: %q", string(data))
	}
}
