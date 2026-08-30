package cmd

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/1Panel-dev/1Panel/backend/buserr"
	"github.com/1Panel-dev/1Panel/backend/constant"
)

// sleepMarker 使用独特参数，避免误伤机器上其他 sleep 进程。
const sleepMarker = "sleep 97.77"

// cleanSleepMarker 兜底清理测试可能残留的进程。
func cleanSleepMarker(t *testing.T) {
	t.Helper()
	if out, err := exec.Command("pkill", "-f", sleepMarker).CombinedOutput(); err == nil {
		t.Logf("cleaned up leftover processes: %s", strings.TrimSpace(string(out)))
	}
}

// assertTimeoutErr 断言返回的是命令超时错误。
func assertTimeoutErr(t *testing.T, err error) {
	t.Helper()
	var bErr buserr.BusinessError
	if !errors.As(err, &bErr) || bErr.Msg != constant.ErrCmdTimeout {
		t.Fatalf("expected ErrCmdTimeout, got: %v", err)
	}
}

// assertSleepGone 轮询确认 sleepMarker 对应的进程已被全部杀死。
func assertSleepGone(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		out, _ := exec.Command("pgrep", "-f", sleepMarker).CombinedOutput()
		if len(bytes.TrimSpace(out)) == 0 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	out, _ := exec.Command("pgrep", "-f", sleepMarker).CombinedOutput()
	t.Fatalf("process group not killed, remaining processes:\n%s", out)
}

func TestExecWithTimeOutKillsProcessGroup(t *testing.T) {
	cleanSleepMarker(t)
	defer cleanSleepMarker(t)

	// bash 派生的 sleep 子进程，超时后整个进程组必须被杀死
	_, err := ExecWithTimeOut(sleepMarker+" & wait", time.Second)
	assertTimeoutErr(t, err)
	assertSleepGone(t)
}

func TestExecCronjobWithTimeOutKillsProcessGroup(t *testing.T) {
	cleanSleepMarker(t)
	defer cleanSleepMarker(t)

	outPath := filepath.Join(t.TempDir(), "cron.log")
	err := ExecCronjobWithTimeOut(sleepMarker+" & wait", t.TempDir(), outPath, time.Second)
	assertTimeoutErr(t, err)
	assertSleepGone(t)
}

func TestExecWithTimeOutNormal(t *testing.T) {
	out, err := ExecWithTimeOut("echo hello", 5*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.TrimSpace(out) != "hello" {
		t.Fatalf("unexpected output: %q", out)
	}
}

func TestExecCronjobWithTimeOutNormal(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "out.log")
	if err := ExecCronjobWithTimeOut("echo cron-ok", t.TempDir(), outPath, 5*time.Second); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read out file: %v", err)
	}
	if strings.TrimSpace(string(data)) != "cron-ok" {
		t.Fatalf("unexpected output: %q", string(data))
	}
}

// TestExecCronjobWithTimeOutStdinPipesContent verifies the stdin-aware
// sibling byte-for-byte: stdinContent must reach the child process
// unmodified. bash -c only parses its own argument string; the stdin data is
// read by the child program (here: cat) without any shell word-splitting,
// $()/backtick/$VAR expansion or quote processing on the way.
func TestExecCronjobWithTimeOutStdinPipesContent(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "out.log")
	script := "echo $(hostname) `echo backtick` \"quoted\" $HOME\nline2\n"
	if err := ExecCronjobWithTimeOutStdin("cat", script, t.TempDir(), outPath, 5*time.Second); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read out file: %v", err)
	}
	if got := string(data); got != script {
		t.Fatalf("stdin content was altered in transit:\n got %q\nwant %q", got, script)
	}
}

// TestExecCronjobWithTimeOutStdinExpandsInsideTheShell verifies the script is
// executed by the child shell (which expands $(...) on purpose), not by the
// host bash -c wrapper that only launches it.
func TestExecCronjobWithTimeOutStdinExpandsInsideTheShell(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "out.log")
	if err := ExecCronjobWithTimeOutStdin("sh", "echo x-$(printf 42)", t.TempDir(), outPath, 5*time.Second); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read out file: %v", err)
	}
	if strings.TrimSpace(string(data)) != "x-42" {
		t.Fatalf("unexpected output: %q, want %q", string(data), "x-42")
	}
}

// TestExecCronjobWithTimeOutStdinEmptyInput runs with an empty stdin payload.
func TestExecCronjobWithTimeOutStdinEmptyInput(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "out.log")
	if err := ExecCronjobWithTimeOutStdin("sh", "", t.TempDir(), outPath, 5*time.Second); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read out file: %v", err)
	}
	if len(strings.TrimSpace(string(data))) != 0 {
		t.Fatalf("expected no output for an empty stdin script, got %q", string(data))
	}
}

func TestExecScriptNormal(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "test.sh")
	if err := os.WriteFile(script, []byte("#!/bin/bash\necho script-ok\n"), 0755); err != nil {
		t.Fatalf("write script: %v", err)
	}
	out, err := ExecScript(script, dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.TrimSpace(out) != "script-ok" {
		t.Fatalf("unexpected output: %q", out)
	}
}

// TestWriteDockerEnvFile is the regression test for the credential argv leak:
// the docker env file must be root-owned 0600, must not itself be passed to
// any process argv containing the password, and must be removable.
func TestWriteDockerEnvFile(t *testing.T) {
	dir := t.TempDir()
	path, err := WriteDockerEnvFile(dir, map[string]string{"MYSQL_PWD": "s3cr3t-pass", "REDISCLI_AUTH": "r3d-pass"})
	if err != nil {
		t.Fatalf("WriteDockerEnvFile failed: %v", err)
	}
	defer os.Remove(path)

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat env file: %v", err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("env file mode = %v, want 0600", got)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read env file: %v", err)
	}
	content := string(data)
	for _, want := range []string{"MYSQL_PWD=s3cr3t-pass", "REDISCLI_AUTH=r3d-pass"} {
		if !strings.Contains(content, want) {
			t.Fatalf("env file missing %q, got:\n%s", want, content)
		}
	}

	// The credential must never surface in a process argv: build the docker
	// exec argv exactly like the mysql/redis clients do and assert the
	// password is absent from it (only the 0600 file path is present).
	args := append([]string{"exec", "--env-file", path, "mysql", "-uroot", "-e"}, "select 1")
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "s3cr3t-pass") {
		t.Fatalf("password leaked into docker exec argv: %s", joined)
	}
	if !strings.Contains(joined, "--env-file") {
		t.Fatalf("docker exec argv has no --env-file: %s", joined)
	}
}

// TestWriteDockerEnvFileNotWorldReadable re-checks the file permissions from
// the perspective of another local user (mode bits only).
func TestWriteDockerEnvFileNotWorldReadable(t *testing.T) {
	dir := t.TempDir()
	path, err := WriteDockerEnvFile(dir, map[string]string{"MYSQL_PWD": "x"})
	if err != nil {
		t.Fatalf("WriteDockerEnvFile failed: %v", err)
	}
	defer os.Remove(path)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat env file: %v", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("env file is group/world accessible: %v", info.Mode().Perm())
	}
}
