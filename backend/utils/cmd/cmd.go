package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/1Panel-dev/1Panel/backend/buserr"
	"github.com/1Panel-dev/1Panel/backend/constant"
)

func Exec(cmdStr string) (string, error) {
	return ExecWithTimeOut(cmdStr, 20*time.Second)
}

func handleErr(stdout, stderr bytes.Buffer, err error) (string, error) {
	errMsg := ""
	if len(stderr.String()) != 0 {
		errMsg = fmt.Sprintf("stderr: %s", stderr.String())
	}
	if len(stdout.String()) != 0 {
		if len(errMsg) != 0 {
			errMsg = fmt.Sprintf("%s; stdout: %s", errMsg, stdout.String())
		} else {
			errMsg = fmt.Sprintf("stdout: %s", stdout.String())
		}
	}
	return errMsg, err
}

func setSysProcAttr(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// killProcessGroup 杀掉命令及其整个进程组，避免超时后留下孤儿子进程。
// 进程组 ID 等于进程 PID（Setpgid 后）。
func killProcessGroup(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
}

func ExecWithTimeOut(cmdStr string, timeout time.Duration) (string, error) {
	cmd := exec.Command("bash", "-c", cmdStr)
	setSysProcAttr(cmd)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return "", err
	}
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()
	after := time.After(timeout)
	select {
	case <-after:
		killProcessGroup(cmd)
		return "", buserr.New(constant.ErrCmdTimeout)
	case err := <-done:
		if err != nil {
			return handleErr(stdout, stderr, err)
		}
	}

	return stdout.String(), nil
}

// ExecWithTimeOutArgv is the argv (non-shell) sibling of ExecWithTimeOut:
// name and args are handed to exec.Command directly, so no bash -c parsing
// happens and the arguments can never inject shell commands. Use it whenever
// an argument originates from untrusted content (e.g. image names parsed out
// of remote docker-compose.yml files). Timeout and process-group cleanup
// behave exactly like ExecWithTimeOut.
func ExecWithTimeOutArgv(name string, timeout time.Duration, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	setSysProcAttr(cmd)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return "", err
	}
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()
	after := time.After(timeout)
	select {
	case <-after:
		killProcessGroup(cmd)
		return "", buserr.New(constant.ErrCmdTimeout)
	case err := <-done:
		if err != nil {
			return handleErr(stdout, stderr, err)
		}
	}

	return stdout.String(), nil
}

func ExecContainerScript(containerName, cmdStr string, timeout time.Duration) error {
	// containerName is interpolated unquoted into the docker exec command,
	// so reject shell metacharacters even for rows persisted before the
	// service-level name checks existed (ValidShellArgs semantics: non-empty
	// and free of the CheckIllegal charset).
	if containerName == "" || CheckIllegal(containerName) {
		return buserr.New(constant.ErrCmdIllegal)
	}
	cmdStr = fmt.Sprintf("docker exec -i %s bash -c '%s'", containerName, cmdStr)
	out, err := ExecWithTimeOut(cmdStr, timeout)
	if err != nil {
		if out != "" {
			return fmt.Errorf("%s; err: %v", out, err)
		}
		return err
	}
	return nil
}

func ExecCronjobWithTimeOut(cmdStr, workdir, outPath string, timeout time.Duration) error {
	file, err := os.OpenFile(outPath, os.O_WRONLY|os.O_CREATE, 0666)
	if err != nil {
		return err
	}
	defer file.Close()

	cmd := exec.Command("bash", "-c", cmdStr)
	setSysProcAttr(cmd)
	cmd.Dir = workdir
	cmd.Stdout = file
	cmd.Stderr = file
	if err := cmd.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()
	after := time.After(timeout)
	select {
	case <-after:
		killProcessGroup(cmd)
		return buserr.New(constant.ErrCmdTimeout)
	case err := <-done:
		if err != nil {
			return err
		}
	}
	return nil
}

// ExecCronjobWithTimeOutStdin is the stdin-aware sibling of
// ExecCronjobWithTimeOut: cmdStr is executed the same way, but stdinContent is
// piped to the child process instead of being interpolated into cmdStr.
//
// It exists for the container-exec cronjob path: the script content must reach
// the in-container shell untouched, and the host shell must never parse it
// (interpolating it into `docker exec ... -c "..."` lets the host shell expand
// $(), backticks and $VAR before docker ever sees the script).
func ExecCronjobWithTimeOutStdin(cmdStr, stdinContent, workdir, outPath string, timeout time.Duration) error {
	file, err := os.OpenFile(outPath, os.O_WRONLY|os.O_CREATE, 0666)
	if err != nil {
		return err
	}
	defer file.Close()

	cmd := exec.Command("bash", "-c", cmdStr)
	setSysProcAttr(cmd)
	cmd.Dir = workdir
	cmd.Stdout = file
	cmd.Stderr = file
	cmd.Stdin = strings.NewReader(stdinContent)
	if err := cmd.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()
	after := time.After(timeout)
	select {
	case <-after:
		killProcessGroup(cmd)
		return buserr.New(constant.ErrCmdTimeout)
	case err := <-done:
		if err != nil {
			return err
		}
	}
	return nil
}

func Execf(cmdStr string, a ...interface{}) (string, error) {
	cmd := exec.Command("bash", "-c", fmt.Sprintf(cmdStr, a...))
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return handleErr(stdout, stderr, err)
	}
	return stdout.String(), nil
}

func ExecWithCheck(name string, a ...string) (string, error) {
	cmd := exec.Command(name, a...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return handleErr(stdout, stderr, err)
	}
	return stdout.String(), nil
}

func ExecScript(scriptPath, workDir string) (string, error) {
	cmd := exec.Command("bash", scriptPath)
	setSysProcAttr(cmd)
	var stdout, stderr bytes.Buffer
	cmd.Dir = workDir
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return "", err
	}
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()
	after := time.After(10 * time.Minute)
	select {
	case <-after:
		killProcessGroup(cmd)
		return "", buserr.New(constant.ErrCmdTimeout)
	case err := <-done:
		if err != nil {
			return handleErr(stdout, stderr, err)
		}
	}

	return stdout.String(), nil
}

func ExecCmd(cmdStr string) error {
	cmd := exec.Command("bash", "-c", cmdStr)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("error : %v, output: %s", err, output)
	}
	return nil
}

func ExecCmdWithDir(cmdStr, workDir string) error {
	cmd := exec.Command("bash", "-c", cmdStr)
	cmd.Dir = workDir
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("error : %v, output: %s", err, output)
	}
	return nil
}

func CheckIllegal(args ...string) bool {
	if args == nil {
		return false
	}
	for _, arg := range args {
		if strings.Contains(arg, "&") || strings.Contains(arg, "|") || strings.Contains(arg, ";") ||
			strings.Contains(arg, "$") || strings.Contains(arg, "'") || strings.Contains(arg, "`") ||
			strings.Contains(arg, "(") || strings.Contains(arg, ")") || strings.Contains(arg, "\"") ||
			strings.Contains(arg, "\n") || strings.Contains(arg, "\r") || strings.Contains(arg, ">") || strings.Contains(arg, "<") {
			return true
		}
	}
	return false
}

// WriteDockerEnvFile writes key=value pairs to a fresh 0600 file under dir and
// returns its path. The caller must pass the path to `docker exec --env-file`
// and is responsible for removing the file (typically via defer os.Remove).
//
// Rationale: passing a credential as a docker exec argument (`-p <password>`,
// `-a <password>` or `-e VAR=<password>`) leaks it into the process argv,
// which is world-readable on Linux by default (/proc/<pid>/cmdline is 0444
// even for root-owned processes). `--env-file` hands the values to the docker
// CLI (running as root, started by the panel) over the daemon socket and keeps
// them out of argv entirely; the panel then only has to secure the file
// itself, which is enforced here with a root-owned 0600 mode.
func WriteDockerEnvFile(dir string, envs map[string]string) (string, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	file, err := os.CreateTemp(dir, "docker-env-*")
	if err != nil {
		return "", err
	}
	defer file.Close()
	if err := os.Chmod(file.Name(), 0600); err != nil {
		_ = os.Remove(file.Name())
		return "", err
	}
	var builder strings.Builder
	for key, value := range envs {
		builder.WriteString(key)
		builder.WriteString("=")
		builder.WriteString(value)
		builder.WriteString("\n")
	}
	if _, err := file.WriteString(builder.String()); err != nil {
		_ = os.Remove(file.Name())
		return "", err
	}
	abs, err := filepath.Abs(file.Name())
	if err != nil {
		_ = os.Remove(file.Name())
		return "", err
	}
	return abs, nil
}

func HasNoPasswordSudo() bool {
	cmd2 := exec.Command("sudo", "-n", "ls")
	err2 := cmd2.Run()
	return err2 == nil
}

func SudoHandleCmd() string {
	cmd := exec.Command("sudo", "-n", "ls")
	if err := cmd.Run(); err == nil {
		return "sudo "
	}
	return ""
}

func Which(name string) bool {
	stdout, err := Execf("which %s", name)
	if err != nil || (len(strings.ReplaceAll(stdout, "\n", "")) == 0) {
		return false
	}
	return true
}

func ExecShellWithTimeOut(cmdStr, workdir string, logger *log.Logger, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "bash", "-c", cmdStr)
	cmd.Dir = workdir
	cmd.Stdout = logger.Writer()
	cmd.Stderr = logger.Writer()
	if err := cmd.Start(); err != nil {
		return err
	}
	err := cmd.Wait()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return buserr.New(constant.ErrCmdTimeout)
	}
	return err
}
