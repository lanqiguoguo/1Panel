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
	"regexp"
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

// ExecWithTimeOutExtraFiles is the ExtraFiles-aware sibling of
// ExecWithTimeOut: cmdStr is parsed and executed by bash -c exactly like
// ExecWithTimeOut, and extraFiles are handed to the bash process starting at
// fd 3. bash does not close inherited descriptors, so pipeline children (e.g.
// `openssl ... -pass fd:3`) can read them. Timeout and process-group cleanup
// behave exactly like ExecWithTimeOut. File descriptors in extraFiles must be
// closed by the caller after this function returns.
func ExecWithTimeOutExtraFiles(cmdStr string, timeout time.Duration, extraFiles []*os.File) (string, error) {
	cmd := exec.Command("bash", "-c", cmdStr)
	setSysProcAttr(cmd)
	cmd.ExtraFiles = extraFiles
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

// SecretPassReader returns the read end of an OS pipe whose sole content is
// secret. Hand the returned file to one of the *ExtraFiles exec helpers (or
// cmd.ExtraFiles directly): the child receives it as fd 3, which openssl
// consumes with `-pass fd:3`. The password therefore never appears in a
// command line (/proc/<pid>/cmdline is world-readable). The write end is
// closed before returning, so the child reads the secret and then EOF. The
// pipe content is consumable exactly once and the caller owns the read end:
// it must be closed once the command has finished.
func SecretPassReader(secret string) (*os.File, error) {
	passReader, passWriter, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	if _, err := passWriter.WriteString(secret); err != nil {
		passWriter.Close()
		passReader.Close()
		return nil, err
	}
	if err := passWriter.Close(); err != nil {
		passReader.Close()
		return nil, err
	}
	return passReader, nil
}

// ExecCmdWithExtraFiles is the ExtraFiles-aware sibling of ExecCmd: cmdStr is
// parsed and executed by bash -c exactly like ExecCmd, and extraFiles are
// handed to the bash process starting at fd 3. bash does not close inherited
// descriptors, so pipeline children (e.g. `openssl ... -pass fd:3`) can read
// them. Note that the bash process itself keeps fd 3 open until the whole
// command finishes; file descriptors in extraFiles must therefore be closed
// by the caller after this function returns.
func ExecCmdWithExtraFiles(cmdStr string, extraFiles []*os.File) error {
	cmd := exec.Command("bash", "-c", cmdStr)
	setSysProcAttr(cmd)
	cmd.ExtraFiles = extraFiles
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

// CheckIllegal reports whether any argument contains a shell metacharacter or
// an "invisible separator": besides the classic metacharacters, the tab,
// vertical tab and form feed controls are rejected because bash word-splits on
// them just like on spaces, so they let a single validated value smuggle extra
// argv entries into an unquoted interpolation (e.g. a tar exclusion rule
// carrying "--checkpoint-action=exec=..." after a tab). Space is NOT rejected:
// it is a legal character in file and directory names.
func CheckIllegal(args ...string) bool {
	if args == nil {
		return false
	}
	for _, arg := range args {
		if strings.Contains(arg, "&") || strings.Contains(arg, "|") || strings.Contains(arg, ";") ||
			strings.Contains(arg, "$") || strings.Contains(arg, "'") || strings.Contains(arg, "`") ||
			strings.Contains(arg, "(") || strings.Contains(arg, ")") || strings.Contains(arg, "\"") ||
			strings.Contains(arg, "\n") || strings.Contains(arg, "\r") || strings.Contains(arg, ">") || strings.Contains(arg, "<") ||
			strings.Contains(arg, "\t") || strings.Contains(arg, "\v") || strings.Contains(arg, "\f") {
			return true
		}
	}
	return false
}

// validHostRegexp whitelists the values accepted as a remote database host in
// shell-built backup/restore commands: an optional IPv6 zone index (%eth0),
// then either a bracketed IPv6 body ("[2001:db8::1]", optionally :port) or a
// plain hostname / IPv4 / bare-IPv6 body drawn from alphanumerics, dots,
// dashes, underscores and colons, optionally followed by a docker network
// scope suffix (e.g. "mynet", "br-0a1b2c3d4e5e"). Whitespace and every shell
// metacharacter fall outside the class, so a rejected value can never break
// out of the enclosing single-quoted bash -c string; colons are inert to the
// shell and only ever select address/port forms.
var validHostRegexp = regexp.MustCompile(`^%?(?:\[[\p{L}\p{N}_.:-]+\]|[\p{L}\p{N}_.:-]+)(?::\d+)?(?:%[\p{L}\p{N}-]+)?$`)

// ValidDBHost reports whether host is safe to interpolate into the
// `docker run ... bash -c 'client -h <host> ...'` command built by the remote
// mysql/postgresql clients. It accepts hostnames, IPv4, bracketed IPv6 (the
// address may already arrive wrapped in brackets, see mysql.NewMysqlClient),
// an optional :port suffix and docker network-style names; it rejects empty
// values, whitespace and anything carrying shell metacharacters.
func ValidDBHost(host string) bool {
	if host == "" || len(host) > 253 || strings.ContainsAny(host, " \t\v\f\r\n") {
		return false
	}
	return validHostRegexp.MatchString(host)
}

// ValidDBUser reports whether user is safe to interpolate unquoted into the
// remote client command line (`-u<user>`, `-U <user>`). Databases only allow
// alphanumerics, underscore, dot and dash in user names, so the whitelist is
// restricted to that charset; empty values and shell metacharacters
// ($ ( ) ` ' " ; & | < > \n \r, tab and friends) are rejected.
func ValidDBUser(user string) bool {
	if user == "" || len(user) > 128 {
		return false
	}
	for _, r := range user {
		if !(r >= 'a' && r <= 'z') && !(r >= 'A' && r <= 'Z') && !(r >= '0' && r <= '9') &&
			r != '_' && r != '.' && r != '-' {
			return false
		}
	}
	return true
}

// ValidDBCharset reports whether charset is one of the client-encodable
// character set names ([A-Za-z0-9_-]+). MySQL collation/charset identifiers
// only ever use that charset, so anything else (spaces, quotes, semicolons)
// is rejected.
func ValidDBCharset(charset string) bool {
	if charset == "" || len(charset) > 64 {
		return false
	}
	for _, r := range charset {
		if !(r >= 'a' && r <= 'z') && !(r >= 'A' && r <= 'Z') && !(r >= '0' && r <= '9') &&
			r != '_' && r != '-' {
			return false
		}
	}
	return true
}

// validDBNameRegexp whitelists database/schema names embedded in backup and
// restore commands. MySQL allows the same charset (plus "$"), PostgreSQL adds
// no further characters; dots cover "my-db.v2" style names. Shell
// metacharacters, whitespace and empty names are all outside the class.
var validDBNameRegexp = regexp.MustCompile(`^[\p{L}\p{N}$_-][\p{L}\p{N}$_.\-]*(?:\.[\p{L}\p{N}$_.\-]+)*$`)

// ValidDBName reports whether name is a legal database/schema name safe for
// interpolation into the remote client shell command. MySQL identifiers
// accept alphanumerics plus _ - . $ (Unicode letters and digits included);
// the dot keeps multi-component names like "my-db.v2" working. Empty strings,
// pure dots ("." / ".."), whitespace, quotes, semicolons, backticks, $() and
// every other shell metacharacter are rejected.
func ValidDBName(name string) bool {
	if name == "" || len(name) > 255 {
		return false
	}
	return validDBNameRegexp.MatchString(name)
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
