package service

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestBuildSSHKeygenArgs(t *testing.T) {
	secretFile := "/home/test/.ssh/id_item_rsa"

	t.Run("no password omits -N", func(t *testing.T) {
		args := buildSSHKeygenArgs(secretFile, "rsa", "")
		want := []string{"-t", "rsa", "-f", secretFile}
		if !reflect.DeepEqual(args, want) {
			t.Fatalf("unexpected args: got %v, want %v", args, want)
		}
		for _, a := range args {
			if a == "-N" {
				t.Fatalf("args should not contain -N when password is empty: %v", args)
			}
		}
	})

	t.Run("password kept as single argv after -N", func(t *testing.T) {
		password := "my pass with spaces -and-hyphens"
		args := buildSSHKeygenArgs("/tmp/key/id_item_ed25519", "ed25519", password)
		want := []string{"-t", "ed25519", "-f", "/tmp/key/id_item_ed25519", "-N", password}
		if !reflect.DeepEqual(args, want) {
			t.Fatalf("unexpected args: got %v, want %v", args, want)
		}
		if args[len(args)-1] != password {
			t.Fatalf("password not a single argv: got %q", args[len(args)-1])
		}
	})

	t.Run("malicious password is not expanded into args", func(t *testing.T) {
		// 恶意密码：若经过 shell 拼接会被解释为 `-f /tmp/pwned` 额外参数。
		password := "x -f /tmp/pwned"
		args := buildSSHKeygenArgs(secretFile, "rsa", password)

		nIdx := -1
		for i, a := range args {
			if a == "-N" {
				nIdx = i
			}
			if a == "/tmp/pwned" {
				t.Fatalf("malicious password split into its own argv element: %v", args)
			}
		}
		if nIdx == -1 {
			t.Fatalf("-N not found in args: %v", args)
		}
		if nIdx+1 >= len(args) || args[nIdx+1] != password {
			t.Fatalf("malicious password must be the single value of -N: %v", args)
		}
		// 除 -N 的值外，不应出现任何来自密码的片段。
		for i, a := range args {
			if i == nIdx+1 {
				continue
			}
			if strings.Contains(a, "/tmp/pwned") {
				t.Fatalf("password fragment leaked into another argv element %q: %v", a, args)
			}
		}
	})
}

// TestSSHKeygenPassphraseActsAsNewKeyPassword 集成验证 -N 的语义：
// 生成的密钥使用给定密码做 passphrase——错误密码无法解锁，正确密码可以。
// 不依赖 user.Current()/HOME，直接通过 buildSSHKeygenArgs + exec.Command 复现修复后的调用方式。
func TestSSHKeygenPassphraseActsAsNewKeyPassword(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not available in environment, skipping integration test")
	}

	secretFile := filepath.Join(t.TempDir(), "id_item_ed25519")
	secretPubFile := secretFile + ".pub"
	for _, stale := range []string{secretFile, secretPubFile} {
		if err := os.Remove(stale); err != nil && !os.IsNotExist(err) {
			t.Fatalf("remove stale file: %v", err)
		}
	}

	password := "pass with spaces -and dash"
	keygen := exec.Command("ssh-keygen", buildSSHKeygenArgs(secretFile, "ed25519", password)...)
	if out, err := keygen.CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen failed: %v, out: %s", err, out)
	}
	if _, err := os.Stat(secretFile); err != nil {
		t.Fatalf("private key not generated: %v", err)
	}
	if _, err := os.Stat(secretPubFile); err != nil {
		t.Fatalf("public key not generated: %v", err)
	}

	// 错误密码应被拒绝 => 证明 passphrase 真的生效（原 -P 语义下无效）。
	wrong := exec.Command("ssh-keygen", "-y", "-f", secretFile, "-P", "wrong")
	if out, err := wrong.CombinedOutput(); err == nil {
		t.Fatalf("expected wrong passphrase to be rejected, out: %s", out)
	}
	// 正确密码应能解锁。
	right := exec.Command("ssh-keygen", "-y", "-f", secretFile, "-P", password)
	if out, err := right.CombinedOutput(); err != nil {
		t.Fatalf("correct passphrase should unlock key: %v, out: %s", err, out)
	}
}

// TestSSHKeygenNoShellInjection 集成验证恶意密码不会造成额外的文件写入
// （复现修复前通过 bash -c 拼接时可写入任意路径，此处验证参数化后无法做到）。
func TestSSHKeygenNoShellInjection(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not available in environment, skipping integration test")
	}

	baseDir := t.TempDir()
	secretFile := filepath.Join(baseDir, "id_item_rsa")
	pwned := filepath.Join(baseDir, "pwned")

	// 若被 shell 解释，`-f <pwned>` 会让 ssh-keygen 覆盖 <pwned> 文件。
	password := "x -f " + pwned
	keygen := exec.Command("ssh-keygen", buildSSHKeygenArgs(secretFile, "rsa", password)...)
	if out, err := keygen.CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen failed: %v, out: %s", err, out)
	}
	if _, err := os.Stat(pwned); err == nil {
		t.Fatalf("malicious password was interpreted as extra ssh-keygen args, pwned file was created: %q", password)
	}
	if _, err := os.Stat(secretFile); err != nil {
		t.Fatalf("key not generated at intended path: %v", err)
	}
}
