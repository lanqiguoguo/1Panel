package service

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/1Panel-dev/1Panel/backend/global"
	legoLogger "github.com/go-acme/lego/v4/log"
	"github.com/sirupsen/logrus"
)

// memLogger 是 lego log.StdLogger 的一个内存实现，写入 bytes.Buffer，
// 用于在不需要真实文件与网络的情况下模拟"证书申请 goroutine 覆盖 lego
// 全局 Logger 并输出日志"。
type memLogger struct {
	buf *bytes.Buffer
}

func (m memLogger) Fatal(args ...interface{})                 { fmt.Fprintln(m.buf, args...) }
func (m memLogger) Fatalln(args ...interface{})               { fmt.Fprintln(m.buf, args...) }
func (m memLogger) Fatalf(format string, args ...interface{}) { fmt.Fprintf(m.buf, format, args...) }
func (m memLogger) Print(args ...interface{})                 { fmt.Fprint(m.buf, args...) }
func (m memLogger) Println(args ...interface{})               { fmt.Fprintln(m.buf, args...) }
func (m memLogger) Printf(format string, args ...interface{}) { fmt.Fprintf(m.buf, format, args...) }

// TestSSLApplyLoggerSerialized 验证 sslApplyMu 对 lego 包级全局 Logger 的串行化
// 保护。每个 goroutine 与 obtainWithLegoLock 完全同构：持锁 → 把
// legoLogger.Logger 换成指向自己 buffer 的 logger → 输出若干行（期间不断断言
// 全局仍指向自己）→ 释放锁之前恢复为 originalLegoLogger → 解锁。
// 断言：每个 goroutine 的日志块完整且连续（buffer 里恰好是自己的全部日志行、
// 按序排列、不含其它 goroutine 的任何行）；全部结束后全局恢复为
// originalLegoLogger。若串行化被破坏或恢复时机不在解锁之前，buffer 会交叉、
// 行数不足或终态不符。该测试在 -race 下运行，可捕获对全局 Logger 的任何未
// 加锁读写。只涉及锁与 logger，无需 DB。
func TestSSLApplyLoggerSerialized(t *testing.T) {
	const goroutines = 8
	const linesPerGoroutine = 50

	var wg sync.WaitGroup
	results := make([]string, goroutines)
	for g := 0; g < goroutines; g++ {
		g := g
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := &bytes.Buffer{}
			// 与 obtainWithLegoLock 相同的临界区结构：持锁 -> 覆盖
			// lego 全局 Logger -> 输出日志 -> 解锁前恢复默认值。
			sslApplyMu.Lock()
			legoLogger.Logger = memLogger{buf: buf}
			for i := 0; i < linesPerGoroutine; i++ {
				// 持锁期间全局必须仍指向自己的 logger，
				// 否则说明有 goroutine 在锁外动了它。
				if cur, ok := legoLogger.Logger.(memLogger); !ok || cur.buf != buf {
					legoLogger.Logger = originalLegoLogger
					sslApplyMu.Unlock()
					t.Errorf("goroutine %d line %d: legoLogger.Logger was replaced by another goroutine while lock was held", g, i)
					return
				}
				legoLogger.Logger.Println(fmt.Sprintf("g%d-line-%d", g, i))
			}
			legoLogger.Logger = originalLegoLogger
			sslApplyMu.Unlock()
			results[g] = buf.String()
		}()
	}
	wg.Wait()

	for g := 0; g < goroutines; g++ {
		lines := strings.Split(strings.TrimRight(results[g], "\n"), "\n")
		if len(lines) != linesPerGoroutine {
			t.Fatalf("goroutine %d: got %d log lines, want %d (log lines leaked into another goroutine's buffer)",
				g, len(lines), linesPerGoroutine)
		}
		for i, line := range lines {
			want := fmt.Sprintf("g%d-line-%d", g, i)
			if line != want {
				t.Fatalf("goroutine %d line %d: got %q, want %q (log blocks interleaved across goroutines)",
					g, i, line, want)
			}
		}
	}
	if legoLogger.Logger != originalLegoLogger {
		t.Fatalf("after all applicants finished, legoLogger.Logger was not restored to the package default (last holder must restore before Unlock)")
	}
}

// TestSSLApplyLockNarrowedToLegoPhase 验证锁收窄的核心性质：goroutine A 完成
// obtainWithLegoLock 式的持锁阶段（覆盖 logger、恢复默认、解锁）进入模拟的
// "锁外慢阶段"（对应解析证书、保存、ExecShellWithTimeOut 最长 30 分钟、
// createPemFile、nginx reload 等）后停在 channel 上；此时 goroutine B 必须
// 能进入 sslApplyMu 临界区——证明 A 已不持锁。若锁仍覆盖慢阶段（旧行为），
// B 永远拿不到锁，select 超时后测试失败。全部时序用 channel 同步，无 sleep。
func TestSSLApplyLockNarrowedToLegoPhase(t *testing.T) {
	aInSlowPhase := make(chan struct{}) // A 已解锁并进入慢阶段
	bAcquired := make(chan struct{})    // B 已在 A 慢阶段期间拿到锁
	releaseA := make(chan struct{})     // 放行 A 结束慢阶段

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { // A：完整模拟 ObtainSSL 的两阶段结构
		defer wg.Done()
		// 持锁阶段，与 obtainWithLegoLock 同构。
		sslApplyMu.Lock()
		legoLogger.Logger = memLogger{buf: &bytes.Buffer{}}
		legoLogger.Logger = originalLegoLogger // 解锁前恢复
		sslApplyMu.Unlock()
		close(aInSlowPhase)
		<-releaseA // 模拟慢阶段（shell/reload）持续到 B 完成验证
	}()
	go func() { // B：等待 A 进入慢阶段后尝试进入临界区
		defer wg.Done()
		<-aInSlowPhase
		sslApplyMu.Lock()
		legoLogger.Logger = memLogger{buf: &bytes.Buffer{}}
		close(bAcquired)
		legoLogger.Logger = originalLegoLogger
		sslApplyMu.Unlock()
	}()

	select {
	case <-bAcquired:
	case <-time.After(10 * time.Second):
		t.Fatal("goroutine B could not acquire sslApplyMu while goroutine A was in its post-lock slow phase: the critical section is held longer than the lego phase")
	}
	close(releaseA)
	wg.Wait()
}

// TestNewSSLLogFileOpenFailureFallsBackToStderr 验证 newSSLLogFile 的兜底路径：
// 日志文件创建失败时，向 global.LOG 记录原因并返回一个写到 os.Stderr 的可用
// logger——绝不返回 nil writer（log.New(nil, ...) 会在首次写入时 panic），
// 也不返回需要关闭的文件句柄。
func TestNewSSLLogFileOpenFailureFallsBackToStderr(t *testing.T) {
	// global.LOG 由服务端启动流程装配；单元测试里临时放一个一次性 logrus
	// logger，让兜底分支的错误记录有去处，结束后还原。
	prevLog, prevStderr := global.LOG, os.Stderr
	t.Cleanup(func() { global.LOG, os.Stderr = prevLog, prevStderr })
	global.LOG = logrus.New()

	// 先把 os.Stderr 换成管道，newSSLLogFile 内部 log.New(os.Stderr, ...) 捕获
	// 的就是管道写端，之后可以从读端断言兜底 logger 确实落到 stderr。
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = w.Close()
		_ = r.Close()
	}()
	os.Stderr = w

	logFile, logger := newSSLLogFile(filepath.Join(t.TempDir(), "missing-dir", "apply.log"))
	if logFile != nil {
		t.Fatalf("expected no file handle on open failure, got %v", logFile)
	}
	if logger == nil {
		t.Fatal("expected a fallback stderr logger, got nil (first write would panic)")
	}
	logger.Println("ssl-logfile-fallback-probe")

	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "ssl-logfile-fallback-probe") {
		t.Fatalf("fallback logger did not write to stderr, got %q", string(out))
	}
}
