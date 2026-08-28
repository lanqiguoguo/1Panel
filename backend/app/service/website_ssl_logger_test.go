package service

import (
	"bytes"
	"fmt"
	"strings"
	"sync"
	"testing"

	legoLogger "github.com/go-acme/lego/v4/log"
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
// 保护：模拟并发证书申请 goroutine（每个 goroutine 与 ObtainSSL 中一样：在
// sslApplyMu 临界区内覆盖 legoLogger.Logger 为指向自己 buffer 的 logger，输出
// 若干行日志后释放锁）。断言每个 goroutine 的日志块完整且连续——buffer 里恰好
// 是自己的全部日志行、按序排列、不含其它 goroutine 的任何行。若锁被移除或某处
// 覆盖/输出逃出临界区，另一 goroutine 的日志会串入本 buffer（行数不足或内容
// 交叉），测试即失败；同时该测试在 -race 下运行以捕获对全局 Logger 的任何
// 未加锁读写。此测试只涉及锁与 logger，无需 DB。
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
			// 与 ObtainSSL 的 goroutine 相同的临界区结构：持锁 -> 覆盖
			// lego 全局 Logger -> 输出日志 -> 恢复 -> 解锁。
			sslApplyMu.Lock()
			defer sslApplyMu.Unlock()
			prev := legoLogger.Logger
			defer func() { legoLogger.Logger = prev }()
			legoLogger.Logger = memLogger{buf: buf}
			for i := 0; i < linesPerGoroutine; i++ {
				legoLogger.Logger.Println(fmt.Sprintf("g%d-line-%d", g, i))
			}
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
}
