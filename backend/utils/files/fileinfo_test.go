package files

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/buserr"
	"github.com/1Panel-dev/1Panel/backend/constant"
	"github.com/spf13/afero"
)

// assertCanNotRead asserts that err is the ErrFileCanNotRead business error.
func assertCanNotRead(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected ErrFileCanNotRead, got nil")
	}
	be, ok := err.(buserr.BusinessError)
	if !ok || be.Msg != constant.ErrFileCanNotRead {
		t.Fatalf("expected ErrFileCanNotRead, got %v", err)
	}
}

// TestGetContentRejectsFifo 验证 FIFO（命名管道）在读取前即被拒绝，不会再
// 进入 ReadFile 造成永久阻塞。
func TestGetContentRejectsFifo(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "pipe.fifo")
	if err := syscall.Mkfifo(fifo, 0644); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
	// 以读写方式持有一个打开的 fd（Linux 上 O_RDWR 打开 FIFO 不会阻塞），
	// 这样即使实现退化为直接读 FIFO，测试也会因读到 EOF 而失败而非挂死。
	keeper, err := os.OpenFile(fifo, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer keeper.Close()

	info, err := os.Stat(fifo)
	if err != nil {
		t.Fatal(err)
	}
	f := &FileInfo{Fs: afero.NewOsFs(), Path: fifo, FileMode: info.Mode(), Size: info.Size()}
	assertCanNotRead(t, f.getContent())
}

// TestGetContentRejectsCharDevice 验证字符设备（/dev/zero）在读取前即被
// 拒绝；检查发生在任何 ReadFile 之前，因此本测试不会触发无界读。
func TestGetContentRejectsCharDevice(t *testing.T) {
	const zero = "/dev/zero"
	info, err := os.Stat(zero)
	if err != nil || info.Mode()&os.ModeCharDevice == 0 {
		t.Skipf("%s is not available on this platform", zero)
	}
	f := &FileInfo{Fs: afero.NewOsFs(), Path: zero, FileMode: info.Mode(), Size: info.Size()}
	assertCanNotRead(t, f.getContent())
}

// TestGetContentRegularFileStillWorks 验证普通文件的读取不受影响。
func TestGetContentRegularFileStillWorks(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a.txt")
	if err := os.WriteFile(p, []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	f := &FileInfo{Fs: afero.NewOsFs(), Path: p, FileMode: info.Mode(), Size: info.Size()}
	if err := f.getContent(); err != nil {
		t.Fatalf("regular file should load, got %v", err)
	}
	if f.Content != "hello" {
		t.Fatalf("content = %q, want %q", f.Content, "hello")
	}
}
