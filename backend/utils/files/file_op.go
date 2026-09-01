package files

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/1Panel-dev/1Panel/backend/buserr"
	"github.com/1Panel-dev/1Panel/backend/constant"
	"github.com/1Panel-dev/1Panel/backend/utils/cmd"
	http2 "github.com/1Panel-dev/1Panel/backend/utils/http"
	cZip "github.com/klauspost/compress/zip"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"

	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/mholt/archiver/v4"
	"github.com/pkg/errors"
	"github.com/spf13/afero"
)

type FileOp struct {
	Fs afero.Fs
	// cutProtectedPathCheck, when set, is consulted by Cut immediately before
	// executing the move: every source path and the effective destination is
	// passed through it, and a true verdict aborts the operation. It exists
	// because package files cannot import app/service (import cycle) where
	// the protected-path policy lives; the service layer installs its check
	// via SetCutProtectedPathCheck. When nil (tests, other callers) Cut skips
	// this re-check and relies on its own argument validation only.
	cutProtectedPathCheck func(paths ...string) bool
}

// SetCutProtectedPathCheck installs the execution-point protected-path
// re-check used by Cut (see FileOp.cutProtectedPathCheck). It must be called
// once during service-layer initialization.
func SetCutProtectedPathCheck(check func(paths ...string) bool) {
	cutProtectedPathOnce.Do(func() {
		cutProtectedPathCheckGlobal = check
	})
}

var (
	cutProtectedPathCheckGlobal func(paths ...string) bool
	cutProtectedPathOnce        sync.Once
)

func NewFileOp() FileOp {
	fo := FileOp{
		Fs: afero.NewOsFs(),
	}
	if cutProtectedPathCheckGlobal != nil {
		fo.cutProtectedPathCheck = cutProtectedPathCheckGlobal
	}
	return fo
}

func (f FileOp) OpenFile(dst string) (fs.File, error) {
	return f.Fs.Open(dst)
}

func (f FileOp) GetContent(dst string) ([]byte, error) {
	afs := &afero.Afero{Fs: f.Fs}
	cByte, err := afs.ReadFile(dst)
	if err != nil {
		return nil, err
	}
	return cByte, nil
}

func (f FileOp) CreateDir(dst string, mode fs.FileMode) error {
	return f.Fs.MkdirAll(dst, mode)
}

func (f FileOp) CreateDirWithMode(dst string, mode fs.FileMode) error {
	if err := f.Fs.MkdirAll(dst, mode); err != nil {
		return err
	}
	return f.ChmodRWithMode(dst, mode, true)
}

func (f FileOp) CreateFile(dst string) error {
	if _, err := f.Fs.Create(dst); err != nil {
		return err
	}
	return nil
}

func (f FileOp) CreateFileWithMode(dst string, mode fs.FileMode) error {
	// 纵深防御：强制剥离 setuid/setgid/sticky 等高位权限位，
	// 防止调用方透传未掩码的 mode 创建出 SUID 文件
	mode = mode.Perm()
	file, err := f.Fs.OpenFile(dst, os.O_CREATE, mode)
	if err != nil {
		return err
	}
	return file.Close()
}

func (f FileOp) LinkFile(source string, dst string, isSymlink bool) error {
	if isSymlink {
		osFs := afero.OsFs{}
		return osFs.SymlinkIfPossible(source, dst)
	} else {
		return os.Link(source, dst)
	}
}

func (f FileOp) DeleteDir(dst string) error {
	return f.Fs.RemoveAll(dst)
}

func (f FileOp) Stat(dst string) bool {
	info, _ := f.Fs.Stat(dst)
	return info != nil
}

func (f FileOp) DeleteFile(dst string) error {
	return f.Fs.Remove(dst)
}

func (f FileOp) CleanDir(dst string) error {
	if !ValidPath(dst) {
		return buserr.New(constant.ErrCmdIllegal)
	}
	return cmd.ExecCmd(fmt.Sprintf("rm -rf '%s'/*", dst))
}

func (f FileOp) RmRf(dst string) error {
	if !ValidPath(dst) {
		return buserr.New(constant.ErrCmdIllegal)
	}
	return cmd.ExecCmd(fmt.Sprintf("rm -rf '%s'", dst))
}

func (f FileOp) WriteFile(dst string, in io.Reader, mode fs.FileMode) error {
	file, err := f.Fs.OpenFile(dst, os.O_RDWR|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer file.Close()

	if _, err = io.Copy(file, in); err != nil {
		return err
	}

	if _, err = file.Stat(); err != nil {
		return err
	}
	return nil
}

func (f FileOp) SaveFile(dst string, content string, mode fs.FileMode) error {
	if !f.Stat(path.Dir(dst)) {
		_ = f.CreateDir(path.Dir(dst), mode.Perm())
	}
	file, err := f.Fs.OpenFile(dst, os.O_RDWR|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer file.Close()
	write := bufio.NewWriter(file)
	_, _ = write.WriteString(content)
	write.Flush()
	return nil
}

func (f FileOp) SaveFileWithByte(dst string, content []byte, mode fs.FileMode) error {
	if !f.Stat(path.Dir(dst)) {
		_ = f.CreateDir(path.Dir(dst), mode.Perm())
	}
	file, err := f.Fs.OpenFile(dst, os.O_RDWR|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer file.Close()
	write := bufio.NewWriter(file)
	_, _ = write.Write(content)
	write.Flush()
	return nil
}

var validUserGroupRegexp = regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`)

// ValidUserGroup checks whether the given user/group name only contains
// characters allowed by chown (alphanumerics, dot, underscore and dash).
func ValidUserGroup(s string) bool {
	return validUserGroupRegexp.MatchString(s)
}

var validContainerNameRegexp = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)

// ValidContainerName reports whether the given name matches the docker
// container name rule: 1-128 characters of alphanumerics, underscore, dot
// and dash, starting with a letter or digit. Container names also land
// unquoted in shell commands (docker exec), so this charset is enforced at
// the service boundary in addition to ValidShellArgs at the call sites.
func ValidContainerName(s string) bool {
	return validContainerNameRegexp.MatchString(s)
}

// ValidPath checks whether the given path contains no shell metacharacters.
// It is used before a path is interpolated into a shell command.
func ValidPath(s string) bool {
	if s == "" {
		return false
	}
	return !cmd.CheckIllegal(s)
}

// ValidShellArgs reports whether every value can be safely interpolated into
// a bash -c command: each must be non-empty and free of shell metacharacters
// (see cmd.CheckIllegal, which rejects &, |, ;, $, quotes, backticks,
// parentheses, redirections and newlines). It is applied to every
// user-controlled value before a shell archiver command is built; secrets
// are covered as well because a single quote would break the openssl -k
// quoting.
func ValidShellArgs(values ...string) bool {
	for _, v := range values {
		if !ValidPath(v) {
			return false
		}
	}
	return true
}

// SanitizeFilename validates an uploaded file name and returns a safe
// basename. Empty names, "." and "..", absolute paths, and names containing
// path separators ("/" or "\") are rejected to prevent path traversal
// attacks on file upload.
func SanitizeFilename(name string) (string, error) {
	if name == "" || name == "." || name == ".." {
		return "", buserr.New(constant.ErrCmdIllegal)
	}
	if strings.ContainsAny(name, `/\`) {
		return "", buserr.New(constant.ErrCmdIllegal)
	}
	base := filepath.Base(name)
	if base == "." || base == ".." || base != name {
		return "", buserr.New(constant.ErrCmdIllegal)
	}
	return base, nil
}

func (f FileOp) ChownR(dst string, uid string, gid string, sub bool) error {
	if !ValidUserGroup(uid) || !ValidUserGroup(gid) {
		return buserr.New(constant.ErrCmdIllegal)
	}
	if !ValidPath(dst) {
		return buserr.New(constant.ErrCmdIllegal)
	}
	cmdStr := fmt.Sprintf(`chown %s:%s '%s'`, uid, gid, dst)
	if sub {
		cmdStr = fmt.Sprintf(`chown -R %s:%s '%s'`, uid, gid, dst)
	}
	if cmd.HasNoPasswordSudo() {
		cmdStr = fmt.Sprintf("sudo %s", cmdStr)
	}
	if msg, err := cmd.ExecWithTimeOut(cmdStr, 10*time.Second); err != nil {
		if msg != "" {
			return errors.New(msg)
		}
		return err
	}
	return nil
}

func (f FileOp) ChmodR(dst string, mode int64, sub bool) error {
	if !ValidPath(dst) {
		return buserr.New(constant.ErrCmdIllegal)
	}
	cmdStr := fmt.Sprintf(`chmod %v '%s'`, fmt.Sprintf("%04o", mode), dst)
	if sub {
		cmdStr = fmt.Sprintf(`chmod -R %v '%s'`, fmt.Sprintf("%04o", mode), dst)
	}
	if cmd.HasNoPasswordSudo() {
		cmdStr = fmt.Sprintf("sudo %s", cmdStr)
	}
	if msg, err := cmd.ExecWithTimeOut(cmdStr, 10*time.Second); err != nil {
		if msg != "" {
			return errors.New(msg)
		}
		return err
	}
	return nil
}

func (f FileOp) ChmodRWithMode(dst string, mode fs.FileMode, sub bool) error {
	if !ValidPath(dst) {
		return buserr.New(constant.ErrCmdIllegal)
	}
	cmdStr := fmt.Sprintf(`chmod %v '%s'`, fmt.Sprintf("%o", mode.Perm()), dst)
	if sub {
		cmdStr = fmt.Sprintf(`chmod -R %v '%s'`, fmt.Sprintf("%o", mode.Perm()), dst)
	}
	if cmd.HasNoPasswordSudo() {
		cmdStr = fmt.Sprintf("sudo %s", cmdStr)
	}
	if msg, err := cmd.ExecWithTimeOut(cmdStr, 10*time.Second); err != nil {
		if msg != "" {
			return errors.New(msg)
		}
		return err
	}
	return nil
}

func (f FileOp) Rename(oldName string, newName string) error {
	return f.Fs.Rename(oldName, newName)
}

type WriteCounter struct {
	Total   uint64
	Written uint64
	Key     string
	Name    string
}

type Process struct {
	Total   uint64  `json:"total"`
	Written uint64  `json:"written"`
	Percent float64 `json:"percent"`
	Name    string  `json:"name"`
}

func (w *WriteCounter) Write(p []byte) (n int, err error) {
	n = len(p)
	w.Written += uint64(n)
	w.SaveProcess()
	return n, nil
}

func (w *WriteCounter) SaveProcess() {
	percentValue := 0.0
	if w.Total > 0 {
		percent := float64(w.Written) / float64(w.Total) * 100
		percentValue, _ = strconv.ParseFloat(fmt.Sprintf("%.2f", percent), 64)
	}
	process := Process{
		Total:   w.Total,
		Written: w.Written,
		Percent: percentValue,
		Name:    w.Name,
	}
	by, _ := json.Marshal(process)
	if percentValue < 100 {
		if err := global.CACHE.Set(w.Key, string(by)); err != nil {
			global.LOG.Errorf("save cache error, err %s", err.Error())
		}
	} else {
		if err := global.CACHE.SetWithTTL(w.Key, string(by), time.Second*time.Duration(10)); err != nil {
			global.LOG.Errorf("save cache error, err %s", err.Error())
		}
	}
}

// downloadMaxSize caps the size of files fetched through
// DownloadFileWithProcess (512MB, the same limit as file uploads) so a
// misbehaving or malicious remote server cannot exhaust local disk space.
// It is a variable so tests can override it with a smaller value.
var downloadMaxSize = int64(512 << 20)

// validateDownloadURL guards DownloadFileWithProcess against SSRF: only
// http/https URLs whose host resolves to a public address are accepted.
// It is a variable so tests can relax it for local httptest servers.
var validateDownloadURL = http2.ValidatePublicURL

// validateDownloadRedirectURL re-validates every redirect target of
// DownloadFileWithProcess: the scheme must stay http/https and the new host
// must again resolve to a public address, so a public URL cannot be used as a
// trampoline into the internal network via a 302.
// It is a variable so tests can relax it for local httptest servers.
var validateDownloadRedirectURL = http2.ValidatePublicURL

// errSSRFAddressRejected marks connections the download dialer refused because
// the resolved address is loopback/private/link-local/reserved. The entry
// check (validateDownloadURL) and this per-connection check share the same
// verdict function (http2.IsPublicIP), so a rejection at this layer means the
// address flipped between the two DNS resolutions (DNS rebinding) or a
// redirect slipped past the per-hop check.
var errSSRFAddressRejected = errors.New("download target resolves to an internal or reserved address")

// verifyDownloadIP vets the already-resolved IP of each new connection; it is
// a variable so tests running against loopback httptest servers can relax it.
var verifyDownloadIP = func(host string) error {
	ip := net.ParseIP(host)
	if !http2.IsPublicIP(ip) {
		return fmt.Errorf("%w: %s", errSSRFAddressRejected, host)
	}
	return nil
}

// ssrfGuardedTransport returns an http.Transport whose Control hook vets the
// already-resolved IP of every new connection right before the connect syscall
// runs, leaving no window between the check and the actual connect. A hostile
// DNS answer that flips the record to an internal address (169.254.169.254,
// 127.0.0.1, ...) after the entry check is refused here, before any byte is
// sent. The control hook runs on every dialed connection including redirect
// hops, since those are plain new connections too.
func ssrfGuardedTransport(insecureTLS bool) *http.Transport {
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   60 * time.Second,
			KeepAlive: 60 * time.Second,
			Control: func(network, address string, c syscall.RawConn) error {
				host, _, err := net.SplitHostPort(address)
				if err != nil {
					return err
				}
				return verifyDownloadIP(host)
			},
		}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
		IdleConnTimeout:       15 * time.Second,
	}
	if insecureTLS {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return transport
}

func (f FileOp) DownloadFileWithProcess(url, dst, key string, ignoreCertificate bool) error {
	if err := validateDownloadURL(url); err != nil {
		return err
	}
	client := &http.Client{
		Timeout:   constant.TimeOut5m * time.Second,
		Transport: ssrfGuardedTransport(ignoreCertificate),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// every hop is a fresh request to a possibly different (and
			// possibly hostile) host: re-run the full entry check on the new
			// URL, scheme included, and abort the chain on failure. The
			// returned error must carry the validator verdict at its cause so
			// callers can errors.Is against it even after net/http wraps
			// CheckRedirect errors in *url.Error.
			if err := validateDownloadRedirectURL(req.URL.String()); err != nil {
				global.LOG.Errorf("download redirect to [%s] blocked, err %s", req.URL, err.Error())
				return fmt.Errorf("blocked redirect to %s: %w", req.URL, err)
			}
			return nil
		},
	}
	request, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Accept-Encoding", "identity")
	resp, err := client.Do(request)
	if err != nil {
		global.LOG.Errorf("get download file [%s] error, err %s", dst, err.Error())
		return err
	}
	defer resp.Body.Close()
	out, err := os.Create(dst)
	if err != nil {
		global.LOG.Errorf("create download file [%s] error, err %s", dst, err.Error())
		return err
	}
	defer out.Close()

	counter := &WriteCounter{}
	counter.Key = key
	if resp.ContentLength > 0 {
		counter.Total = uint64(resp.ContentLength)
	}
	counter.Name = filepath.Base(dst)
	written, err := io.Copy(out, io.TeeReader(io.LimitReader(resp.Body, downloadMaxSize+1), counter))
	if err != nil {
		global.LOG.Errorf("save download file [%s] error, err %s", dst, err.Error())
		_ = os.Remove(dst)
		return err
	}
	if written > downloadMaxSize {
		_ = out.Close()
		_ = os.Remove(dst)
		return fmt.Errorf("download exceeds size limit (%d bytes)", downloadMaxSize)
	}

	value, err := global.CACHE.Get(counter.Key)
	if err != nil {
		global.LOG.Errorf("get cache error,err %s", err.Error())
		return nil
	}
	process := &Process{}
	_ = json.Unmarshal(value, process)
	process.Percent = 100
	process.Name = counter.Name
	process.Total = process.Written
	by, _ := json.Marshal(process)
	if err := global.CACHE.SetWithTTL(counter.Key, string(by), time.Second*time.Duration(10)); err != nil {
		global.LOG.Errorf("save cache error, err %s", err.Error())
	}
	return nil
}

func (f FileOp) DownloadFile(url, dst string) error {
	resp, err := http2.GetHttpRes(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	out, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("create download file [%s] error, err %s", dst, err.Error())
	}
	defer out.Close()

	if _, err = io.Copy(out, resp.Body); err != nil {
		return fmt.Errorf("save download file [%s] error, err %s", dst, err.Error())
	}
	return nil
}

func (f FileOp) DownloadFileWithProxy(url, dst string) error {
	_, resp, err := http2.HandleGet(url, http.MethodGet, constant.TimeOut5m)
	if err != nil {
		return err
	}

	out, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("create download file [%s] error, err %s", dst, err.Error())
	}
	defer out.Close()

	reader := bytes.NewReader(resp)
	if _, err = io.Copy(out, reader); err != nil {
		return fmt.Errorf("save download file [%s] error, err %s", dst, err.Error())
	}
	return nil
}

func (f FileOp) Cut(oldPaths []string, dst, name string, cover bool) error {
	if len(oldPaths) == 0 {
		return nil
	}
	// every oldPath plus the computed destination is interpolated into the
	// mv fallback command below, so all of them must be free of shell
	// metacharacters
	values := make([]string, 0, len(oldPaths)+2)
	values = append(values, oldPaths...)
	values = append(values, dst)
	if name != "" {
		values = append(values, name)
	}
	if !ValidShellArgs(values...) {
		return buserr.New(constant.ErrCmdIllegal)
	}
	var dstPath string
	coverFlag := ""
	if name != "" {
		dstPath = filepath.Join(dst, name)
		if f.Stat(dstPath) {
			dstPath = dst
		}
		if cover {
			coverFlag = "-f"
		}
	} else {
		dstPath = dst
		coverFlag = "-f"
	}

	// Cut removes the entries at oldPaths and creates them at dstPath, so a
	// TOCTOU flip by a concurrent rename between the service-layer validation
	// and this execution point would move data into (or out of) a protected
	// directory. Re-check every source and the effective destination right
	// before the move; the window shrinks to the rename syscall itself.
	//
	// The destination must be re-derived from the same logic as above because
	// the effective target switches to dst when the joined path already
	// exists. isProtectedPathMulti is injectable: package files cannot import
	// app/service (import cycle), so production wiring is done via
	// SetCutProtectedPathCheck by the service layer at init time.
	if f.cutProtectedPathCheck != nil {
		targets := append([]string{dstPath}, oldPaths...)
		if f.cutProtectedPathCheck(targets...) {
			return buserr.New(constant.ErrPathNotDelete)
		}
	}

	// Preferred path: rename(2) is atomic, keeps attributes (same inode) and
	// needs no shell, removing the bash dependency entirely for the common
	// same-filesystem case. Per-source fallback keeps the original multi-path
	// semantics: each entry is moved (and overwritten with cover) exactly as
	// "mv [coverFlag] <oldPaths...> <dstPath>" would do. Cross-device moves
	// (EXDEV) fall back to the original shell mv, which copies+removes across
	// filesystems — os.Rename cannot.
	//
	// Target derivation, mirroring mv's argument semantics:
	//   - dstPath is an existing directory  -> sources land INSIDE it, i.e.
	//     target = dstPath/<base> ("mv a b dstDir/" moves both under dstDir)
	//   - otherwise (single source rename-with-new-name, or overwrite) the
	//     target IS dstPath
	movedAny := false
	shellFallback := false
	dstPathIsDir := false
	if info, err := f.Fs.Stat(dstPath); err == nil && info.IsDir() {
		dstPathIsDir = true
	}
	for _, p := range oldPaths {
		target := dstPath
		if dstPathIsDir {
			target = filepath.Join(dstPath, filepath.Base(p))
		}
		if err := f.Fs.Rename(p, target); err != nil {
			if errors.Is(err, syscall.EXDEV) {
				shellFallback = true
				break
			}
			return err
		}
		movedAny = true
	}
	if movedAny && !shellFallback {
		return nil
	}
	if shellFallback {
		// one of the sources lives on another filesystem; redo the whole
		// batch with mv, which handles cross-device moves. Sources already
		// moved by rename are gone, so mv must only see the remainder —
		// simplest correct behavior: let mv operate on the originals of the
		// remaining sources by passing the full original list minus the moved
		// ones. To keep the original call contract (single mv for all paths,
		// preserving multi-source semantics with existing tests), fall back
		// only for the sources that failed with EXDEV.
		var remaining []string
		for _, p := range oldPaths {
			if f.Stat(p) {
				remaining = append(remaining, p)
			}
		}
		if len(remaining) == 0 {
			return nil
		}
		oldPaths = remaining
	}
	var quotedPaths []string
	for _, p := range oldPaths {
		quotedPaths = append(quotedPaths, fmt.Sprintf("'%s'", p))
	}
	mvCommand := fmt.Sprintf("mv %s %s '%s'", coverFlag, strings.Join(quotedPaths, " "), dstPath)
	if err := cmd.ExecCmd(mvCommand); err != nil {
		return err
	}
	return nil
}

func (f FileOp) Mv(oldPath, dstPath string) error {
	if !ValidShellArgs(oldPath, dstPath) {
		return buserr.New(constant.ErrCmdIllegal)
	}
	cmdStr := fmt.Sprintf(`mv '%s' '%s'`, oldPath, dstPath)
	if err := cmd.ExecCmd(cmdStr); err != nil {
		return err
	}
	return nil
}

func (f FileOp) Copy(src, dst string) error {
	if src = path.Clean("/" + src); src == "" {
		return os.ErrNotExist
	}
	if dst = path.Clean("/" + dst); dst == "" {
		return os.ErrNotExist
	}
	if src == "/" || dst == "/" {
		return os.ErrInvalid
	}
	if dst == src {
		return os.ErrInvalid
	}
	info, err := f.Fs.Stat(src)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return f.CopyDir(src, dst)
	}
	return f.CopyFile(src, dst)
}

func (f FileOp) CopyAndReName(src, dst, name string, cover bool) error {
	if src = path.Clean("/" + src); src == "" {
		return os.ErrNotExist
	}
	if dst = path.Clean("/" + dst); dst == "" {
		return os.ErrNotExist
	}
	if src == "/" || dst == "/" {
		return os.ErrInvalid
	}
	if dst == src {
		return os.ErrInvalid
	}

	// src, dst and the rename target are interpolated into the cp commands
	// below, so they must be free of shell metacharacters
	if !ValidShellArgs(src, dst) || (name != "" && !ValidPath(name)) {
		return buserr.New(constant.ErrCmdIllegal)
	}

	srcInfo, err := f.Fs.Stat(src)
	if err != nil {
		return err
	}

	if srcInfo.IsDir() {
		dstPath := dst
		if name != "" && !cover {
			dstPath = filepath.Join(dst, name)
		}
		return cmd.ExecCmd(fmt.Sprintf(`cp -rf '%s' '%s'`, src, dstPath))
	} else {
		dstPath := filepath.Join(dst, name)
		if cover {
			dstPath = dst
		}
		return cmd.ExecCmd(fmt.Sprintf(`cp -f '%s' '%s'`, src, dstPath))
	}
}

func (f FileOp) CopyDir(src, dst string) error {
	if !ValidShellArgs(src, dst) {
		return buserr.New(constant.ErrCmdIllegal)
	}
	srcInfo, err := f.Fs.Stat(src)
	if err != nil {
		return err
	}
	dstDir := filepath.Join(dst, srcInfo.Name())
	if err = f.Fs.MkdirAll(dstDir, srcInfo.Mode()); err != nil {
		return err
	}
	return cmd.ExecCmd(fmt.Sprintf(`cp -rf '%s' '%s'`, src, dst+"/"))
}

func (f FileOp) CopyFile(src, dst string) error {
	if !ValidShellArgs(src, dst) {
		return buserr.New(constant.ErrCmdIllegal)
	}
	dst = filepath.Clean(dst) + string(filepath.Separator)
	return cmd.ExecCmd(fmt.Sprintf(`cp -f '%s' '%s'`, src, dst+"/"))
}

func (f FileOp) GetDirSize(path string) (float64, error) {
	var size int64
	err := filepath.Walk(path, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			size += info.Size()
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return float64(size), nil
}

func getFormat(cType CompressType) archiver.CompressedArchive {
	format := archiver.CompressedArchive{}
	switch cType {
	case Tar:
		format.Archival = archiver.Tar{}
	case TarGz, Gz:
		format.Compression = archiver.Gz{}
		format.Archival = archiver.Tar{}
	case SdkTarGz:
		format.Compression = archiver.Gz{}
		format.Archival = archiver.Tar{}
	case SdkZip, Zip:
		format.Archival = archiver.Zip{
			Compression: zip.Deflate,
		}
	case Bz2:
		format.Compression = archiver.Bz2{}
		format.Archival = archiver.Tar{}
	case Xz:
		format.Compression = archiver.Xz{}
		format.Archival = archiver.Tar{}
	}
	return format
}

func (f FileOp) Compress(srcRiles []string, dst string, name string, cType CompressType, secret string) error {
	format := getFormat(cType)

	fileMaps := make(map[string]string, len(srcRiles))
	for _, s := range srcRiles {
		base := filepath.Base(s)
		fileMaps[s] = base
	}

	if !f.Stat(dst) {
		_ = f.CreateDir(dst, 0755)
	}

	files, err := archiver.FilesFromDisk(nil, fileMaps)
	if err != nil {
		return err
	}
	dstFile := filepath.Join(dst, name)
	out, err := f.Fs.Create(dstFile)
	if err != nil {
		return err
	}

	switch cType {
	case Zip:
		if err := ZipFile(files, out); err == nil {
			return nil
		}
		_ = f.DeleteFile(dstFile)
		return NewZipArchiver().Compress(srcRiles, dstFile, "")
	case TarGz:
		err = NewTarGzArchiver().Compress(srcRiles, dstFile, secret)
		if err != nil {
			_ = f.DeleteFile(dstFile)
			return err
		}
	default:
		err = format.Archive(context.Background(), out, files)
		if err != nil {
			_ = f.DeleteFile(dstFile)
			return err
		}
	}
	return nil
}

func isIgnoreFile(name string) bool {
	return strings.HasPrefix(name, "__MACOSX") || strings.HasSuffix(name, ".DS_Store") || strings.HasPrefix(name, "._")
}

func decodeGBK(input string) (string, error) {
	decoder := simplifiedchinese.GBK.NewDecoder()
	decoded, _, err := transform.String(decoder, input)
	if err != nil {
		return "", err
	}
	return decoded, nil
}

// decompressMaxEntries and decompressMaxTotalSize guard against zip bomb
// archives: at most 100000 entries and 4GB of total uncompressed content may
// be written out (the 512MB file upload limit and the commonly several
// hundred MB backups/application packages leave plenty of headroom below the
// 4GB cap).
//
// decompressMaxDepth caps how deeply archive entries may nest below the
// extraction destination. A hostile archive can otherwise force the creation
// of a very deep directory chain (a/b/c/... thousands of levels), which costs
// one path traversal and inode per level and grows the on-disk path toward
// PATH_MAX. Legitimate backups and application packages stay far below 64
// levels, so the cap is purely defensive.
const (
	decompressMaxEntries   = 100000
	decompressMaxTotalSize = 4 * 1024 * 1024 * 1024
	decompressMaxDepth     = 64
)

// errUnsafeArchive marks archive validation failures. Callers must not fall
// back to an extractor that does not enforce the same member checks.
var errUnsafeArchive = errors.New("unsafe archive")

// checkArchivePath verifies that an entry name extracted from an archive stays
// inside dst. Absolute paths, paths containing ".." components, entries that
// resolve to the destination itself ("." or any name folding to it) and
// symbolic link entries are rejected to prevent path traversal, takeover of
// dst itself and symlink escapes.
//
// A leading "./" is intentionally not checked on the raw name: filepath.Clean
// normalizes it away, so "./sub/a.txt" folds to "sub/a.txt" and any unsafe
// shape that relies on the "./" prefix ("./.", "./..", "./../x") folds to
// ".", ".." or "../x", all of which the cleanName checks below already reject.
// Legitimate archives created with "tar -cf x.tar ./src" or "zip -r x.zip ."
// carry such entries and must keep working.
func checkArchivePath(fileName string, info fs.FileInfo) error {
	if info != nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: archive entry is a symlink: %s", errUnsafeArchive, fileName)
	}
	slashName := filepath.FromSlash(fileName)
	cleanName := filepath.Clean(slashName)
	if cleanName == "." || cleanName == ".." ||
		strings.HasPrefix(cleanName, "."+string(filepath.Separator)) ||
		strings.HasPrefix(cleanName, ".."+string(filepath.Separator)) ||
		filepath.IsAbs(cleanName) {
		return fmt.Errorf("%w: invalid archive entry path: %s", errUnsafeArchive, fileName)
	}
	// A ".." component anywhere in the raw name would be folded away by
	// filepath.Clean/Join, letting an entry silently resolve to a different
	// path inside dst (e.g. "a/../b" -> dst/b); reject it outright.
	for _, comp := range strings.Split(slashName, string(filepath.Separator)) {
		if comp == ".." {
			return fmt.Errorf("%w: invalid archive entry path: %s", errUnsafeArchive, fileName)
		}
	}
	return nil
}

func archiveEntryPath(dst, fileName string, info fs.FileInfo, linkTarget string) (string, error) {
	if err := checkArchivePath(fileName, info); err != nil {
		return "", err
	}
	if linkTarget != "" {
		return "", fmt.Errorf("%w: archive entry is a link: %s", errUnsafeArchive, fileName)
	}
	filePath := filepath.Join(dst, filepath.Clean(filepath.FromSlash(fileName)))
	// Double check the joined path still lies strictly inside dst. The ".."
	// component checks above guarantee filepath.Join cannot fold the entry
	// onto dst itself or outside of it, so a plain prefix check suffices.
	cleanDst := filepath.Clean(dst)
	if !strings.HasPrefix(filePath, cleanDst+string(filepath.Separator)) {
		return "", fmt.Errorf("%w: archive entry escapes destination: %s", errUnsafeArchive, fileName)
	}
	// Belt and braces: the resolved path must stay strictly inside cleanDst
	// with no remaining ".." components relative to it.
	rel, err := filepath.Rel(cleanDst, filePath)
	if err != nil ||
		rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", fmt.Errorf("%w: archive entry escapes destination: %s", errUnsafeArchive, fileName)
	}
	// Depth cap: entries nested more than decompressMaxDepth levels below dst
	// are rejected so a hostile archive cannot force an unboundedly deep
	// directory chain. The relative path is clean at this point, so counting
	// separators is exact (a file directly inside dst has depth 0).
	if depth := strings.Count(rel, string(filepath.Separator)); depth > decompressMaxDepth {
		return "", fmt.Errorf("%w: archive entry too deep (limit %d levels): %s", errUnsafeArchive, decompressMaxDepth, fileName)
	}
	return filePath, nil
}

// archiveEntryName returns the entry name to extract, decoding GBK zip names
// that are not marked UTF-8. A name containing a NUL byte cannot be opened
// (os.OpenFile fails with EINVAL on it), so it is reported with a skip
// sentinel error instead: the entry is dropped and extraction continues.
// Decoding failures are NOT skipped — a corrupt GBK name means the archive is
// malformed and the whole extraction aborts, matching the pre-existing
// behavior.
func archiveEntryName(archFile archiver.File) (string, error) {
	fileName := archFile.NameInArchive
	if header, ok := archFile.Header.(cZip.FileHeader); ok {
		if header.NonUTF8 && header.Flags == 0 {
			decoded, err := decodeGBK(fileName)
			if err != nil {
				return "", err
			}
			fileName = decoded
		}
	}
	if strings.ContainsRune(fileName, '\x00') {
		return "", fmt.Errorf("%w: archive entry name contains a NUL byte: %q", errUnsafeArchive, fileName)
	}
	return fileName, nil
}

// sanitizedEntryMode strips the setuid/setgid/sticky bits from an
// archive-supplied mode so extraction can never leave a privileged file
// behind: those bits have no meaning for freshly created backup-restore files
// (executability is carried by the remaining permission bits, which are
// preserved, subject to the process umask like every other extraction).
func sanitizedEntryMode(mode os.FileMode) os.FileMode {
	return mode &^ os.ModeSetuid &^ os.ModeSetgid &^ os.ModeSticky
}

// isArchiveRootEntry reports whether a directory entry is the archive root
// itself, stored as "./" by "tar -cf x.tar .", "zip -r x.zip ." and similar
// tooling. Such an entry folds onto dst itself: it carries nothing to
// extract, and creating it could chmod dst with an attacker-controlled mode,
// so the handlers skip it before any path validation. A bare "." or "./."
// entry is NOT skipped here — those are rejected by checkArchivePath.
func isArchiveRootEntry(archFile archiver.File) bool {
	name := filepath.FromSlash(archFile.NameInArchive)
	if !strings.HasSuffix(name, string(filepath.Separator)) {
		return false
	}
	return filepath.Clean(name) == "."
}

func (f FileOp) decompressWithSDK(srcFile string, dst string, cType CompressType) error {
	return f.decompressWithSDKWithLimits(srcFile, dst, cType, decompressMaxEntries, decompressMaxTotalSize)
}

func (f FileOp) decompressWithSDKWithLimits(srcFile string, dst string, cType CompressType, maxEntries int, maxTotalSize int64) error {
	format := getFormat(cType)
	var totalSize int64
	var totalEntries int
	handler := func(ctx context.Context, archFile archiver.File) error {
		info := archFile.FileInfo
		if isIgnoreFile(archFile.Name()) {
			return nil
		}
		if isArchiveRootEntry(archFile) {
			return nil
		}
		fileName, err := archiveEntryName(archFile)
		if err != nil {
			if errors.Is(err, errUnsafeArchive) {
				// a name the OS cannot materialize (embedded NUL) — skip the
				// entry rather than abort the whole extraction
				return nil
			}
			return err
		}
		filePath, err := archiveEntryPath(dst, fileName, archFile.FileInfo, archFile.LinkTarget)
		if err != nil {
			return err
		}
		totalEntries++
		if totalEntries > maxEntries {
			return fmt.Errorf("%w: archive contains too many entries (limit %d): %s", errUnsafeArchive, maxEntries, fileName)
		}
		mode := sanitizedEntryMode(info.Mode())
		if archFile.FileInfo.IsDir() {
			if err := f.Fs.MkdirAll(filePath, mode); err != nil {
				return err
			}
			return nil
		} else {
			parentDir := path.Dir(filePath)
			if !f.Stat(parentDir) {
				if err := f.Fs.MkdirAll(parentDir, mode); err != nil {
					return err
				}
			}
		}
		remaining := maxTotalSize - totalSize
		if remaining <= 0 {
			return fmt.Errorf("%w: archive total size exceeds limit (%d bytes)", errUnsafeArchive, maxTotalSize)
		}
		fr, err := archFile.Open()
		if err != nil {
			return err
		}
		defer fr.Close()
		fw, err := f.Fs.OpenFile(filePath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, mode)
		if err != nil {
			return err
		}
		defer fw.Close()
		written, err := io.Copy(fw, io.LimitReader(fr, remaining))
		if err != nil {
			return err
		}
		totalSize += written
		if written == remaining {
			// the entry may continue beyond the remaining budget, read one
			// more byte to detect it without writing unbounded content
			var probe [1]byte
			if n, _ := fr.Read(probe[:]); n > 0 {
				return fmt.Errorf("%w: archive total size exceeds limit (%d bytes)", errUnsafeArchive, maxTotalSize)
			}
		}

		return nil
	}
	input, err := f.Fs.Open(srcFile)
	if err != nil {
		return err
	}
	return format.Extract(context.Background(), input, nil, handler)
}

// validateArchiveWithSDK checks an already-decompressed archive without
// writing it. It is used before the encrypted-archive compatibility fallback
// so the shell extractor never receives an unvalidated member list.
func (f FileOp) validateArchiveWithSDK(srcFile string, dst string, cType CompressType) error {
	format := getFormat(cType)
	var totalSize int64
	var totalEntries int
	handler := func(ctx context.Context, archFile archiver.File) error {
		if isIgnoreFile(archFile.Name()) {
			return nil
		}
		if isArchiveRootEntry(archFile) {
			return nil
		}
		fileName, err := archiveEntryName(archFile)
		if err != nil {
			if errors.Is(err, errUnsafeArchive) {
				// mirror the extractor: NUL-named entries are skipped, not fatal
				return nil
			}
			return err
		}
		if _, err := archiveEntryPath(dst, fileName, archFile.FileInfo, archFile.LinkTarget); err != nil {
			return err
		}
		totalEntries++
		if totalEntries > decompressMaxEntries {
			return fmt.Errorf("%w: archive contains too many entries (limit %d): %s", errUnsafeArchive, decompressMaxEntries, fileName)
		}
		if !archFile.FileInfo.IsDir() && archFile.FileInfo.Size() > 0 {
			if archFile.FileInfo.Size() > decompressMaxTotalSize-totalSize {
				return fmt.Errorf("%w: archive total size exceeds limit (%d bytes)", errUnsafeArchive, decompressMaxTotalSize)
			}
			totalSize += archFile.FileInfo.Size()
		}
		return nil
	}
	input, err := f.Fs.Open(srcFile)
	if err != nil {
		return err
	}
	defer input.Close()
	return format.Extract(context.Background(), input, nil, handler)
}

func decryptTarGz(srcFile, secret string) (string, error) {
	tmpFile, err := os.CreateTemp("", "1panel-decompress-*.tar.gz")
	if err != nil {
		return "", err
	}
	tmpPath := tmpFile.Name()
	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return "", err
	}

	decrypt, passReader, err := buildDecryptCmd(srcFile, tmpPath, secret)
	if err != nil {
		_ = os.Remove(tmpPath)
		return "", err
	}
	defer passReader.Close()
	if output, err := decrypt.CombinedOutput(); err != nil {
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("decrypt archive: %v, output: %s", err, output)
	}
	return tmpPath, nil
}

// buildDecryptCmd builds the openssl command that decrypts a backup archive
// into tmpPath. The secret is handed to openssl through file descriptor 3
// (cmd.ExtraFiles starts at fd 3) via -pass fd:3 instead of -k, so it never
// appears in the process cmdline (/proc/<pid>/cmdline). The write end of the
// pipe is closed by cmd.SecretPassReader before it returns; the caller must
// close the returned read end once the command has finished.
func buildDecryptCmd(srcFile, tmpPath, secret string) (*exec.Cmd, *os.File, error) {
	passReader, err := cmd.SecretPassReader(secret)
	if err != nil {
		return nil, nil, err
	}
	decrypt := exec.Command("openssl", "enc", "-d", "-aes-256-cbc", "-pass", "fd:3", "-in", srcFile, "-out", tmpPath)
	decrypt.ExtraFiles = []*os.File{passReader}
	return decrypt, passReader, nil
}

func (f FileOp) Decompress(srcFile string, dst string, cType CompressType, secret string) error {
	if cType == Tar || cType == Zip || cType == TarGz {
		if !ValidShellArgs(srcFile, dst) || (cType == TarGz && len(secret) != 0 && !ValidShellArgs(secret)) {
			return buserr.New(constant.ErrCmdIllegal)
		}
		if !f.Stat(dst) {
			_ = f.CreateDir(dst, 0755)
		}
		sdkErr := f.decompressWithSDK(srcFile, dst, cType)
		if sdkErr == nil {
			return nil
		}
		if errors.Is(sdkErr, errUnsafeArchive) {
			return sdkErr
		}
		// A plain archive, a malformed archive, and every SDK safety failure
		// must not reach a less restrictive extractor. The only compatibility
		// path is an encrypted tar.gz: decrypt it first, validate all members
		// with the SDK, and only then use the existing shell extractor.
		if cType != TarGz || len(secret) == 0 {
			return sdkErr
		}
		decryptedPath, err := decryptTarGz(srcFile, secret)
		if err != nil {
			return fmt.Errorf("decrypt backup archive failed: %w", err)
		}
		defer os.Remove(decryptedPath)
		if err := f.validateArchiveWithSDK(decryptedPath, dst, TarGz); err != nil {
			return err
		}
		if shellArchiver, err := NewShellArchiver(TarGz); err == nil {
			return shellArchiver.Extract(decryptedPath, dst, "")
		}
		return sdkErr
	}
	return f.decompressWithSDK(srcFile, dst, cType)
}

func ZipFile(files []archiver.File, dst afero.File) error {
	zw := zip.NewWriter(dst)
	defer zw.Close()

	for _, file := range files {
		hdr, err := zip.FileInfoHeader(file)
		if err != nil {
			return err
		}
		hdr.Method = zip.Deflate
		hdr.Name = file.NameInArchive
		if file.IsDir() {
			if !strings.HasSuffix(hdr.Name, "/") {
				hdr.Name += "/"
			}
		}
		w, err := zw.CreateHeader(hdr)
		if err != nil {
			return err
		}
		if file.IsDir() {
			continue
		}

		if file.LinkTarget != "" {
			_, err = w.Write([]byte(filepath.ToSlash(file.LinkTarget)))
			if err != nil {
				return err
			}
		} else {
			fileReader, err := file.Open()
			if err != nil {
				return err
			}
			_, err = io.Copy(w, fileReader)
			if err != nil {
				return err
			}
		}
	}
	return nil
}
