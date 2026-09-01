package files

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	http2 "github.com/1Panel-dev/1Panel/backend/utils/http"
)

// http2IsPublicIP aliases the shared verdict function for redirect tests.
var http2IsPublicIP = http2.IsPublicIP

// TestDownloadDialerRejectsLoopback proves the download transport refuses to
// even open a TCP connection toward a loopback/private address: the Control
// hook runs after DNS resolution but before connect, so a hostile DNS answer
// flipping a public name onto an internal address is stopped with
// errSSRFAddressRejected. No server is needed — the dial must fail with the
// SSRF error before any byte can flow.
func TestDownloadDialerRejectsLoopback(t *testing.T) {
	transport := ssrfGuardedTransport(false)
	addr := "127.0.0.1:1" // loopback, and port 1 refuses even without the guard
	_, err := transport.DialContext(t.Context(), "tcp", addr)
	if err == nil {
		t.Fatal("dial to 127.0.0.1 should be rejected by the SSRF guard")
	}
	if !errors.Is(err, errSSRFAddressRejected) {
		t.Fatalf("expected errSSRFAddressRejected, got: %v", err)
	}

	// same verdict for a link-local metadata address; the connect itself can
	// never happen because the guard fires first
	for _, host := range []string{"169.254.169.254", "10.0.0.1", "192.168.1.1"} {
		_, err := transport.DialContext(t.Context(), "tcp", net.JoinHostPort(host, "80"))
		if !errors.Is(err, errSSRFAddressRejected) {
			t.Fatalf("dial to %s: expected errSSRFAddressRejected, got: %v", host, err)
		}
	}
}

// TestDownloadDialerAllowlistBypassCanary documents that the per-connection
// guard and the entry check share one verdict function: if the shared table
// ever drifts (e.g. loopback reclassified as public), this test fails.
func TestDownloadDialerAllowlistBypassCanary(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1", "169.254.169.254", "10.0.0.1", "fc00::1"} {
		if err := verifyDownloadIP(host); err == nil {
			t.Fatalf("verifyDownloadIP(%s) accepted an internal address", host)
		}
	}
}

// errBlockedRedirectSentinel is installed as validateDownloadRedirectURL in
// the redirect tests so assertions can match the exact guard error even after
// http.Client wraps it in *url.Error.
var errBlockedRedirectSentinel = errors.New("blocked redirect sentinel")

// TestDownloadRedirectToInternalBlocked starts a real httptest server that
// redirects to internal addresses and proves CheckRedirect aborts the chain:
// the client must surface the blocked-redirect error and never write a file.
func TestDownloadRedirectToInternalBlocked(t *testing.T) {
	usePermissiveDownloadURL(t) // the loopback httptest start URL must pass entry+IP checks

	internalTargets := []string{
		"http://127.0.0.1:1/x",
		"http://169.254.169.254/latest/meta-data/",
		"http://10.0.0.1/",
	}
	for _, target := range internalTargets {
		t.Run(target, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, target, http.StatusFound)
			}))
			defer srv.Close()

			// relax only the scheme-agnostic lookup part: the redirected host
			// names are literal IPs here, so the real validator would reject
			// them anyway; the sentinel makes the block source unambiguous
			orig := validateDownloadRedirectURL
			validateDownloadRedirectURL = func(raw string) error {
				u, err := url.Parse(raw)
				if err != nil {
					return err
				}
				host := u.Hostname()
				ip := net.ParseIP(host)
				if ip != nil && !http2IsPublicIP(ip) {
					return errBlockedRedirectSentinel
				}
				return nil
			}
			t.Cleanup(func() { validateDownloadRedirectURL = orig })

			dst := filepath.Join(t.TempDir(), "redirect.txt")
			fo := NewFileOp()
			err := fo.DownloadFileWithProcess(srv.URL+"/start", dst, "file-wget-test-redirect", false)
			if err == nil {
				t.Fatalf("redirect to %s must be blocked", target)
			}
			// net/http wraps CheckRedirect errors in *url.Error; the sentinel
			// must survive as the cause, and the wrapped message must name the
			// blocked target
			if !errors.Is(err, errBlockedRedirectSentinel) {
				t.Fatalf("expected blocked-redirect sentinel as cause, got: %v", err)
			}
			if !strings.Contains(err.Error(), "blocked redirect to "+target) {
				t.Fatalf("expected blocked-redirect message naming the target, got: %v", err)
			}
			if _, statErr := os.Stat(dst); !os.IsNotExist(statErr) {
				t.Fatalf("blocked download must not leave a file behind: %v", statErr)
			}
		})
	}
}

// TestDownloadRedirectToLoopbackServerBlocked covers the realistic variant:
// the redirect target is a second local httptest server (a live loopback
// endpoint that would happily serve data). CheckRedirect must stop the chain
// before that endpoint is ever contacted.
func TestDownloadRedirectToLoopbackServerBlocked(t *testing.T) {
	usePermissiveDownloadURL(t) // start URL and both servers are loopback httptest

	secret := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("internal secret"))
	}))
	defer secret.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, secret.URL+"/flag", http.StatusFound)
	}))
	defer srv.Close()

	orig := validateDownloadRedirectURL
	validateDownloadRedirectURL = func(raw string) error {
		u, err := url.Parse(raw)
		if err != nil {
			return err
		}
		host := u.Hostname()
		ip := net.ParseIP(host)
		if ip != nil && !http2IsPublicIP(ip) {
			return errBlockedRedirectSentinel
		}
		return nil
	}
	t.Cleanup(func() { validateDownloadRedirectURL = orig })

	dst := filepath.Join(t.TempDir(), "redirect2.txt")
	fo := NewFileOp()
	err := fo.DownloadFileWithProcess(srv.URL+"/start", dst, "file-wget-test-redirect2", false)
	if err == nil || !errors.Is(err, errBlockedRedirectSentinel) {
		t.Fatalf("redirect to loopback server must be blocked, got: %v", err)
	}
	if _, statErr := os.Stat(dst); !os.IsNotExist(statErr) {
		t.Fatalf("blocked download must not leave a file behind: %v", statErr)
	}
}

// TestDownloadRedirectToPublicFollowed proves the guard does not break
// legitimate redirect chains: a 302 between two loopback servers succeeds
// while the per-hop URL check is relaxed, and the redirected payload is
// written in full.
func TestDownloadRedirectToPublicFollowed(t *testing.T) {
	usePermissiveDownloadURL(t) // start URL and final URL are loopback httptest
	orig := validateDownloadRedirectURL
	validateDownloadRedirectURL = func(raw string) error { return nil }
	t.Cleanup(func() { validateDownloadRedirectURL = orig })

	final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("after redirect"))
	}))
	defer final.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, final.URL+"/real", http.StatusFound)
	}))
	defer srv.Close()

	dst := filepath.Join(t.TempDir(), "followed.txt")
	fo := NewFileOp()
	if err := fo.DownloadFileWithProcess(srv.URL+"/start", dst, "file-wget-test-followed", false); err != nil {
		t.Fatalf("legitimate redirect should be followed: %v", err)
	}
	data, err := os.ReadFile(dst)
	if err != nil || string(data) != "after redirect" {
		t.Fatalf("redirected payload mismatch: %q, err: %v", string(data), err)
	}
}

// TestValidateDownloadRedirectURLRejectsNonHTTP ensures the per-hop validator
// enforces the scheme constraint exactly like the entry validator: a redirect
// to a non-http(s) scheme is refused. (Go's client additionally refuses such
// redirects itself, but the guard must not be the weak link.) The scheme rule
// for the download entry point is already covered by
// TestDownloadFileWithProcessSSRF's "file scheme" case through the same
// ValidatePublicURL implementation.
func TestValidateDownloadRedirectURLRejectsNonHTTP(t *testing.T) {
	if err := validateDownloadRedirectURL("file:///etc/passwd"); err == nil {
		t.Fatal("redirect target with file:// scheme must be rejected")
	}
	if err := validateDownloadRedirectURL("ftp://example.invalid/x"); err == nil {
		t.Fatal("redirect target with ftp:// scheme must be rejected")
	}
}
