package service

import (
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/app/dto"
)

// TestMaskProxyCredentials is the regression test for the credential leak in
// TestProxy: buildProxyURL injects user:password via url.UserPassword and
// resolveProxyPassword may bring in the decrypted password from the settings
// table, so any *url.Error that embeds the proxy URL (u.String() renders the
// plaintext credentials) must be masked before it reaches the caller.
func TestMaskProxyCredentials(t *testing.T) {
	u, err := buildProxyURL("http", "proxy.internal", "8080", "alice", "s3cret-pw")
	if err != nil {
		t.Fatalf("buildProxyURL failed: %v", err)
	}
	if u.User.String() != "alice:s3cret-pw" {
		t.Fatalf("unexpected userinfo %q in the built proxy URL", u.User.String())
	}

	// the realistic leak shape: *url.Error carries the full proxy URL with
	// plaintext credentials in its message
	leak := &url.Error{Op: "Head", URL: u.String(), Err: errors.New("connection refused")}
	masked := maskProxyCredentials(leak, u)
	text := masked.Error()
	if strings.Contains(text, "s3cret-pw") {
		t.Errorf("masked error still contains the plaintext password: %q", text)
	}
	if !strings.Contains(text, "***@") {
		t.Errorf("masked error does not contain the ***@ mask: %q", text)
	}
	if strings.Contains(text, "alice") {
		t.Errorf("masked error still contains the proxy user: %q", text)
	}

	// every other branch must pass through untouched
	plain := errors.New("plain failure")
	if got := maskProxyCredentials(plain, u); got != plain {
		t.Errorf("error without embedded credentials was rewritten: %v", got)
	}
	if got := maskProxyCredentials(leak, nil); got != leak {
		t.Errorf("nil proxy URL must return the error unchanged, got %v", got)
	}
}

// TestProxyErrorNeverContainsPassword drives the real TestProxy against a
// closed local proxy port and asserts the returned error text never carries
// the proxy password, whatever branch produced the error.
func TestProxyErrorNeverContainsPassword(t *testing.T) {
	req := dto.ProxyUpdate{
		ProxyType:   "http",
		ProxyUrl:    "127.0.0.1",
		ProxyPort:   "1",
		ProxyUser:   "alice",
		ProxyPasswd: "s3cret-pw",
	}
	_, err := (&SettingService{}).TestProxy(req)
	if err == nil {
		t.Fatal("TestProxy against a closed proxy port succeeded unexpectedly")
	}
	if text := err.Error(); strings.Contains(text, "s3cret-pw") {
		t.Errorf("TestProxy error text leaks the proxy password: %q", text)
	}
}
