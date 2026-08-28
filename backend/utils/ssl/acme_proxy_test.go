package ssl

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	httpUtil "github.com/1Panel-dev/1Panel/backend/utils/http"
)

// proxyResolutionString renders a proxy resolution result for comparison,
// with nil (direct connection) mapped to the empty string.
func proxyResolutionString(u *url.URL, err error) (string, error) {
	if err != nil {
		return "", err
	}
	if u == nil {
		return "", nil
	}
	return u.String(), nil
}

// TestNewConfigHTTPClientHonorsPanelProxy verifies that the lego config built
// by newConfig carries an HTTP client backed by the unified panel transport:
// an external host must resolve to the proxy configured via httpUtil.SetProxyURL,
// while loopback requests always stay direct.
func TestNewConfigHTTPClientHonorsPanelProxy(t *testing.T) {
	proxyURL, err := url.Parse("http://10.0.0.1:8888")
	if err != nil {
		t.Fatalf("parse proxy url failed: %v", err)
	}
	httpUtil.SetProxyURL(proxyURL)
	t.Cleanup(func() { httpUtil.SetProxyURL(nil) })

	config := newConfig(&AcmeUser{Email: "test@example.com"}, "letsencrypt")
	if config.HTTPClient == nil {
		t.Fatal("newConfig must set a non-nil HTTPClient")
	}
	if config.HTTPClient.Timeout != 2*time.Minute {
		t.Errorf("HTTPClient.Timeout = %v, want %v", config.HTTPClient.Timeout, 2*time.Minute)
	}
	transport, ok := config.HTTPClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("HTTPClient.Transport type = %T, want *http.Transport from panel http util", config.HTTPClient.Transport)
	}

	externalReq, err := http.NewRequest(http.MethodGet, "https://example.com/directory", nil)
	if err != nil {
		t.Fatalf("build external request failed: %v", err)
	}
	got, err := transport.Proxy(externalReq)
	if err != nil {
		t.Fatalf("resolve proxy for external host failed: %v", err)
	}
	if got != proxyURL {
		t.Errorf("proxy for https://example.com = %v, want configured panel proxy %v", got, proxyURL)
	}

	loopbackReq, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:8080/ping", nil)
	if err != nil {
		t.Fatalf("build loopback request failed: %v", err)
	}
	got, err = transport.Proxy(loopbackReq)
	if err != nil {
		t.Fatalf("resolve proxy for loopback host failed: %v", err)
	}
	if got != nil {
		t.Errorf("proxy for http://127.0.0.1:8080 = %v, want nil", got)
	}
}

// TestNewConfigHTTPClientWithoutPanelProxy verifies that with no proxy
// configured the transport falls back to the standard environment variables,
// exactly like http.ProxyFromEnvironment would.
func TestNewConfigHTTPClientWithoutPanelProxy(t *testing.T) {
	httpUtil.SetProxyURL(nil)
	t.Cleanup(func() { httpUtil.SetProxyURL(nil) })

	config := newConfig(&AcmeUser{Email: "test@example.com"}, "letsencrypt")
	transport, ok := config.HTTPClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("HTTPClient.Transport type = %T, want *http.Transport from panel http util", config.HTTPClient.Transport)
	}

	req, err := http.NewRequest(http.MethodGet, "https://example.com/directory", nil)
	if err != nil {
		t.Fatalf("build request failed: %v", err)
	}
	got, err := transport.Proxy(req)
	want, wantErr := http.ProxyFromEnvironment(req)
	gotStr, gotErr := proxyResolutionString(got, err)
	wantStr, _ := proxyResolutionString(want, wantErr)
	if gotErr != nil {
		t.Fatalf("resolve proxy failed: %v", gotErr)
	}
	if gotStr != wantStr {
		t.Errorf("proxy without panel settings = %q, want environment behavior %q", gotStr, wantStr)
	}
}

// TestNewACMEHTTPClient verifies the shared ACME client used by both the
// lego config and the ZeroSSL EAB credential fetch.
func TestNewACMEHTTPClient(t *testing.T) {
	client := newACMEHTTPClient()
	if client.Timeout != 2*time.Minute {
		t.Errorf("Timeout = %v, want %v", client.Timeout, 2*time.Minute)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport type = %T, want *http.Transport from panel http util", client.Transport)
	}
	if transport.ResponseHeaderTimeout != 30*time.Second {
		t.Errorf("ResponseHeaderTimeout = %v, want %v", transport.ResponseHeaderTimeout, 30*time.Second)
	}
	if transport.TLSHandshakeTimeout != 30*time.Second {
		t.Errorf("TLSHandshakeTimeout = %v, want %v", transport.TLSHandshakeTimeout, 30*time.Second)
	}
}

// TestNewTransportWithTimeouts verifies that the parameterized transport
// variant honors the requested timeouts.
func TestNewTransportWithTimeouts(t *testing.T) {
	transport := httpUtil.NewTransportWith(45*time.Second, 12*time.Second)
	if transport.ResponseHeaderTimeout != 45*time.Second {
		t.Errorf("ResponseHeaderTimeout = %v, want %v", transport.ResponseHeaderTimeout, 45*time.Second)
	}
	if transport.TLSHandshakeTimeout != 12*time.Second {
		t.Errorf("TLSHandshakeTimeout = %v, want %v", transport.TLSHandshakeTimeout, 12*time.Second)
	}
}

// TestNewTransportDefaultTimeoutsUnchanged guards the existing callers: the
// parameterless constructor must keep its original timeout values.
func TestNewTransportDefaultTimeoutsUnchanged(t *testing.T) {
	transport := httpUtil.NewTransport()
	if transport.ResponseHeaderTimeout != 10*time.Second {
		t.Errorf("ResponseHeaderTimeout = %v, want %v", transport.ResponseHeaderTimeout, 10*time.Second)
	}
	if transport.TLSHandshakeTimeout != 5*time.Second {
		t.Errorf("TLSHandshakeTimeout = %v, want %v", transport.TLSHandshakeTimeout, 5*time.Second)
	}
}
