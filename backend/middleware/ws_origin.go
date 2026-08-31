package middleware

import (
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/1Panel-dev/1Panel/backend/global"
)

// CheckWSOrigin verifies the Origin header of a WebSocket upgrade request.
// Requests without an Origin header (non-browser clients such as curl,
// websocat or internal tools) are allowed, since they cannot carry the
// session cookie of a victim in a cross-site attack.
// Requests with an Origin header are only allowed when the origin host and
// port match the request Host. The comparison includes the port: when either
// side omits the port, the scheme default is applied (http/ws -> 80,
// https/wss -> 443), so origins on the same host but a different port are
// rejected to prevent Cross-Site WebSocket Hijacking. Hosts are compared as
// plain strings (no DNS resolution), so IPs and domain names are treated
// alike.
func CheckWSOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	originURL, err := url.Parse(origin)
	if err != nil || originURL.Host == "" {
		global.LOG.Warnf("reject websocket upgrade from invalid origin %s, host %s", origin, r.Host)
		return false
	}
	originHost, originPort := splitHostPort(originURL.Host, schemeDefaultPort(originURL.Scheme))
	reqHost, reqPort := splitHostPort(r.Host, requestDefaultPort(r))
	if originHost == reqHost && originPort == reqPort {
		return true
	}
	global.LOG.Warnf("reject websocket upgrade from origin %s, host %s", origin, r.Host)
	return false
}

// schemeDefaultPort returns the default port of a URL scheme, or an empty
// string for schemes without a well-known default port.
func schemeDefaultPort(scheme string) string {
	switch scheme {
	case "http", "ws":
		return "80"
	case "https", "wss":
		return "443"
	default:
		return ""
	}
}

// requestDefaultPort returns the default port of the incoming request based
// on its transport: https/wss -> 443, otherwise http/ws -> 80.
func requestDefaultPort(r *http.Request) string {
	if r.TLS != nil {
		return "443"
	}
	return "80"
}

// splitHostPort splits a host:port pair into host and port, falling back to
// defaultPort when no port is present. It tolerates IPv6 literals with or
// without brackets.
func splitHostPort(hostPort, defaultPort string) (string, string) {
	if host, port, err := net.SplitHostPort(hostPort); err == nil {
		return host, port
	}
	return strings.Trim(strings.TrimSpace(hostPort), "[]"), defaultPort
}
