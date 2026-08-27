package middleware

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/1Panel-dev/1Panel/backend/global"
)

// CheckWSOrigin verifies the Origin header of a WebSocket upgrade request.
// Requests without an Origin header (non-browser clients such as curl,
// websocat or internal tools) are allowed, since they cannot carry the
// session cookie of a victim in a cross-site attack.
// Requests with an Origin header are only allowed when the origin host
// matches the request Host, otherwise the upgrade is rejected to prevent
// Cross-Site WebSocket Hijacking.
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
	if getHost(originURL.Host) == getHost(r.Host) {
		return true
	}
	global.LOG.Warnf("reject websocket upgrade from origin %s, host %s", origin, r.Host)
	return false
}

func getHost(host string) string {
	parts := strings.Split(host, ":")
	if len(parts) > 0 {
		return parts[0]
	}
	return host
}
