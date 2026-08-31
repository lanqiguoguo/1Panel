package middleware

import (
	"crypto/tls"
	"net/http"
	"os"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/global"

	"github.com/sirupsen/logrus"
)

func TestMain(m *testing.M) {
	global.LOG = logrus.New()
	os.Exit(m.Run())
}

func TestCheckWSOrigin(t *testing.T) {
	tests := []struct {
		name   string
		origin string
		host   string
		tls    bool
		want   bool
	}{
		{
			name: "no origin header",
			host: "192.168.1.1:8090",
			want: true,
		},
		{
			name:   "origin host and port match host",
			origin: "http://192.168.1.1:8090",
			host:   "192.168.1.1:8090",
			want:   true,
		},
		{
			name:   "origin without port matches host on default http port",
			origin: "http://1.2.3.4",
			host:   "1.2.3.4:80",
			want:   true,
		},
		{
			name:   "origin with explicit default http port matches host without port",
			origin: "http://1.2.3.4:80",
			host:   "1.2.3.4",
			want:   true,
		},
		{
			name:   "https origin without port matches wss host without port",
			origin: "https://panel.example.com",
			host:   "panel.example.com",
			tls:    true,
			want:   true,
		},
		{
			name:   "https origin with explicit default port matches wss host without port",
			origin: "https://panel.example.com:443",
			host:   "panel.example.com",
			tls:    true,
			want:   true,
		},
		{
			name:   "origin host matches but port differs is rejected",
			origin: "https://example.com:8443",
			host:   "example.com",
			want:   false,
		},
		{
			name:   "same ip different port is rejected",
			origin: "http://192.168.1.1:80",
			host:   "192.168.1.1:28547",
			want:   false,
		},
		{
			name:   "origin without port rejected on non default host port",
			origin: "http://1.2.3.4",
			host:   "1.2.3.4:28547",
			want:   false,
		},
		{
			name:   "http origin rejected on wss host without port",
			origin: "http://panel.example.com",
			host:   "panel.example.com",
			tls:    true,
			want:   false,
		},
		{
			name:   "origin host differs from host",
			origin: "http://evil.example.com",
			host:   "192.168.1.1:8090",
			want:   false,
		},
		{
			name:   "origin is invalid url",
			origin: "://invalid",
			host:   "192.168.1.1:8090",
			want:   false,
		},
		{
			name:   "origin scheme only",
			origin: "http://",
			host:   "192.168.1.1:8090",
			want:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, "http://"+tt.host, nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Host = tt.host
			if tt.tls {
				req.TLS = &tls.ConnectionState{}
			}
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			if got := CheckWSOrigin(req); got != tt.want {
				t.Fatalf("CheckWSOrigin(origin=%q, host=%q) = %v, want %v", tt.origin, tt.host, got, tt.want)
			}
		})
	}
}
