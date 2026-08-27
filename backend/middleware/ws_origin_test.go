package middleware

import (
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
		want   bool
	}{
		{
			name: "no origin header",
			host: "192.168.1.1:8090",
			want: true,
		},
		{
			name:   "origin host matches host",
			origin: "http://192.168.1.1:8090",
			host:   "192.168.1.1:8090",
			want:   true,
		},
		{
			name:   "origin host matches host ignoring port",
			origin: "https://example.com:8443",
			host:   "example.com",
			want:   true,
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
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			if got := CheckWSOrigin(req); got != tt.want {
				t.Fatalf("CheckWSOrigin(origin=%q, host=%q) = %v, want %v", tt.origin, tt.host, got, tt.want)
			}
		})
	}
}
