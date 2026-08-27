package service

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/1Panel-dev/1Panel/backend/app/dto"
	"github.com/1Panel-dev/1Panel/backend/app/model"
	"github.com/1Panel-dev/1Panel/backend/global"
	http2 "github.com/1Panel-dev/1Panel/backend/utils/http"
	"github.com/sirupsen/logrus"
)

func TestShouldSkipIconDownload(t *testing.T) {
	tests := []struct {
		name         string
		app          model.App
		lastModified int
		want         bool
	}{
		{
			name:         "new app without icon must be downloaded",
			app:          model.App{Icon: ""},
			lastModified: 100,
			want:         false,
		},
		{
			name:         "existing icon with same lastModified is kept",
			app:          model.App{Icon: "icon-bytes", LastModified: 100},
			lastModified: 100,
			want:         true,
		},
		{
			name:         "existing icon with changed lastModified is downloaded",
			app:          model.App{Icon: "icon-bytes", LastModified: 100},
			lastModified: 200,
			want:         false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldSkipIconDownload(tt.app, tt.lastModified); got != tt.want {
				t.Errorf("shouldSkipIconDownload() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDownloadAppAssetsConcurrency(t *testing.T) {
	global.LOG = logrus.New()
	var mu sync.Mutex
	inflight, maxInflight := 0, 0
	// sized beyond the total request count so the handler never blocks
	finished := make(chan struct{}, 64)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		inflight++
		if inflight > maxInflight {
			maxInflight = inflight
		}
		mu.Unlock()
		time.Sleep(100 * time.Millisecond)
		mu.Lock()
		inflight--
		mu.Unlock()
		w.Write([]byte("data"))
		finished <- struct{}{}
	}))
	defer server.Close()

	var apps []dto.AppDefine
	for i := 0; i < 20; i++ {
		key := fmt.Sprintf("app-%d", i)
		apps = append(apps, dto.AppDefine{
			AppProperty: dto.AppProperty{Key: key, Type: "runtime"},
			Icon:        server.URL + "/icon/" + key,
			Versions: []dto.AppConfigVersion{
				{Name: "1.0", AppForm: map[string]interface{}{}},
			},
		})
	}

	start := time.Now()
	iconMap, composeMap := downloadAppAssets(apps, []model.App{}, server.URL, "1.0.0", http2.NewTransport(), func(string) error { return nil })
	elapsed := time.Since(start)
	mu.Lock()
	m := maxInflight
	mu.Unlock()

	// 20 icons + 20 compose files with 8 workers take at least 40 requests / 8
	// workers * 100ms = 500ms when the pool is actually bounded.
	if elapsed < 500*time.Millisecond {
		t.Errorf("downloads finished in %v, the concurrency limit is not in effect", elapsed)
	}
	if m > appAssetsConcurrency {
		t.Errorf("max inflight requests = %d, want <= %d", m, appAssetsConcurrency)
	}
	if len(iconMap) != len(apps) || len(composeMap) != len(apps) {
		t.Fatalf("iconMap = %d, composeMap = %d, want both %d", len(iconMap), len(composeMap), len(apps))
	}
	for i := 0; i < len(apps); i++ {
		if iconMap[fmt.Sprintf("app-%d", i)] == "" {
			t.Errorf("icon of app-%d missing", i)
		}
		if composeMap[fmt.Sprintf("app-%d", i)]["1.0"] != "data" {
			t.Errorf("compose of app-%d missing", i)
		}
	}
}

func TestDownloadAppAssets(t *testing.T) {
	global.LOG = logrus.New()
	iconContent := []byte("fake-icon-bytes")
	composeContent := []byte("services:\n  app:\n    image: nginx\n")

	var mu sync.Mutex
	requests := make(map[string]int)
	mux := http.NewServeMux()
	serve := func(path string, content []byte) {
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			requests[r.URL.Path]++
			mu.Unlock()
			w.Write(content)
		})
	}
	serve("/icon/", iconContent)
	serve("/mysql/8.0/docker-compose.yml", composeContent)
	serve("/nginx/1.25/docker-compose.yml", composeContent)
	mux.HandleFunc("/broken/", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	iconURL := func(key string) string {
		return fmt.Sprintf("%s/icon/%s.png", server.URL, key)
	}

	tests := []struct {
		name        string
		apps        []dto.AppDefine
		oldApps     []model.App
		systemVer   string
		wantIcons   map[string]string
		wantCompose map[string]map[string]string
	}{
		{
			name: "basic concurrent downloads",
			apps: []dto.AppDefine{
				{
					AppProperty: dto.AppProperty{Key: "mysql", Type: "runtime"},
					Icon:        iconURL("mysql"),
					Versions: []dto.AppConfigVersion{
						{Name: "8.0", AppForm: map[string]interface{}{}},
					},
				},
				{
					AppProperty: dto.AppProperty{Key: "nginx", Type: "app"},
					Icon:        iconURL("nginx"),
					Versions: []dto.AppConfigVersion{
						{Name: "1.25", AppForm: map[string]interface{}{}},
					},
				},
			},
			wantIcons: map[string]string{
				"mysql": base64.StdEncoding.EncodeToString(iconContent),
				"nginx": base64.StdEncoding.EncodeToString(iconContent),
			},
			wantCompose: map[string]map[string]string{
				"mysql": {"8.0": string(composeContent)},
			},
		},
		{
			name: "icon unchanged keeps existing icon",
			apps: []dto.AppDefine{
				{
					AppProperty:  dto.AppProperty{Key: "mysql", Type: "runtime"},
					Icon:         iconURL("mysql"),
					LastModified: 100,
					Versions: []dto.AppConfigVersion{
						{Name: "8.0", AppForm: map[string]interface{}{}},
					},
				},
			},
			oldApps: []model.App{
				{Key: "mysql", Icon: "existing-icon", LastModified: 100},
			},
			wantIcons: map[string]string{},
			wantCompose: map[string]map[string]string{
				"mysql": {"8.0": string(composeContent)},
			},
		},
		{
			name: "icon changed after lastModified is downloaded",
			apps: []dto.AppDefine{
				{
					AppProperty:  dto.AppProperty{Key: "mysql", Type: "runtime"},
					Icon:         iconURL("mysql"),
					LastModified: 200,
					Versions: []dto.AppConfigVersion{
						{Name: "8.0", AppForm: map[string]interface{}{}},
					},
				},
			},
			oldApps: []model.App{
				{Key: "mysql", Icon: "existing-icon", LastModified: 100},
			},
			wantIcons: map[string]string{
				"mysql": base64.StdEncoding.EncodeToString(iconContent),
			},
			wantCompose: map[string]map[string]string{
				"mysql": {"8.0": string(composeContent)},
			},
		},
		{
			name: "failed download skips the failed asset only",
			apps: []dto.AppDefine{
				{
					AppProperty: dto.AppProperty{Key: "mysql", Type: "runtime"},
					Icon:        fmt.Sprintf("%s/broken/icon.png", server.URL),
					Versions: []dto.AppConfigVersion{
						{Name: "8.0", AppForm: map[string]interface{}{}},
					},
				},
				{
					AppProperty: dto.AppProperty{Key: "nginx", Type: "runtime"},
					Icon:        iconURL("nginx"),
					Versions: []dto.AppConfigVersion{
						{Name: "1.25", AppForm: map[string]interface{}{}},
					},
				},
			},
			wantIcons: map[string]string{
				"nginx": base64.StdEncoding.EncodeToString(iconContent),
			},
			wantCompose: map[string]map[string]string{
				"mysql": {"8.0": string(composeContent)},
				"nginx": {"1.25": string(composeContent)},
			},
		},
		{
			name: "version not supported by current panel is filtered out",
			apps: []dto.AppDefine{
				{
					AppProperty: dto.AppProperty{Key: "mysql", Type: "runtime"},
					Icon:        iconURL("mysql"),
					Versions: []dto.AppConfigVersion{
						{Name: "8.0", AppForm: map[string]interface{}{
							"supportVersion": 2.0,
						}},
					},
				},
			},
			systemVer: "1.10.0",
			wantIcons: map[string]string{
				"mysql": base64.StdEncoding.EncodeToString(iconContent),
			},
			wantCompose: map[string]map[string]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := http2.NewTransport()
			// ValidatePublicURL rejects loopback addresses for SSRF protection,
			// so tests use a permissive validator against the local server.
			iconMap, composeMap := downloadAppAssets(tt.apps, tt.oldApps, server.URL, tt.systemVer, transport, func(string) error { return nil })
			if len(iconMap) != len(tt.wantIcons) {
				t.Fatalf("iconMap length = %d, want %d", len(iconMap), len(tt.wantIcons))
			}
			for key, want := range tt.wantIcons {
				if iconMap[key] != want {
					t.Errorf("iconMap[%s] = %q, want %q", key, iconMap[key], want)
				}
			}
			if len(composeMap) != len(tt.wantCompose) {
				t.Fatalf("composeMap length = %d, want %d", len(composeMap), len(tt.wantCompose))
			}
			for key, wantVersions := range tt.wantCompose {
				for version, want := range wantVersions {
					if composeMap[key][version] != want {
						t.Errorf("composeMap[%s][%s] = %q, want %q", key, version, composeMap[key][version], want)
					}
				}
			}
		})
	}
}
