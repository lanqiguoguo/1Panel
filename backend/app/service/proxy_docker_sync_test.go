package service

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/app/dto"
)

// ---- dockerProxySyncAction: the sync state machine ----

// TestDockerProxySyncAction covers the four states of the panel proxy ->
// Docker daemon.json sync machine:
//   - sync on  + proxy configured -> write the proxies object
//   - sync on  + proxy disabled   -> remove the key (the whole proxy is off)
//   - sync off + previously on    -> remove the key (uncheck after a sync)
//   - sync off + previously off   -> no-op (daemon.json left untouched)
func TestDockerProxySyncAction(t *testing.T) {
	const noProxyIP = "127.0.0.0/8,::1"

	tests := []struct {
		name     string
		prevSync string
		newSync  string
		proxyURL string
		apply    bool
		proxies  map[string]interface{}
	}{
		{
			name:     "enable with proxy writes http/https/no-proxy",
			prevSync: "false",
			newSync:  "true",
			proxyURL: "http://10.0.0.1:8888",
			apply:    true,
			proxies: map[string]interface{}{
				"http-proxy":  "http://10.0.0.1:8888",
				"https-proxy": "http://10.0.0.1:8888",
				"no-proxy":    noProxyIP,
			},
		},
		{
			name:     "socks5 URL goes into http-proxy (dockerd rejects socks5-proxy key)",
			prevSync: "false",
			newSync:  "true",
			proxyURL: "socks5://10.0.0.1:1080",
			apply:    true,
			proxies: map[string]interface{}{
				"http-proxy":  "socks5://10.0.0.1:1080",
				"https-proxy": "socks5://10.0.0.1:1080",
				"no-proxy":    noProxyIP,
			},
		},
		{
			name:     "enable with disabled proxy removes the key",
			prevSync: "false",
			newSync:  "true",
			proxyURL: "",
			apply:    true,
			proxies:  nil,
		},
		{
			name:     "uncheck after a previous sync removes the key",
			prevSync: "true",
			newSync:  "false",
			proxyURL: "http://10.0.0.1:8888",
			apply:    true,
			proxies:  nil,
		},
		{
			name:     "off after off is a no-op",
			prevSync: "false",
			newSync:  "false",
			proxyURL: "http://10.0.0.1:8888",
			apply:    false,
			proxies:  nil,
		},
		{
			name:     "off with disabled proxy is a no-op",
			prevSync: "false",
			newSync:  "false",
			proxyURL: "",
			apply:    false,
			proxies:  nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proxies, apply := dockerProxySyncAction(tt.prevSync, tt.newSync, tt.proxyURL)
			if apply != tt.apply {
				t.Errorf("apply = %v, want %v", apply, tt.apply)
			}
			if tt.apply && len(proxies) != len(tt.proxies) {
				t.Fatalf("proxies = %v, want %v", proxies, tt.proxies)
			}
			for k, want := range tt.proxies {
				if proxies[k] != want {
					t.Errorf("proxies[%s] = %v, want %v", k, proxies[k], want)
				}
			}
		})
	}
}

// ---- buildProxyURL: the URL written into the daemon config ----

func TestBuildProxyURLForDaemonWrite(t *testing.T) {
	tests := []struct {
		name      string
		proxyType string
		addr      string
		port      string
		user      string
		pass      string
		want      string
	}{
		{name: "http without user", proxyType: "http", addr: "127.0.0.1", port: "8888", want: "http://127.0.0.1:8888"},
		{name: "socks5 with user", proxyType: "socks5", addr: "10.0.0.1", port: "1080", user: "u", pass: "p", want: "socks5://u:p@10.0.0.1:1080"},
		{name: "https with port", proxyType: "https", addr: "proxy.corp.example", port: "3128", want: "https://proxy.corp.example:3128"},
		{name: "no port keeps bare host", proxyType: "http", addr: "10.0.0.9", want: "http://10.0.0.9"},
		{name: "userinfo special chars are escaped", proxyType: "http", addr: "10.0.0.1", port: "8080", user: "u", pass: "p@ss:1", want: "http://u:p%40ss%3A1@10.0.0.1:8080"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := buildProxyURL(tt.proxyType, tt.addr, tt.port, tt.user, tt.pass)
			if err != nil {
				t.Fatalf("buildProxyURL failed: %v", err)
			}
			if u == nil {
				t.Fatal("buildProxyURL returned nil, want URL")
			}
			if u.String() != tt.want {
				t.Errorf("buildProxyURL = %q, want %q", u.String(), tt.want)
			}
		})
	}

	// empty type + empty address means "proxy disabled" -> no URL for the daemon
	if u, err := buildProxyURL("", "", "", "", ""); err != nil || u != nil {
		t.Errorf("buildProxyURL(disabled) = %v, %v; want nil, nil", u, err)
	}
}

// ---- writeDaemonJsonProxies: merge / remove semantics on daemon.json ----

// TestWriteDaemonJsonProxiesMerge verifies the "proxies" key is added while
// every other existing key of daemon.json is preserved bit-for-bit.
func TestWriteDaemonJsonProxiesMerge(t *testing.T) {
	file := filepath.Join(t.TempDir(), "docker", "daemon.json")
	if err := os.MkdirAll(filepath.Dir(file), 0755); err != nil {
		t.Fatal(err)
	}
	original := "{\n\t\"registry-mirrors\": [\n\t\t\"https://mirror.example.com\"\n\t],\n\t\"live-restore\": false\n}"
	if err := os.WriteFile(file, []byte(original), 0640); err != nil {
		t.Fatal(err)
	}

	proxies := map[string]interface{}{
		"http-proxy":  "http://127.0.0.1:8888",
		"https-proxy": "http://127.0.0.1:8888",
		"no-proxy":    "127.0.0.0/8,::1",
	}
	if err := writeDaemonJsonProxies(file, proxies); err != nil {
		t.Fatalf("writeDaemonJsonProxies failed: %v", err)
	}

	content, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]interface{}
	if err := json.Unmarshal(content, &got); err != nil {
		t.Fatalf("resulting daemon.json is not valid JSON: %v\n%s", err, content)
	}
	if want := []interface{}{"https://mirror.example.com"}; !jsonEqual(got["registry-mirrors"], want) {
		t.Errorf("registry-mirrors = %v, want %v", got["registry-mirrors"], want)
	}
	if got["live-restore"] != false {
		t.Errorf("live-restore = %v, want false", got["live-restore"])
	}
	proxiesGot, ok := got["proxies"].(map[string]interface{})
	if !ok {
		t.Fatalf("proxies key missing or not an object: %v", got["proxies"])
	}
	for k, want := range proxies {
		if proxiesGot[k] != want {
			t.Errorf("proxies[%s] = %v, want %v", k, proxiesGot[k], want)
		}
	}

	info, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0640 {
		t.Errorf("daemon.json mode = %v, want 0640", info.Mode().Perm())
	}
}

// TestWriteDaemonJsonProxiesAbsentFile verifies an absent daemon.json (the
// common case on a fresh host) is created with only the proxies key.
func TestWriteDaemonJsonProxiesAbsentFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "docker", "daemon.json") // parent dir missing on purpose

	proxies := map[string]interface{}{"http-proxy": "http://10.0.0.1:8888"}
	if err := writeDaemonJsonProxies(file, proxies); err != nil {
		t.Fatalf("writeDaemonJsonProxies on absent file failed: %v", err)
	}

	content, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("daemon.json was not created: %v", err)
	}
	var got map[string]interface{}
	if err := json.Unmarshal(content, &got); err != nil {
		t.Fatalf("created daemon.json is not valid JSON: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("created daemon.json = %v, want only the proxies key", got)
	}
}

// TestWriteDaemonJsonProxiesRemove verifies removing the "proxies" key keeps
// every other key intact, and that an empty resulting config removes the file
// (the UpdateConf convention, leaving the host at its pre-feature state).
func TestWriteDaemonJsonProxiesRemove(t *testing.T) {
	t.Run("other keys survive the removal", func(t *testing.T) {
		file := filepath.Join(t.TempDir(), "daemon.json")
		original := map[string]interface{}{
			"proxies":         map[string]interface{}{"http-proxy": "http://10.0.0.1:8888"},
			"registry-mirrors": []string{"https://mirror.example.com"},
		}
		raw, _ := json.MarshalIndent(original, "", "\t")
		if err := os.WriteFile(file, raw, 0640); err != nil {
			t.Fatal(err)
		}

		if err := writeDaemonJsonProxies(file, nil); err != nil {
			t.Fatalf("writeDaemonJsonProxies(nil) failed: %v", err)
		}
		content, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("daemon.json should still exist: %v", err)
		}
		var got map[string]interface{}
		if err := json.Unmarshal(content, &got); err != nil {
			t.Fatal(err)
		}
		if _, ok := got["proxies"]; ok {
			t.Error("proxies key was not removed")
		}
		if want := []interface{}{"https://mirror.example.com"}; !jsonEqual(got["registry-mirrors"], want) {
			t.Errorf("registry-mirrors = %v, want %v", got["registry-mirrors"], want)
		}
	})

	t.Run("empty config removes the file", func(t *testing.T) {
		file := filepath.Join(t.TempDir(), "daemon.json")
		if err := os.WriteFile(file, []byte(`{"proxies":{"http-proxy":"http://10.0.0.1:8888"}}`), 0640); err != nil {
			t.Fatal(err)
		}
		if err := writeDaemonJsonProxies(file, nil); err != nil {
			t.Fatalf("writeDaemonJsonProxies(nil) failed: %v", err)
		}
		if _, err := os.Stat(file); !os.IsNotExist(err) {
			t.Errorf("daemon.json should have been removed, stat err = %v", err)
		}
	})
}

// TestWriteDaemonJsonProxiesCorruptFile verifies a parse error on the existing
// file surfaces instead of silently truncating the host's daemon config.
func TestWriteDaemonJsonProxiesCorruptFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "daemon.json")
	if err := os.WriteFile(file, []byte("not json"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := writeDaemonJsonProxies(file, map[string]interface{}{"http-proxy": "x"}); err == nil {
		t.Fatal("writeDaemonJsonProxies on a corrupt file succeeded, want error")
	}
}

// ---- backup / restore: the rollback file handling ----

// TestDaemonJsonBackupRestoreRoundTrip verifies the backup captures the
// previous content and restore writes it back byte-for-byte.
func TestDaemonJsonBackupRestoreRoundTrip(t *testing.T) {
	file := filepath.Join(t.TempDir(), "daemon.json")
	original := []byte(`{"registry-mirrors":["https://mirror.example.com"],"live-restore":false}`)
	if err := os.WriteFile(file, original, 0640); err != nil {
		t.Fatal(err)
	}

	backup, err := backupDaemonJson(file)
	if err != nil {
		t.Fatalf("backupDaemonJson failed: %v", err)
	}
	if !backup.Existed {
		t.Error("backup.Existed = false, want true")
	}

	// simulate a failed sync write that corrupted the config
	if err := os.WriteFile(file, []byte(`{"proxies":{"http-proxy":"http://bad"}}`), 0640); err != nil {
		t.Fatal(err)
	}
	if err := restoreDaemonJson(file, backup); err != nil {
		t.Fatalf("restoreDaemonJson failed: %v", err)
	}
	got, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(original) {
		t.Errorf("restored content = %q, want original %q", got, original)
	}
}

// TestDaemonJsonBackupRestoreAbsentFile verifies the "did not exist" case:
// restore removes the file so the host returns to its original state.
func TestDaemonJsonBackupRestoreAbsentFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "daemon.json")

	backup, err := backupDaemonJson(file)
	if err != nil {
		t.Fatalf("backupDaemonJson on absent file failed: %v", err)
	}
	if backup.Existed {
		t.Error("backup.Existed = true for an absent file, want false")
	}
	if backup.Content != nil {
		t.Errorf("backup.Content = %q, want empty", backup.Content)
	}

	if err := os.WriteFile(file, []byte(`{"proxies":{"http-proxy":"http://10.0.0.1:8888"}}`), 0640); err != nil {
		t.Fatal(err)
	}
	if err := restoreDaemonJson(file, backup); err != nil {
		t.Fatalf("restoreDaemonJson failed: %v", err)
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Errorf("daemon.json should have been removed by the restore, stat err = %v", err)
	}
}

// ---- UpdateProxy round-trip: ProxyDockerSync persistence ----

// TestUpdateProxyDockerSyncRoundTrip covers the persisted ProxyDockerSync
// setting through UpdateProxy. Only the "false" -> "false" (and garbage ->
// "false" normalization) paths run here: any "true" submission triggers the
// real daemon.json write + docker restart, which is environment-bound and
// covered by the live E2E on the dev host.
func TestUpdateProxyDockerSyncRoundTrip(t *testing.T) {
	setupProxyUpdateTest(t)
	u := &SettingService{}

	err := u.UpdateProxy(dto.ProxyUpdate{
		ProxyType:       "http",
		ProxyUrl:        "10.0.0.1",
		ProxyPort:       "8888",
		ProxyDockerSync: "false",
	})
	if err != nil {
		t.Fatalf("UpdateProxy with sync=false failed: %v", err)
	}
	if got := proxySettingValue(t, "ProxyDockerSync"); got != "false" {
		t.Errorf("ProxyDockerSync = %q, want false", got)
	}

	// anything but "true" normalizes to "false" and never touches daemon.json
	err = u.UpdateProxy(dto.ProxyUpdate{
		ProxyType:       "http",
		ProxyUrl:        "10.0.0.1",
		ProxyPort:       "8888",
		ProxyDockerSync: "garbage",
	})
	if err != nil {
		t.Fatalf("UpdateProxy with a garbage sync flag failed: %v", err)
	}
	if got := proxySettingValue(t, "ProxyDockerSync"); got != "false" {
		t.Errorf("ProxyDockerSync after garbage flag = %q, want false", got)
	}
}

// jsonEqual compares decoded JSON values (arrays come back as []interface{}).
func jsonEqual(got interface{}, want interface{}) bool {
	rawGot, errGot := json.Marshal(got)
	rawWant, errWant := json.Marshal(want)
	if errGot != nil || errWant != nil {
		return false
	}
	return string(rawGot) == string(rawWant)
}
