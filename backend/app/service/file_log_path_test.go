package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/app/dto/request"
	"github.com/1Panel-dev/1Panel/backend/constant"
	"github.com/1Panel-dev/1Panel/backend/global"
)

func TestSafeLogPathRejectsPathTraversal(t *testing.T) {
	root := filepath.Join(t.TempDir(), "logs")

	valid := []struct {
		name       string
		components []string
	}{
		{name: "website", components: []string{"example.com", "log", "access.log"}},
		{name: "docker", components: []string{"image_pull_nginx_latest_20260830120000.log"}},
		{name: "ai model", components: []string{"qwen2.5:7b"}},
		{name: "namespaced ai model", components: []string{"library", "qwen2.5:7b"}},
		{name: "mysql", components: []string{"mysql-abc123", "data", "1Panel-slow.log"}},
		{name: "mariadb", components: []string{"mariadb-abc123", "db", "data", "1Panel-slow.log"}},
	}
	for _, tc := range valid {
		t.Run(tc.name, func(t *testing.T) {
			got, err := safeLogPath(root, tc.components...)
			if err != nil {
				t.Fatalf("safeLogPath(%q) unexpected error: %v", tc.components, err)
			}
			if rel, err := filepath.Rel(root, got); err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				t.Fatalf("safeLogPath(%q) escaped root: %q", tc.components, got)
			}
		})
	}

	invalid := []string{
		"../outside",
		"../../etc/passwd",
		"/etc/passwd",
		`..\outside`,
		`C:\Windows\win.ini`,
		"C:passwd",
		`\\server\share\secret`,
		"a/b",
		"a\\b",
		".",
		"..",
		"",
		"bad\x00name",
		"bad\nname",
	}
	for _, name := range invalid {
		t.Run(name, func(t *testing.T) {
			if _, err := safeLogPath(root, name); err == nil {
				t.Fatalf("safeLogPath(%q) returned nil error", name)
			}
		})
	}
}

func TestValidDockerLogName(t *testing.T) {
	cases := map[string]string{
		"image-pull":     "image_pull_nginx_latest_20260830120000.log",
		"image-push":     "image_push_nginx_latest_20260830120000.log",
		"image-build":    "image_build_my-image_20260830120000.log",
		"compose-create": "compose_create_my-project_20260830120000.log",
	}
	for logType, name := range cases {
		if !validDockerLogName(logType, name) {
			t.Errorf("validDockerLogName(%q, %q) = false", logType, name)
		}
	}

	invalid := []struct {
		logType string
		name    string
	}{
		{logType: "image-pull", name: "image_push_nginx_latest_20260830120000.log"},
		{logType: "image-pull", name: "image_pull_nginx_latest.log"},
		{logType: "image-pull", name: "image_pull_nginx_latest_20260830120000.txt"},
		{logType: "image-pull", name: "image_pull_nginx/secret_20260830120000.log"},
	}
	for _, tc := range invalid {
		if validDockerLogName(tc.logType, tc.name) {
			t.Errorf("validDockerLogName(%q, %q) = true", tc.logType, tc.name)
		}
	}
}

func TestReadLogByLineRejectsUnsafeNames(t *testing.T) {
	dataDir := t.TempDir()
	tmpDir := t.TempDir()
	oldDataDir, oldTmpDir := global.CONF.System.DataDir, global.CONF.System.TmpDir
	global.CONF.System.DataDir = dataDir
	global.CONF.System.TmpDir = tmpDir
	t.Cleanup(func() {
		global.CONF.System.DataDir = oldDataDir
		global.CONF.System.TmpDir = oldTmpDir
	})

	files := map[string]string{
		filepath.Join(dataDir, "log", "1Panel.log"):                                                  "system log",
		filepath.Join(dataDir, "log", "1Panel-2026-08-29.log"):                                       "historical system log",
		filepath.Join(tmpDir, "docker_logs", "image_pull_nginx_latest_20260830120000.log"):           "docker log",
		filepath.Join(tmpDir, "docker_logs", "image_push_nginx_latest_20260830120000.log"):           "docker push log",
		filepath.Join(tmpDir, "docker_logs", "image_build_my-image_20260830120000.log"):              "docker build log",
		filepath.Join(tmpDir, "docker_logs", "compose_create_my-project_20260830120000.log"):         "compose log",
		filepath.Join(dataDir, "log", "AITools", "qwen2.5:7b"):                                       "ai log",
		filepath.Join(dataDir, "log", "AITools", "library", "qwen2.5:7b"):                            "namespaced ai log",
		filepath.Join(dataDir, "apps", "mysql", "mysql-abc123", "data", "1Panel-slow.log"):           "mysql log",
		filepath.Join(dataDir, "apps", "mariadb", "mariadb-abc123", "db", "data", "1Panel-slow.log"): "mariadb log",
	}
	for filePath, content := range files {
		if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
			t.Fatalf("mkdir %s: %v", filepath.Dir(filePath), err)
		}
		if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
			t.Fatalf("write %s: %v", filePath, err)
		}
	}

	svc := NewIFileService()
	valid := []request.FileReadByLineReq{
		{Type: constant.TypeSystem, Page: 1, PageSize: 100},
		{Type: constant.TypeSystem, Name: "2026-08-29", Page: 1, PageSize: 100},
		{Type: "image-pull", Name: "image_pull_nginx_latest_20260830120000.log", Page: 1, PageSize: 100},
		{Type: "image-push", Name: "image_push_nginx_latest_20260830120000.log", Page: 1, PageSize: 100},
		{Type: "image-build", Name: "image_build_my-image_20260830120000.log", Page: 1, PageSize: 100},
		{Type: "compose-create", Name: "compose_create_my-project_20260830120000.log", Page: 1, PageSize: 100},
		{Type: "ollama-model", Name: "qwen2.5:7b", Page: 1, PageSize: 100},
		{Type: "ollama-model", Name: "library/qwen2.5:7b", Page: 1, PageSize: 100},
		{Type: "mysql-slow-logs", Name: "mysql-abc123", Page: 1, PageSize: 100},
		{Type: "mariadb-slow-logs", Name: "mariadb-abc123", Page: 1, PageSize: 100},
	}
	for _, req := range valid {
		t.Run("valid/"+req.Type+"/"+req.Name, func(t *testing.T) {
			res, err := svc.ReadLogByLine(req)
			if err != nil {
				t.Fatalf("ReadLogByLine(%+v) unexpected error: %v", req, err)
			}
			if res == nil || len(res.Lines) == 0 {
				t.Fatalf("ReadLogByLine(%+v) returned no lines", req)
			}
		})
	}

	unsafeNames := []string{
		"../outside",
		"../../etc/passwd",
		"/etc/passwd",
		`..\outside`,
		`C:\Windows\win.ini`,
		"C:passwd",
		"a/b",
		"a\\b",
	}
	for _, typ := range []string{"image-pull", "image-push", "image-build", "compose-create", "mysql-slow-logs", "mariadb-slow-logs"} {
		for _, name := range unsafeNames {
			t.Run("unsafe/"+typ+"/"+name, func(t *testing.T) {
				if _, err := svc.ReadLogByLine(request.FileReadByLineReq{Type: typ, Name: name, Page: 1, PageSize: 100}); err == nil {
					t.Fatalf("ReadLogByLine(type=%q, name=%q) returned nil error", typ, name)
				}
			})
		}
	}
	for _, name := range []string{"../outside", "../../etc/passwd", "/etc/passwd", `..\outside`, `C:\Windows\win.ini`, "C:passwd", "a/../b", "a//b"} {
		t.Run("unsafe/ollama-model/"+name, func(t *testing.T) {
			if _, err := svc.ReadLogByLine(request.FileReadByLineReq{Type: "ollama-model", Name: name, Page: 1, PageSize: 100}); err == nil {
				t.Fatalf("ReadLogByLine(type=ollama-model, name=%q) returned nil error", name)
			}
		})
	}

	for _, name := range unsafeNames {
		t.Run("unsafe/system/"+name, func(t *testing.T) {
			if _, err := svc.ReadLogByLine(request.FileReadByLineReq{Type: constant.TypeSystem, Name: name, Page: 1, PageSize: 100}); err == nil {
				t.Fatalf("ReadLogByLine(system name=%q) returned nil error", name)
			}
		})
	}

	for _, name := range []string{"access.log/other", "secret.log", "../access.log"} {
		if _, err := svc.ReadLogByLine(request.FileReadByLineReq{Type: constant.TypeWebsite, Name: name, Page: 1, PageSize: 100}); err == nil {
			t.Fatalf("ReadLogByLine(website name=%q) returned nil error", name)
		}
	}

	for _, typ := range []string{"image-pull", "image-push", "image-build", "compose-create"} {
		for _, name := range []string{"log", "image_pull_file.txt", "image_pull_x_not-a-timestamp.log"} {
			if _, err := svc.ReadLogByLine(request.FileReadByLineReq{Type: typ, Name: name, Page: 1, PageSize: 100}); err == nil {
				t.Fatalf("ReadLogByLine(type=%q, invalid generated name=%q) returned nil error", typ, name)
			}
		}
	}

	if _, err := svc.ReadLogByLine(request.FileReadByLineReq{Type: "unknown", Name: "anything", Page: 1, PageSize: 100}); err == nil {
		t.Fatal("unknown log type returned nil error")
	}
}
