package service

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/app/model"
	"github.com/1Panel-dev/1Panel/backend/constant"
	"github.com/1Panel-dev/1Panel/backend/global"
)

// setupContainerLogPathTest points constant.DataDir at a throwaway dir so
// composeDetailPathAllowed checks against a controlled root.
func setupContainerLogPathTest(t *testing.T) string {
	t.Helper()
	dataDir := filepath.Join(t.TempDir(), "1panel")
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		t.Fatalf("mkdir dataDir: %v", err)
	}
	oldDataDir := global.CONF.System.DataDir
	oldDataDirC := constant.DataDir
	global.CONF.System.DataDir = dataDir
	constant.DataDir = dataDir
	t.Cleanup(func() {
		global.CONF.System.DataDir = oldDataDir
		constant.DataDir = oldDataDirC
	})
	return dataDir
}

// TestComposeDetailPathAllowedRecorded pins the allowed read targets once a
// compose record exists: only files inside the recorded project directory
// pass, anything outside (system files, sibling projects) is refused.
func TestComposeDetailPathAllowedRecorded(t *testing.T) {
	dataDir := setupContainerLogPathTest(t)
	svc := &ContainerService{}
	record := model.Compose{BaseModel: model.BaseModel{ID: 1}, Name: "web", Path: filepath.Join(dataDir, "docker", "compose", "web", "docker-compose.yml")}

	valid := []string{
		filepath.Join(dataDir, "docker", "compose", "web", "docker-compose.yml"),
		filepath.Join(dataDir, "docker", "compose", "web", "other.yml"),
		filepath.Join(dataDir, "docker", "compose", "web"),
	}
	for _, p := range valid {
		if !svc.composeDetailPathAllowed(p, record) {
			t.Errorf("composeDetailPathAllowed(%q) = false, want true", p)
		}
	}

	invalid := []string{
		"/etc/shadow", // label forgery target
		filepath.Join(dataDir, "docker", "compose", "other", "docker-compose.yml"),   // sibling project
		filepath.Join(dataDir, "secret.txt"),                                         // outside the project dir
		filepath.Join(dataDir, "docker", "compose", "web", "..", "..", "secret.txt"), // traversal
		"relative/path.yml", // not absolute
		"",                  // empty
	}
	for _, p := range invalid {
		if svc.composeDetailPathAllowed(p, record) {
			t.Errorf("composeDetailPathAllowed(%q) = true, want false", p)
		}
	}
}

// TestComposeDetailPathAllowedNoRecord pins the fallback for compose runs
// whose DB record is not written yet (async up still running, app-store
// installs): only absolute paths inside the panel data dir pass.
func TestComposeDetailPathAllowedNoRecord(t *testing.T) {
	dataDir := setupContainerLogPathTest(t)
	svc := &ContainerService{}
	var record model.Compose // zero-value: ID == 0, no record

	valid := []string{
		filepath.Join(dataDir, "apps", "openresty", "openresty-1", "docker-compose.yml"),
		filepath.Join(dataDir, "docker", "compose", "web", "docker-compose.yml"),
	}
	for _, p := range valid {
		if !svc.composeDetailPathAllowed(p, record) {
			t.Errorf("composeDetailPathAllowed(%q) = false, want true", p)
		}
	}

	invalid := []string{
		"/etc/shadow",                               // system file outside DataDir
		"/opt/project/docker-compose.yml",           // user-created compose outside DataDir
		filepath.Join(dataDir, "..", "outside.yml"), // traversal escape
		"", // empty
	}
	for _, p := range invalid {
		if svc.composeDetailPathAllowed(p, record) {
			t.Errorf("composeDetailPathAllowed(%q) = true, want false", p)
		}
	}
}
