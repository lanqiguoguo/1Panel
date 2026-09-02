package service

import (
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/app/model"
	"github.com/1Panel-dev/1Panel/backend/constant"
	"github.com/1Panel-dev/1Panel/backend/global"
)

// setupCleanupResourceDirs points constant.DataDir/AppInstallDir at a
// throwaway temp dir for the cleanup tests, mirroring
// setupLocalAppInstallDirTest.
func setupCleanupResourceDirs(t *testing.T) string {
	t.Helper()
	oldDataDir := global.CONF.System.DataDir
	oldDataDirC := constant.DataDir
	oldAppInstallDir := constant.AppInstallDir
	dataDir := t.TempDir()
	global.CONF.System.DataDir = dataDir
	constant.DataDir = dataDir
	constant.AppInstallDir = path.Join(dataDir, "apps")
	t.Cleanup(func() {
		global.CONF.System.DataDir = oldDataDir
		constant.DataDir = oldDataDirC
		constant.AppInstallDir = oldAppInstallDir
	})
	return constant.AppInstallDir
}

// TestCleanupWebsiteResourcesAliasConf is the M2 regression: the cleanup of a
// failed website creation must remove conf.d/<alias>.conf (the exact file
// configDefaultNginx writes) together with the site directory. The old code
// deleted conf.d/<PrimaryDomain>.conf, which never exists when the primary
// domain differs from the alias, leaving the ghost nginx config behind.
func TestCleanupWebsiteResourcesAliasConf(t *testing.T) {
	appInstallDir := setupCleanupResourceDirs(t)
	nginxDir := filepath.Join(appInstallDir, "openresty", "openresty-1")
	confDir := filepath.Join(nginxDir, "conf", "conf.d")
	siteDir := filepath.Join(nginxDir, "www", "sites", "my-site-alias")
	for _, d := range []string{confDir, filepath.Join(siteDir, "index"), filepath.Join(siteDir, "log")} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}
	aliasConf := filepath.Join(confDir, "my-site-alias.conf")
	if err := os.WriteFile(aliasConf, []byte("server {}"), 0644); err != nil {
		t.Fatal(err)
	}
	// The decoy the old implementation would have deleted (wrong name).
	primaryConf := filepath.Join(confDir, "primary.example.com.conf")
	if err := os.WriteFile(primaryConf, []byte("server {}"), 0644); err != nil {
		t.Fatal(err)
	}
	install := model.AppInstall{BaseModel: model.BaseModel{ID: 1}, Name: "openresty-1"}
	website := &model.Website{Alias: "my-site-alias", PrimaryDomain: "primary.example.com"}

	if err := cleanupWebsiteResources(install, website); err != nil {
		t.Fatalf("cleanupWebsiteResources failed: %v", err)
	}
	if _, err := os.Stat(aliasConf); !os.IsNotExist(err) {
		t.Errorf("conf.d/%s.conf must be removed by the cleanup", website.Alias)
	}
	if _, err := os.Stat(siteDir); !os.IsNotExist(err) {
		t.Errorf("site dir %s must be removed by the cleanup", siteDir)
	}
	if _, err := os.Stat(primaryConf); err != nil {
		t.Errorf("unrelated conf file conf.d/primary.example.com.conf was removed: %v", err)
	}
}

// TestCleanupWebsiteResourcesIdempotent verifies that the cleanup tolerates
// already-absent artifacts (the nginx check can fail before the folder was
// fully created).
func TestCleanupWebsiteResourcesIdempotent(t *testing.T) {
	_ = setupCleanupResourceDirs(t)
	install := model.AppInstall{BaseModel: model.BaseModel{ID: 1}, Name: "openresty-1"}
	website := &model.Website{Alias: "ghost-alias", PrimaryDomain: "primary.example.com"}
	if err := cleanupWebsiteResources(install, website); err != nil {
		t.Fatalf("cleanup of absent artifacts failed: %v", err)
	}
}
