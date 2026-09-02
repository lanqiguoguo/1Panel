package service

import (
	"context"
	"strings"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/app/dto/request"
	"github.com/1Panel-dev/1Panel/backend/app/model"
	"github.com/1Panel-dev/1Panel/backend/constant"
	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/glebarez/sqlite"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

// setupAppUpgradeURLTest seeds an in-memory DB with one remote app, an install
// pinned to v1.0.0 and two upgrade candidates (v1.1.0, v1.2.0). The candidates
// deliberately start with an empty DockerCompose and a DownloadUrl crafted by
// the caller, mirroring the app-store sync rows GetUpdateVersions consumes.
func setupAppUpgradeURLTest(t *testing.T, downloadURLs ...string) (appID, installID uint) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open in-memory sqlite failed: %v", err)
	}
	for _, m := range []interface{}{&model.App{}, &model.AppDetail{}, &model.AppInstall{}, &model.AppTag{}} {
		if err := db.AutoMigrate(m); err != nil {
			t.Fatalf("migrate %T failed: %v", m, err)
		}
	}
	global.DB = db
	global.LOG = logrus.New()

	app := model.App{
		Name:     "testapp",
		Key:      "testapp",
		Type:     "tool",
		Resource: constant.AppResourceRemote,
	}
	if err := appRepo.Create(context.Background(), &app); err != nil {
		t.Fatalf("seed app failed: %v", err)
	}
	for i, u := range downloadURLs {
		version := "1.1.0"
		if i%2 == 1 {
			version = "1.2.0"
		}
		detail := model.AppDetail{
			AppId:         app.ID,
			Version:       version,
			Status:        constant.AppNormal,
			Params:        "{}",
			DockerCompose: "",
			DownloadUrl:   u,
		}
		if err := appDetailRepo.BatchCreate(context.Background(), []model.AppDetail{detail}); err != nil {
			t.Fatalf("seed app detail %s failed: %v", version, err)
		}
	}
	install := model.AppInstall{
		Name:        "testinstall",
		AppId:       app.ID,
		Version:     "1.0.0",
		Status:      constant.Running,
		ServiceName: "testapp",
	}
	if err := appInstallRepo.Create(context.Background(), &install); err != nil {
		t.Fatalf("seed install failed: %v", err)
	}
	return app.ID, install.ID
}

// readAppDetailByVersion re-reads a seeded app detail straight from the test
// DB, bypassing the appDetailRepo.Update caching used in production paths.
func readAppDetailByVersion(t *testing.T, appID uint, version string) model.AppDetail {
	t.Helper()
	var detail model.AppDetail
	if err := global.DB.First(&detail, "app_id = ? AND version = ?", appID, version).Error; err != nil {
		t.Fatalf("read app detail %s failed: %v", version, err)
	}
	return detail
}

// TestGetUpdateVersionsRejectsInternalComposeURL is the regression test for
// the missing SSRF guard in the GetUpdateVersions docker-compose download.
// detail.DownloadUrl is stored in the app-detail DB by the store sync, so a
// tampered database could previously steer the compose download to an
// internal address and have the response persisted into detail.DockerCompose,
// which the upgrade flow later YAML-parses and hands to `docker compose`. The
// fix reuses the same ValidatePublicURL gate as GetAppDetail: an internal
// host must abort the request before it is made and must not touch the DB.
func TestGetUpdateVersionsRejectsInternalComposeURL(t *testing.T) {
	appID, installID := setupAppUpgradeURLTest(t,
		"http://127.0.0.1:18080/apps/testapp/1.1.0/testapp-1.1.0.tar.gz",
		"https://example.com/apps/testapp/1.2.0/testapp-1.2.0.tar.gz",
	)

	s := &AppInstallService{}
	if _, err := s.GetUpdateVersions(request.AppUpdateVersion{
		AppInstallID:  installID,
		UpdateVersion: "1.1.0",
	}); err == nil {
		t.Fatal("expected internal compose download URL to be rejected, got nil error")
	} else if !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("rejection error = %v, want a URL-not-allowed error naming the guard", err)
	}

	// the tampered detail row must not be touched: DockerCompose stays empty so
	// a later, honest upgrade of this version re-downloads from the store
	detail := readAppDetailByVersion(t, appID, "1.1.0")
	if detail.DockerCompose != "" {
		t.Fatalf("detail 1.1.0 DockerCompose was persisted from a rejected URL: %q", detail.DockerCompose)
	}

	// a second call must fail the same way (no state change between attempts)
	if _, err := s.GetUpdateVersions(request.AppUpdateVersion{
		AppInstallID:  installID,
		UpdateVersion: "1.1.0",
	}); err == nil {
		t.Fatal("expected second call to also reject the internal compose URL")
	}
}

// TestGetUpdateVersionsSkipsComposeFetchForLocalApp pins that the upgrade
// path stays untouched for local apps (resource == local): GetUpdateVersions
// must never try to fetch their docker-compose from a URL. With the fix, the
// request below would otherwise fail or stall on the download of a local
// app's compose file.
func TestGetUpdateVersionsSkipsComposeFetchForLocalApp(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open in-memory sqlite failed: %v", err)
	}
	for _, m := range []interface{}{&model.App{}, &model.AppDetail{}, &model.AppInstall{}, &model.AppTag{}} {
		if err := db.AutoMigrate(m); err != nil {
			t.Fatalf("migrate %T failed: %v", m, err)
		}
	}
	global.DB = db
	global.LOG = logrus.New()

	app := model.App{
		Name:     "testapp-local",
		Key:      "testapp-local",
		Type:     "tool",
		Resource: constant.AppResourceLocal,
	}
	if err := appRepo.Create(context.Background(), &app); err != nil {
		t.Fatalf("seed local app failed: %v", err)
	}
	detail := model.AppDetail{
		AppId:         app.ID,
		Version:       "1.1.0",
		Status:        constant.AppNormal,
		Params:        "{}",
		DockerCompose: "",
		DownloadUrl:   "file:///etc/hosts",
	}
	if err := appDetailRepo.BatchCreate(context.Background(), []model.AppDetail{detail}); err != nil {
		t.Fatalf("seed local app detail failed: %v", err)
	}
	install := model.AppInstall{
		Name:        "testinstall-local",
		AppId:       app.ID,
		Version:     "1.0.0",
		Status:      constant.Running,
		ServiceName: "testapp-local",
	}
	if err := appInstallRepo.Create(context.Background(), &install); err != nil {
		t.Fatalf("seed local install failed: %v", err)
	}

	s := &AppInstallService{}
	versions, err := s.GetUpdateVersions(request.AppUpdateVersion{
		AppInstallID:  install.ID,
		UpdateVersion: "1.1.0",
	})
	if err != nil {
		t.Fatalf("GetUpdateVersions for local app failed: %v", err)
	}
	if len(versions) != 1 || versions[0].Version != "1.1.0" {
		t.Fatalf("expected one upgrade candidate 1.1.0 for local app, got %+v", versions)
	}
	// local app: compose comes from the local install copy, not a URL fetch
	if got := readAppDetailByVersion(t, app.ID, "1.1.0").DockerCompose; got != "" {
		t.Fatalf("local app detail DockerCompose was unexpectedly fetched/persisted: %q", got)
	}
}
