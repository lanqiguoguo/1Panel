package service

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/1Panel-dev/1Panel/backend/app/dto/request"
	"github.com/1Panel-dev/1Panel/backend/app/model"
	"github.com/1Panel-dev/1Panel/backend/buserr"
	"github.com/1Panel-dev/1Panel/backend/constant"
	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/glebarez/sqlite"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

// isBusinessErrorKey reports whether err is the business error carrying the
// given key, independent of the i18n locale the panel is configured with.
func isBusinessErrorKey(err error, key string) bool {
	if err == nil {
		return false
	}
	be, ok := err.(buserr.BusinessError)
	if !ok {
		return false
	}
	return be.Msg == key
}

// setupAppTaskGuardTest prepares an in-memory sqlite DB with the tables the
// app task guard tests need (app, app_detail, app_installs), mirroring
// setupAppInstallResultTest and setupInstallAsyncTest.
func setupAppTaskGuardTest(t *testing.T) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open in-memory sqlite failed: %v", err)
	}
	for _, m := range []interface{}{&model.App{}, &model.AppDetail{}, &model.AppInstall{}, &model.AppTag{}, &model.Setting{}} {
		if err := db.AutoMigrate(m); err != nil {
			t.Fatalf("migrate %T failed: %v", m, err)
		}
	}
	global.DB = db
	global.LOG = logrus.New()
}

// setupLocalAppInstallDirTest points the app install/resource dirs at a
// throwaway temp dir for tests whose assertions are purely about on-disk
// install paths (GetPath/canary dirs). The local app resource tree is
// deliberately NOT created, so a real Install's async goroutine fails
// deterministically inside copyData.
func setupLocalAppInstallDirTest(t *testing.T) {
	t.Helper()
	oldDataDir := global.CONF.System.DataDir
	oldResourceDir := constant.ResourceDir
	oldAppResourceDir := constant.AppResourceDir
	oldLocalAppResourceDir := constant.LocalAppResourceDir
	oldAppInstallDir := constant.AppInstallDir
	oldLocalAppInstallDir := constant.LocalAppInstallDir
	dataDir := t.TempDir()
	global.CONF.System.DataDir = dataDir
	constant.ResourceDir = filepath.Join(dataDir, "resource")
	constant.AppResourceDir = filepath.Join(constant.ResourceDir, "apps")
	constant.LocalAppResourceDir = filepath.Join(constant.AppResourceDir, "local")
	constant.AppInstallDir = filepath.Join(dataDir, "apps")
	constant.LocalAppInstallDir = filepath.Join(constant.AppInstallDir, "local")
	t.Cleanup(func() {
		global.CONF.System.DataDir = oldDataDir
		constant.ResourceDir = oldResourceDir
		constant.AppResourceDir = oldAppResourceDir
		constant.LocalAppResourceDir = oldLocalAppResourceDir
		constant.AppInstallDir = oldAppInstallDir
		constant.LocalAppInstallDir = oldLocalAppInstallDir
	})
}

// seedTaskGuardApp seeds a local app + app detail row and returns both the app
// and the seeded detail ID.
func seedTaskGuardApp(t *testing.T) (model.App, uint) {
	t.Helper()
	app := model.App{
		Name:     "testapp",
		Key:      "testapp",
		Type:     "tool",
		Resource: constant.AppResourceLocal,
	}
	if err := appRepo.Create(context.Background(), &app); err != nil {
		t.Fatalf("seed app failed: %v", err)
	}
	detail := model.AppDetail{
		AppId:         app.ID,
		Version:       "1.0.0",
		Status:        constant.AppNormal,
		Params:        "{}",
		DockerCompose: "services:\n  app:\n    image: nginx\n",
	}
	if err := appDetailRepo.BatchCreate(context.Background(), []model.AppDetail{detail}); err != nil {
		t.Fatalf("seed app detail failed: %v", err)
	}
	var seeded model.AppDetail
	if err := global.DB.First(&seeded, "app_id = ?", app.ID).Error; err != nil {
		t.Fatalf("read seeded app detail failed: %v", err)
	}
	return app, seeded.ID
}

// seedInstallRow seeds an app_installs row in state status and returns it.
func seedInstallRow(t *testing.T, app model.App, name, status string) model.AppInstall {
	t.Helper()
	install := model.AppInstall{
		Name:          name,
		AppId:         app.ID,
		Version:       "1.0.0",
		Status:        status,
		ContainerName: "container-" + name,
		ServiceName:   name,
	}
	if err := appInstallRepo.Create(context.Background(), &install); err != nil {
		t.Fatalf("seed install %s failed: %v", name, err)
	}
	return install
}

// TestTryClaimAppTaskExcludesConcurrentTaskOwners covers the in-process
// per-name claim: a second task for the same name is rejected while the first
// is in flight and accepted again after the release.
func TestTryClaimAppTaskExcludesConcurrentTaskOwners(t *testing.T) {
	name := fmt.Sprintf("claim-excl-%d", os.Getpid())
	releaseAppInstallTask(name) // clear any stale claim from an earlier run

	if !tryClaimAppTask(name) {
		t.Fatal("first claim of a free name failed")
	}
	if tryClaimAppTask(name) {
		t.Fatal("second concurrent claim of the same name succeeded; want rejection")
	}
	// The DB name check is case-insensitive, so the claim must be too: a name
	// that only differs in case is the same install.
	if tryClaimAppTask(strings.ToUpper(name)) {
		t.Fatal("claim with a different case of the same name succeeded; want rejection")
	}
	if !tryClaimAppTask(name + "-other") {
		t.Fatal("claim of an unrelated name failed while another name is busy")
	}
	releaseAppInstallTask(name + "-other")
	releaseAppInstallTask(strings.ToUpper(name))
	if !tryClaimAppTask(name) {
		t.Fatal("claim after release failed; want the name free again")
	}
	releaseAppInstallTask(name)
}

// TestConcurrentSameNameInstallRejectsLoserWithoutCleanup is the regression
// test for the H10 hazard: a second same-name install racing a first one must
// be rejected with the duplicate-name business error and must NOT run the
// cleanup that used to compose-down and delete the winner's install directory
// (the path is derived from the name alone and identical for both requests).
// The winner is simulated by holding the in-process claim; its directory is a
// canary that must survive the loser's request. The Install call itself does
// not need the docker daemon to reach the name check.
func TestConcurrentSameNameInstallRejectsLoserWithoutCleanup(t *testing.T) {
	setupAppTaskGuardTest(t)
	setupLocalAppInstallDirTest(t)

	app, detailID := seedTaskGuardApp(t)
	_ = app

	// The winner owns the name; its install directory is the canary that a
	// broken loser cleanup would delete.
	name := "racecanary"
	canaryDir := filepath.Join(constant.LocalAppInstallDir, "testapp", name)
	if err := os.MkdirAll(canaryDir, 0755); err != nil {
		t.Fatalf("mkdir canary dir failed: %v", err)
	}
	canaryFile := filepath.Join(canaryDir, "canary.txt")
	if err := os.WriteFile(canaryFile, []byte("winner data"), 0644); err != nil {
		t.Fatalf("write canary file failed: %v", err)
	}

	if !tryClaimAppTask(name) {
		t.Fatal("failed to claim the install name for the simulated winner")
	}
	defer releaseAppInstallTask(name)

	svc := NewIAppService()
	req := request.AppInstallCreate{
		AppDetailId: detailID,
		Name:        name,
		Params:      map[string]interface{}{},
	}
	_, err := svc.Install(context.Background(), req)
	if err == nil {
		t.Fatal("second same-name install succeeded while the first was in flight; want duplicate-name rejection")
	}
	if !isBusinessErrorKey(err, constant.ErrAppNameExist) {
		t.Fatalf("loser error = %q, want the duplicate-name business error", err.Error())
	}
	if _, statErr := os.Stat(canaryFile); statErr != nil {
		t.Fatalf("winner canary file %s was deleted by the losing install (stat: %v)", canaryFile, statErr)
	}
	if _, statErr := os.Stat(canaryDir); statErr != nil {
		t.Fatalf("winner canary dir %s was deleted by the losing install (stat: %v)", canaryDir, statErr)
	}
	var count int64
	if err := global.DB.Model(&model.AppInstall{}).Where("name = ?", name).Count(&count).Error; err != nil {
		t.Fatalf("count install rows failed: %v", err)
	}
	if count != 0 {
		t.Fatalf("losing install created %d rows for name %s; want 0", count, name)
	}
}

// TestUpgradeAndRebuildCASRejectsConcurrentTask covers the DB status CAS
// (TryBeginOperate): an upgrade/rebuild may only start from an idle status; a
// request that reaches the CAS while the row already shows Upgrading (or
// Rebuilding/Installing) is rejected with the task-busy error instead of
// running compose down/up against the same files.
func TestUpgradeAndRebuildCASRejectsConcurrentTask(t *testing.T) {
	setupAppTaskGuardTest(t)
	setupLocalAppInstallDirTest(t)

	app, detailID := seedTaskGuardApp(t)
	install := seedInstallRow(t, app, "cas-guard", constant.Running)
	if err := global.DB.Model(&model.AppDetail{}).Where("id = ?", detailID).Update("version", "2.0.0").Error; err != nil {
		t.Fatalf("bump app detail version failed: %v", err)
	}

	// 1) A mutator may start from Running.
	claimed, err := appInstallRepo.TryBeginOperate(install.ID, appTaskIdleStatuses, constant.Upgrading)
	if err != nil {
		t.Fatalf("TryBeginOperate failed: %v", err)
	}
	if claimed != 1 {
		t.Fatalf("TryBeginOperate claimed %d rows from Running; want 1", claimed)
	}

	// 2) A second mutator while the row is Upgrading loses the CAS.
	claimed, err = appInstallRepo.TryBeginOperate(install.ID, appTaskIdleStatuses, constant.Rebuilding)
	if err != nil {
		t.Fatalf("second TryBeginOperate failed: %v", err)
	}
	if claimed != 0 {
		t.Fatalf("second TryBeginOperate claimed %d rows from Upgrading; want 0 (busy)", claimed)
	}

	// 3) The upgrade flow reports an error when it loses the CAS to an
	//    already-Upgrading row even though the in-process name claim is free,
	//    and it must leave the row untouched (still Upgrading).
	releaseAppInstallTask(install.Name) // ensure free (no-op)
	upgradeErr := upgradeInstall(request.AppInstallUpgrade{InstallID: install.ID, DetailID: detailID})
	if upgradeErr == nil {
		t.Fatal("upgradeInstall against an already-Upgrading row succeeded; want task-busy error")
	}
	var after model.AppInstall
	if err := global.DB.First(&after, install.ID).Error; err != nil {
		t.Fatalf("read install row after failed upgrade: %v", err)
	}
	if after.Status != constant.Upgrading {
		t.Fatalf("failed upgradeInstall changed the row status to %q; want it untouched (%q)", after.Status, constant.Upgrading)
	}

	// 4) rebuildApp against the same already-Upgrading row is rejected too and
	//    leaves the row untouched.
	rebuildErr := rebuildApp(install, false)
	if rebuildErr == nil {
		t.Fatal("rebuildApp against an already-Upgrading row succeeded; want task-busy error")
	}
	if err := global.DB.First(&after, install.ID).Error; err != nil {
		t.Fatalf("read install row after failed rebuild: %v", err)
	}
	if after.Status != constant.Upgrading {
		t.Fatalf("failed rebuildApp changed the row status to %q; want it untouched (%q)", after.Status, constant.Upgrading)
	}

	// 5) Once the owning task ends (back to Running) the CAS accepts again.
	if _, err := appInstallRepo.UpdateStatusByID(install.ID, constant.Upgrading, constant.Running); err != nil {
		t.Fatalf("restore Running failed: %v", err)
	}
	claimed, err = appInstallRepo.TryBeginOperate(install.ID, appTaskIdleStatuses, constant.Rebuilding)
	if err != nil {
		t.Fatalf("TryBeginOperate after restore failed: %v", err)
	}
	if claimed != 1 {
		t.Fatalf("TryBeginOperate claimed %d rows from Running after restore; want 1", claimed)
	}
	if _, err := appInstallRepo.UpdateStatusByID(install.ID, constant.Rebuilding, constant.Running); err != nil {
		t.Fatalf("restore Running after rebuild claim failed: %v", err)
	}
}

// TestHandleAppInstallErrOnlyCleansOwnedResources covers the cleanup-scope
// fix in handleAppInstallErr: a request that never created the install row
// (install.ID == 0 — the loser of a concurrent same-name install whose Create
// hit the UNIQUE(name) constraint) must NOT delete the install directory at
// the name-derived path, because it belongs to the winner. Only the request
// that owns the row (ID > 0) may clean the directory it created.
func TestHandleAppInstallErrOnlyCleansOwnedResources(t *testing.T) {
	setupAppTaskGuardTest(t)
	setupLocalAppInstallDirTest(t)

	app, _ := seedTaskGuardApp(t)
	install := model.AppInstall{
		Name:          "cleanup-canary",
		AppId:         app.ID,
		Version:       "1.0.0",
		Status:        constant.Installing,
		ContainerName: "cc",
		ServiceName:   "cleanup-canary",
		App:           app,
	}
	canaryDir := install.GetPath()
	if err := os.MkdirAll(canaryDir, 0755); err != nil {
		t.Fatalf("mkdir canary dir failed: %v", err)
	}
	canaryFile := filepath.Join(canaryDir, "canary.txt")
	if err := os.WriteFile(canaryFile, []byte("winner data"), 0644); err != nil {
		t.Fatalf("write canary file failed: %v", err)
	}

	// Loser: no row was ever created (ID == 0); the cleanup must leave the
	// directory and the canary untouched.
	if err := handleAppInstallErr(context.Background(), &install, true); err != nil {
		t.Fatalf("handleAppInstallErr for the loser returned an error: %v", err)
	}
	if _, statErr := os.Stat(canaryFile); statErr != nil {
		t.Fatalf("loser cleanup deleted the winner canary file %s (stat: %v)", canaryFile, statErr)
	}

	// Owner: the row exists (ID > 0); the cleanup deletes the directory the
	// owner created. (compose.Down runs only when a compose file exists; the
	// canary dir has none, so no docker CLI call happens.)
	install.ID = 42
	if err := handleAppInstallErr(context.Background(), &install, true); err != nil {
		t.Fatalf("handleAppInstallErr for the owner returned an error: %v", err)
	}
	if _, statErr := os.Stat(canaryDir); statErr == nil {
		t.Fatal("owner cleanup did not delete the install directory it owns")
	}

	// cleanupOwned=false (the early error paths of Install, which registered
	// no cleanup defer before the row existed) never deletes a directory.
	if err := os.MkdirAll(canaryDir, 0755); err != nil {
		t.Fatalf("recreate canary dir failed: %v", err)
	}
	install.ID = 0
	if err := handleAppInstallErr(context.Background(), &install, false); err != nil {
		t.Fatalf("handleAppInstallErr with cleanupOwned=false returned an error: %v", err)
	}
	if _, statErr := os.Stat(canaryDir); statErr != nil {
		t.Fatalf("cleanupOwned=false deleted the canary dir %s (stat: %v)", canaryDir, statErr)
	}
}

// TestInstallAsyncReleasesTaskClaimAfterFailure verifies the claim lifecycle
// of the real Install flow end to end (docker-gated): Install claims the name
// and hands the claim to the async goroutine; the goroutine keeps it while the
// task runs and releases it when the task finishes. While the name is claimed,
// a concurrent same-name Install is rejected without touching the row or dir.
func TestInstallAsyncReleasesTaskClaimAfterFailure(t *testing.T) {
	oldDataDir := global.CONF.System.DataDir
	oldResourceDir := constant.ResourceDir
	oldAppResourceDir := constant.AppResourceDir
	oldLocalAppResourceDir := constant.LocalAppResourceDir
	oldAppInstallDir := constant.AppInstallDir
	oldLocalAppInstallDir := constant.LocalAppInstallDir
	dataDir := t.TempDir()
	global.CONF.System.DataDir = dataDir
	constant.ResourceDir = filepath.Join(dataDir, "resource")
	constant.AppResourceDir = filepath.Join(constant.ResourceDir, "apps")
	constant.LocalAppResourceDir = filepath.Join(constant.AppResourceDir, "local")
	constant.AppInstallDir = filepath.Join(dataDir, "apps")
	constant.LocalAppInstallDir = filepath.Join(constant.AppInstallDir, "local")
	t.Cleanup(func() {
		global.CONF.System.DataDir = oldDataDir
		constant.ResourceDir = oldResourceDir
		constant.AppResourceDir = oldAppResourceDir
		constant.LocalAppResourceDir = oldLocalAppResourceDir
		constant.AppInstallDir = oldAppInstallDir
		constant.LocalAppInstallDir = oldLocalAppInstallDir
	})

	detailID := setupInstallAsyncTest(t)

	if !dockerDaemonReachable() {
		t.Skip("docker daemon not reachable; skipping Install lifecycle test")
	}

	httpPort := freeTCPPort(t)
	if httpPort == 0 {
		t.Fatal("could not obtain a free test port")
	}
	name := fmt.Sprintf("lifecycle-%d", httpPort)
	releaseAppInstallTask(name) // clear any stale claim

	// The async goroutine deterministically fails inside copyData (the local
	// app source dir is absent) and flips the row to UpErr.
	install, err := NewIAppService().Install(context.Background(), request.AppInstallCreate{
		AppDetailId: detailID,
		Name:        name,
		Params:      map[string]interface{}{"PANEL_APP_PORT_HTTP": fmt.Sprintf("%d", httpPort)},
	})
	if err != nil {
		t.Fatalf("first Install failed: %v", err)
	}
	if install == nil {
		t.Fatal("first Install returned a nil row")
	}

	// Immediately after the sync path returned, the name must still be claimed
	// by the async goroutine, so a second same-name request is rejected.
	_, secondErr := NewIAppService().Install(context.Background(), request.AppInstallCreate{
		AppDetailId: detailID,
		Name:        name,
		Params:      map[string]interface{}{},
	})
	if secondErr == nil {
		t.Fatal("second same-name Install succeeded while the first was still in flight")
	}
	if !isBusinessErrorKey(secondErr, constant.ErrAppNameExist) {
		t.Fatalf("second Install error = %q, want the duplicate-name business error", secondErr.Error())
	}

	// The claim must survive until the task finishes: poll for UpErr (persisted
	// by the goroutine's defer just before it releases the claim).
	waitRowStatus(t, install.ID, constant.UpErr, 10*time.Second)

	// After the goroutine released the claim the name is claimable again.
	// (The row still exists in state UpErr, so a real Install is rejected by
	// the DB name check — that is the desired post-failure state.)
	claimDeadline := time.After(5 * time.Second)
	for {
		if tryClaimAppTask(name) {
			releaseAppInstallTask(name)
			return
		}
		select {
		case <-claimDeadline:
			t.Fatal("task claim was not released after the install task finished")
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func waitRowStatus(t *testing.T, id uint, want string, timeout time.Duration) {
	t.Helper()
	deadline := time.After(timeout)
	for {
		var cur model.AppInstall
		if err := global.DB.First(&cur, id).Error; err != nil {
			t.Fatalf("read install row %d: %v", id, err)
		}
		if cur.Status == want {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("install row %d did not reach status %s in time; got %q", id, want, cur.Status)
		case <-time.After(20 * time.Millisecond):
		}
	}
}
