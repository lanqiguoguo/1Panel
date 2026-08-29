package service

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/1Panel-dev/1Panel/backend/app/dto/request"
	"github.com/1Panel-dev/1Panel/backend/app/model"
	"github.com/1Panel-dev/1Panel/backend/constant"
	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/1Panel-dev/1Panel/backend/utils/docker"
	"github.com/glebarez/sqlite"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

// dockerDaemonReachable reports whether the install flow's docker backing can
// be reached from the test environment. The full Install path calls
// docker.CreateDefaultDockerNetwork() before it can even launch its async
// install goroutine, so without a reachable daemon the interesting code never
// runs and this test is skipped instead of failing.
func dockerDaemonReachable() bool {
	cli, err := docker.NewDockerClient()
	if err != nil {
		return false
	}
	defer cli.Close()
	_, err = cli.Ping(context.Background())
	return err == nil
}

// setupInstallAsyncTest prepares the in-memory DB and the app/appDetail rows
// Install needs, and points the install/resource dirs at a throwaway temp dir.
// The local app source directory is deliberately not created, so the async
// install goroutine fails deterministically inside copyData after Install has
// already returned — exactly the window the shared-err bug used to corrupt.
func setupInstallAsyncTest(t *testing.T) (detailID uint) {
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
		DockerCompose: "services:\n  app:\n    image: nginx\n    ports:\n      - \"8080:80\"\n",
	}
	if err := appDetailRepo.BatchCreate(context.Background(), []model.AppDetail{detail}); err != nil {
		t.Fatalf("seed app detail failed: %v", err)
	}
	// BatchCreate copies the slice by value, so detail.ID is not back-filled;
	// re-read the row to learn the generated ID.
	var seeded model.AppDetail
	if err := db.First(&seeded, "app_id = ?", app.ID).Error; err != nil {
		t.Fatalf("read seeded app detail failed: %v", err)
	}
	return seeded.ID
}

// TestInstallAsyncGoroutineOwnsItsFailure is the regression test for the
// Install concurrency bug. The async install goroutine used to assign the
// Install function's named return value err on its failures, which Install's
// sync-path deferred handlers also read when Install returns. That was a data
// race; and when the goroutine's failure landed before Install returned, the
// sync path's handler (handleAppInstallErr: compose down + delete app dir +
// deleteLink) ran against a directory the goroutine was still using, while
// the DB row stayed Installing and only the goroutine's own defer released the
// port claim.
//
// The fix gives the goroutine its own err variable (gErr): the goroutine
// persists UpErr + the failure message and releases its own port tokens, and
// the sync path's cleanup only ever runs for synchronous failures. This test
// pins that contract: Install returns nil/nil immediately, then the async
// goroutine deterministically fails during copyData (the local app source dir
// is absent) and must itself flip the row to UpErr with a non-empty message,
// leaving no in-memory port claim behind.
//
// The full Install flow needs the docker daemon for
// docker.CreateDefaultDockerNetwork(), so this test skips when no daemon is
// reachable.
func TestInstallAsyncGoroutineOwnsItsFailure(t *testing.T) {
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

	// The full Install flow needs the docker daemon for
	// docker.CreateDefaultDockerNetwork(); skip when no daemon is reachable.
	if !dockerDaemonReachable() {
		t.Skip("docker daemon not reachable; skipping Install integration test")
	}

	httpPort := freeTCPPort(t)
	if httpPort == 0 {
		t.Fatal("could not obtain a free test port")
	}
	// The port is left unclaimed here so Install's own checkPort registers the
	// in-memory claim, which the async goroutine must release when it fails.

	req := request.AppInstallCreate{
		AppDetailId: detailID,
		Name:        fmt.Sprintf("testinstall-%d", httpPort),
		Params:      map[string]interface{}{"PANEL_APP_PORT_HTTP": fmt.Sprintf("%d", httpPort)},
	}

	install, installErr := NewIAppService().Install(context.Background(), req)
	if installErr != nil {
		t.Fatalf("Install returned a sync error: %v (the async goroutine owns its own failure path)", installErr)
	}
	if install == nil {
		t.Fatal("Install returned a nil install row after a successful sync path")
	}

	// The sync path is done; the async goroutine is scheduled. It must now
	// fail copyData on its own and flip the DB row to UpErr with its own
	// captured message, without any help from a sync-path cleanup.
	var got model.AppInstall
	deadline := time.After(10 * time.Second)
	for {
		var cur model.AppInstall
		if err := global.DB.First(&cur, install.ID).Error; err != nil {
			t.Fatalf("read install row %d: %v", install.ID, err)
		}
		if cur.Status == constant.UpErr {
			got = cur
			break
		}
		select {
		case <-deadline:
			t.Fatalf("install row did not reach %s in time; got status %q message %q",
				constant.UpErr, cur.Status, cur.Message)
		case <-time.After(20 * time.Millisecond):
		}
	}
	if got.Message == "" {
		t.Fatal("UpErr install has an empty message, want the goroutine-captured error text")
	}

	// The goroutine's deferred release must drop its own port claim.
	releaseDeadline := time.After(5 * time.Second)
	for {
		if _, loaded := registeredPorts.Load(httpPort); !loaded {
			break
		}
		select {
		case <-releaseDeadline:
			t.Fatalf("http port %d claim survived the failed install", httpPort)
		case <-time.After(20 * time.Millisecond):
		}
	}
}