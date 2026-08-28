package service

import (
	"context"
	"errors"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/app/model"
	"github.com/1Panel-dev/1Panel/backend/constant"
	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/docker/docker/api/types"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

// setupAppInstallResultTest prepares an in-memory sqlite DB with the
// app_installs table, mirroring the harness style of setting_test.go.
func setupAppInstallResultTest(t *testing.T) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open in-memory sqlite failed: %v", err)
	}
	if err := db.AutoMigrate(&model.AppInstall{}); err != nil {
		t.Fatalf("migrate app_installs failed: %v", err)
	}
	global.DB = db
}

// TestPersistInstallResult covers the fields persistInstallResult writes back
// after an up attempt: a failed install must never end up with an empty
// message in the DB (the silent-failure bug), while a successful install must
// keep the previous write set (status + container_name, never message).
func TestPersistInstallResult(t *testing.T) {
	setupAppInstallResultTest(t)

	create := func(name string) *model.AppInstall {
		t.Helper()
		install := &model.AppInstall{
			Name:          name,
			AppId:         1,
			AppDetailId:   1,
			Version:       "1.0",
			Status:        constant.Installing,
			ContainerName: "",
			ServiceName:   name,
		}
		if err := appInstallRepo.Create(context.Background(), install); err != nil {
			t.Fatalf("seed install %s failed: %v", name, err)
		}
		return install
	}
	read := func(id uint) model.AppInstall {
		t.Helper()
		var got model.AppInstall
		if err := global.DB.First(&got, id).Error; err != nil {
			t.Fatalf("read install %d failed: %v", id, err)
		}
		return got
	}

	t.Run("failure keeps the in-memory message", func(t *testing.T) {
		install := create("fail-with-message")
		install.Status = constant.UpErr
		install.Message = "pull timeout output"
		persistInstallResult(install, errors.New("exit status 1"), []string{"app-container"})

		got := read(install.ID)
		if got.Status != constant.UpErr {
			t.Errorf("status = %q, want %q", got.Status, constant.UpErr)
		}
		if got.Message != "pull timeout output" {
			t.Errorf("message = %q, want the in-memory reason %q", got.Message, "pull timeout output")
		}
		if got.ContainerName != "app-container" {
			t.Errorf("container_name = %q, want %q", got.ContainerName, "app-container")
		}
	})

	t.Run("failure falls back to the discarded error text", func(t *testing.T) {
		install := create("fail-empty-message")
		install.Status = constant.UpErr
		install.Message = ""
		persistInstallResult(install, errors.New("no space left on device"), nil)

		got := read(install.ID)
		if got.Status != constant.UpErr {
			t.Errorf("status = %q, want %q", got.Status, constant.UpErr)
		}
		if got.Message != "no space left on device" {
			t.Errorf("message = %q, want the error text %q", got.Message, "no space left on device")
		}
		if got.ContainerName != "" {
			t.Errorf("container_name = %q, want untouched empty value", got.ContainerName)
		}
	})

	t.Run("success writes status and containers but never the message", func(t *testing.T) {
		install := create("success")
		install.Status = constant.Running
		install.Message = "stale in-memory leftovers"
		persistInstallResult(install, nil, []string{"app-container", "sidecar"})

		got := read(install.ID)
		if got.Status != constant.Running {
			t.Errorf("status = %q, want %q", got.Status, constant.Running)
		}
		if got.Message != "" {
			t.Errorf("message = %q, want untouched empty value (no message key on success)", got.Message)
		}
		if got.ContainerName != "app-container,sidecar" {
			t.Errorf("container_name = %q, want %q", got.ContainerName, "app-container,sidecar")
		}
	})
}

// TestSynAppInstallOnlyUpdatesStatusAndMessage is the regression test for the
// P1-C race: synAppInstall used to Save the whole row, so a sync triggered
// from the installed list could overwrite every column (container_name,
// version, description, ...) with a stale in-memory snapshot while a
// concurrent install/upgrade goroutine was writing. It must now only update
// status and message via UpdateFieldsByID, leaving every other field of the
// DB row untouched.
func TestSynAppInstallOnlyUpdatesStatusAndMessage(t *testing.T) {
	setupAppInstallResultTest(t)

	seed := func(name, status, message, containerName string) *model.AppInstall {
		t.Helper()
		install := &model.AppInstall{
			Name:          name,
			AppId:         1,
			AppDetailId:   1,
			Version:       "1.0",
			Status:        status,
			Message:       message,
			ContainerName: containerName,
			ServiceName:   name,
		}
		if err := appInstallRepo.Create(context.Background(), install); err != nil {
			t.Fatalf("seed install %s failed: %v", name, err)
		}
		return install
	}
	// simulate a snapshot whose non-status fields have drifted from the DB
	// row (e.g. a concurrent writer bumped the version, or the row was
	// touched after the list query): with the old Save these would all have
	// been rolled back by the sync
	stale := func(install *model.AppInstall) *model.AppInstall {
		t.Helper()
		s := *install
		s.Version = "0.9"
		s.ContainerName = "stale-container"
		s.Description = "must-survive"
		return &s
	}
	read := func(id uint) model.AppInstall {
		t.Helper()
		var got model.AppInstall
		if err := global.DB.First(&got, id).Error; err != nil {
			t.Fatalf("read install %d failed: %v", id, err)
		}
		return got
	}

	t.Run("empty containers branch only writes status and message", func(t *testing.T) {
		install := seed("no-containers", constant.Running, "old error", "missing-1")
		synAppInstall(nil, stale(install), false)

		got := read(install.ID)
		if got.Status != constant.Error {
			t.Errorf("status = %q, want %q", got.Status, constant.Error)
		}
		if got.Message == "" {
			t.Error("message = empty, want the ErrContainerNotFound message")
		}
		if got.Version != "1.0" {
			t.Errorf("version = %q, want untouched 1.0", got.Version)
		}
		if got.ContainerName != "missing-1" {
			t.Errorf("container_name = %q, want untouched missing-1", got.ContainerName)
		}
		if got.Description != "" {
			t.Errorf("description = %q, want untouched empty value", got.Description)
		}
	})

	t.Run("main branch writes computed status and clears a stale message", func(t *testing.T) {
		install := seed("running", constant.Running, "old error from previous sync", "running-1")
		containers := map[string]types.Container{
			"/running-1": {Names: []string{"/running-1"}, State: "running"},
		}
		// the caller (SyncInstalled/handleInstalled) passes the snapshot read
		// from the DB; on the healthy path its message is empty, which the map
		// based Updates writes back verbatim, clearing the stale DB message
		snapshot := stale(install)
		snapshot.ContainerName = "running-1"
		snapshot.Message = ""
		synAppInstall(containers, snapshot, false)

		got := read(install.ID)
		if got.Status != constant.Running {
			t.Errorf("status = %q, want %q", got.Status, constant.Running)
		}
		if got.Message != "" {
			t.Errorf("message = %q, want cleared empty value", got.Message)
		}
		if got.Version != "1.0" {
			t.Errorf("version = %q, want untouched 1.0", got.Version)
		}
		if got.ContainerName != "running-1" {
			t.Errorf("container_name = %q, want untouched running-1", got.ContainerName)
		}
		if got.Description != "" {
			t.Errorf("description = %q, want untouched empty value", got.Description)
		}
	})

	t.Run("stale snapshot fields are never rolled back into the DB row", func(t *testing.T) {
		install := seed("stale-snapshot", constant.Running, "old error", "real-1")
		containers := map[string]types.Container{
			"/stale-container": {Names: []string{"/stale-container"}, State: "running"},
		}
		synAppInstall(containers, stale(install), false)

		got := read(install.ID)
		if got.Status != constant.Running {
			t.Errorf("status = %q, want %q", got.Status, constant.Running)
		}
		if got.Message != "old error" {
			t.Errorf("message = %q, want the in-memory message written back", got.Message)
		}
		// the old whole-row Save would have persisted the stale snapshot's
		// version/container/description into the DB
		if got.Version != "1.0" {
			t.Errorf("version = %q, want untouched 1.0 (old Save would roll it back to 0.9)", got.Version)
		}
		if got.ContainerName != "real-1" {
			t.Errorf("container_name = %q, want untouched real-1 (old Save would roll it back to stale-container)", got.ContainerName)
		}
		if got.Description != "" {
			t.Errorf("description = %q, want untouched empty value (old Save would write must-survive)", got.Description)
		}
	})

	t.Run("UpErr short-circuit and force semantics are preserved", func(t *testing.T) {
		install := seed("up-err", constant.UpErr, "keep me", "missing-2")
		// UpErr && !force: early return, nothing written
		synAppInstall(nil, stale(install), false)
		got := read(install.ID)
		if got.Status != constant.UpErr || got.Message != "keep me" {
			t.Errorf("row changed without force: got status=%q message=%q, want untouched UpErr/keep me", got.Status, got.Message)
		}
		if got.Version != "1.0" || got.ContainerName != "missing-2" {
			t.Errorf("non-status fields changed without force: version=%q container=%q", got.Version, got.ContainerName)
		}
		// force=true: the empty-containers branch runs and marks Error
		synAppInstall(nil, stale(install), true)
		got = read(install.ID)
		if got.Status != constant.Error {
			t.Errorf("status = %q, want %q with force", got.Status, constant.Error)
		}
		if got.Message == "" {
			t.Error("message = empty, want the ErrContainerNotFound message with force")
		}
		if got.Version != "1.0" || got.ContainerName != "missing-2" {
			t.Errorf("non-status fields changed by forced sync: version=%q container=%q", got.Version, got.ContainerName)
		}
	})
}
