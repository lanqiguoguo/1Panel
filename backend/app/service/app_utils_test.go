package service

import (
	"context"
	"errors"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/app/model"
	"github.com/1Panel-dev/1Panel/backend/constant"
	"github.com/1Panel-dev/1Panel/backend/global"
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
