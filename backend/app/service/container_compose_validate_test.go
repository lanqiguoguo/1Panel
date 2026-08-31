package service

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/app/dto"
	"github.com/1Panel-dev/1Panel/backend/app/model"
	"github.com/1Panel-dev/1Panel/backend/buserr"
	"github.com/1Panel-dev/1Panel/backend/constant"
	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/glebarez/sqlite"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

// setupComposeValidateTest mirrors the in-memory sqlite harness used by
// app_utils_test.go: TestCompose reads the compose record table before
// reaching loadPath, so the composes table must exist.
func setupComposeValidateTest(t *testing.T) (baseDir, dataDir, canaryDir string) {
	t.Helper()
	if global.LOG == nil {
		global.LOG = logrus.New()
	}
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open in-memory sqlite failed: %v", err)
	}
	if err := db.AutoMigrate(&model.Compose{}); err != nil {
		t.Fatalf("migrate composes failed: %v", err)
	}
	oldDB := global.DB
	global.DB = db
	t.Cleanup(func() { global.DB = oldDB })

	// Redirect the compose root to a throwaway dir and plant a canary next to
	// it: the traversal payloads below (../../pwned, ..) would escape
	// dataDir/docker/compose into baseDir, so any write outside dataDir (or
	// into canaryDir) must be detected.
	baseDir = t.TempDir()
	dataDir = filepath.Join(baseDir, "data")
	canaryDir = filepath.Join(baseDir, "canary")
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		t.Fatalf("mkdir dataDir failed: %v", err)
	}
	if err := os.MkdirAll(canaryDir, 0755); err != nil {
		t.Fatalf("mkdir canaryDir failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(canaryDir, "marker.txt"), []byte("canary"), 0644); err != nil {
		t.Fatalf("write canary marker failed: %v", err)
	}

	oldDataDir := constant.DataDir
	oldConfDataDir := global.CONF.System.DataDir
	constant.DataDir = dataDir
	global.CONF.System.DataDir = dataDir
	t.Cleanup(func() {
		constant.DataDir = oldDataDir
		global.CONF.System.DataDir = oldConfDataDir
	})
	return baseDir, dataDir, canaryDir
}

// TestTestComposeRejectsTraversal verifies that TestCompose rejects a
// malicious compose name before loadPath touches the filesystem. The check
// lives at the top of loadPath so every caller shares it.
func TestTestComposeRejectsTraversal(t *testing.T) {
	baseDir, dataDir, canaryDir := setupComposeValidateTest(t)
	svc := &ContainerService{}

	cases := []dto.ComposeCreate{
		{Name: "../../pwned", From: "edit", File: "services:\n  app:\n    image: alpine\n"},
		{Name: "a/b", From: "edit", File: "services:\n  app:\n    image: alpine\n"},
		{Name: "a:b", From: "edit", File: "services:\n  app:\n    image: alpine\n"},
		{Name: "..", From: "edit", File: "services:\n  app:\n    image: alpine\n"},
	}
	for _, req := range cases {
		_, err := svc.TestCompose(req)
		var be buserr.BusinessError
		if !errors.As(err, &be) || be.Msg != constant.ErrCmdIllegal {
			t.Errorf("TestCompose(name=%q) error = %v, want ErrCmdIllegal", req.Name, err)
		}
	}

	// Canary assertions: nothing escaped the compose root.
	entries, err := os.ReadDir(baseDir)
	if err != nil {
		t.Fatalf("read baseDir failed: %v", err)
	}
	for _, e := range entries {
		switch e.Name() {
		case "data", "canary":
		default:
			t.Errorf("unexpected entry %s created under baseDir", e.Name())
		}
	}
	canaryEntries, err := os.ReadDir(canaryDir)
	if err != nil {
		t.Fatalf("read canaryDir failed: %v", err)
	}
	if len(canaryEntries) != 1 || canaryEntries[0].Name() != "marker.txt" {
		t.Errorf("canary dir was modified: %v", canaryEntries)
	}
	if _, err := os.Stat(filepath.Join(dataDir, "docker")); !os.IsNotExist(err) {
		t.Errorf("compose root was created despite rejected names, err = %v", err)
	}
}

// TestComposeLoadPathValidName verifies that loadPath still materializes the
// compose dir and docker-compose.yml under the (redirected) DataDir for a
// benign name.
func TestComposeLoadPathValidName(t *testing.T) {
	_, dataDir, _ := setupComposeValidateTest(t)
	svc := &ContainerService{}

	content := "services:\n  app:\n    image: alpine\n"
	req := dto.ComposeCreate{Name: "mycompose", From: "edit", File: content}
	if err := svc.loadPath(&req); err != nil {
		t.Fatalf("loadPath(valid name) unexpected error: %v", err)
	}
	composeFile := filepath.Join(dataDir, "docker/compose/mycompose/docker-compose.yml")
	got, err := os.ReadFile(composeFile)
	if err != nil {
		t.Fatalf("loadPath(valid name) did not create compose file: %v", err)
	}
	if string(got) != content {
		t.Errorf("compose file content = %q, want %q", string(got), content)
	}
	if req.Path != composeFile {
		t.Errorf("loadPath did not set req.Path = %q", req.Path)
	}
	_ = os.RemoveAll(filepath.Join(dataDir, "docker/compose/mycompose"))
}
