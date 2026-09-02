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

// TestVerifyComposeOperationPathRecorded pins the ownership check against the
// compose record persisted by CreateCompose: the operated path must match the
// recorded project path (or stay inside the recorded project directory) and
// nothing else.
func TestVerifyComposeOperationPathRecorded(t *testing.T) {
	_, dataDir, _ := setupComposeValidateTest(t)
	svc := &ContainerService{}

	recordedFile := filepath.Join(dataDir, "docker/compose/mycompose/docker-compose.yml")
	if err := composeRepo.CreateRecord(&model.Compose{Name: "mycompose", Path: recordedFile}); err != nil {
		t.Fatalf("seed record failed: %v", err)
	}
	projectDir := filepath.Dir(recordedFile)
	if err := os.MkdirAll(projectDir, 0755); err != nil {
		t.Fatalf("mkdir recorded project dir failed: %v", err)
	}
	if err := os.WriteFile(recordedFile, []byte("services: {}"), 0644); err != nil {
		t.Fatalf("write recorded compose file failed: %v", err)
	}

	cases := []struct {
		name string
		req  dto.ComposeOperation
		want string
		ok   bool
	}{
		{name: "exact recorded path", req: dto.ComposeOperation{Name: "mycompose", Path: recordedFile, Operation: "down"}, want: recordedFile, ok: true},
		{name: "file inside recorded project dir", req: dto.ComposeOperation{Name: "mycompose", Path: filepath.Join(projectDir, "docker-compose.override.yml"), Operation: "up"}, want: filepath.Join(projectDir, "docker-compose.override.yml"), ok: true},
		{name: "sibling project inside compose root rejected", req: dto.ComposeOperation{Name: "mycompose", Path: filepath.Join(dataDir, "docker/compose/other/docker-compose.yml"), Operation: "delete"}},
		{name: "outside record dir rejected", req: dto.ComposeOperation{Name: "mycompose", Path: filepath.Join(dataDir, "websites/foo/docker-compose.yml"), Operation: "up"}},
		{name: "recorded project dir itself as file path rejected", req: dto.ComposeOperation{Name: "mycompose", Path: projectDir, Operation: "down"}},
		{name: "path traversal sibling rejected", req: dto.ComposeOperation{Name: "mycompose", Path: filepath.Join(projectDir, "..", "other", "docker-compose.yml"), Operation: "delete"}},
	}
	for _, tc := range cases {
		got, err := svc.verifyComposeOperationPath(tc.req)
		if tc.ok {
			if err != nil || got != tc.want {
				t.Errorf("verifyComposeOperationPath(%s) = (%q, %v), want (%q, nil)", tc.name, got, err, tc.want)
			}
			continue
		}
		if err == nil {
			t.Errorf("verifyComposeOperationPath(%s) = (%q, nil), want error", tc.name, got)
		}
	}
}

// TestVerifyComposeOperationPathNoRecord covers the pre-record window: the
// delete request may land while CreateCompose's async `docker-compose up` has
// not written the record yet, so the path must fall inside the conventional
// project directory DataDir/docker/compose/<name>.
func TestVerifyComposeOperationPathNoRecord(t *testing.T) {
	_, dataDir, _ := setupComposeValidateTest(t)
	svc := &ContainerService{}
	composeRoot := filepath.Join(dataDir, "docker", "compose")

	inside := filepath.Join(composeRoot, "brandnew/docker-compose.yml")
	if err := os.MkdirAll(filepath.Dir(inside), 0755); err != nil {
		t.Fatalf("mkdir compose dir failed: %v", err)
	}
	if err := os.WriteFile(inside, []byte("services: {}"), 0644); err != nil {
		t.Fatalf("write compose file failed: %v", err)
	}

	cases := []struct {
		name string
		req  dto.ComposeOperation
		want string
		ok   bool
	}{
		{name: "conventional dir no record yet", req: dto.ComposeOperation{Name: "brandnew", Path: inside, Operation: "delete"}, want: inside, ok: true},
		{name: "different name dir no record", req: dto.ComposeOperation{Name: "brandnew", Path: filepath.Join(composeRoot, "someone-else/docker-compose.yml"), Operation: "down"}},
		{name: "arbitrary host dir no record", req: dto.ComposeOperation{Name: "brandnew", Path: "/etc/foo/docker-compose.yml", Operation: "delete"}},
		{name: "traversal out of compose root no record", req: dto.ComposeOperation{Name: "brandnew", Path: filepath.Join(dataDir, "apps/other/docker-compose.yml"), Operation: "down"}},
	}
	for _, tc := range cases {
		got, err := svc.verifyComposeOperationPath(tc.req)
		if tc.ok {
			if err != nil || got != tc.want {
				t.Errorf("verifyComposeOperationPath(%s) = (%q, %v), want (%q, nil)", tc.name, got, err, tc.want)
			}
			continue
		}
		if err == nil {
			t.Errorf("verifyComposeOperationPath(%s) = (%q, nil), want error", tc.name, got)
		}
	}
}

// TestVerifyComposeOperationPathEmptyPath pins the empty-path handling: for
// delete it drops the record only (historical cleanup flow for projects whose
// containers are already gone, see #6862), and it never touches any other
// operation. It asserts through the public ComposeOperation entry (the
// empty-path short-circuit lives there, before validation).
func TestVerifyComposeOperationPathEmptyPath(t *testing.T) {
	setupComposeValidateTest(t)
	svc := &ContainerService{}

	// empty path + delete with a record: record is removed, success returned
	if err := composeRepo.CreateRecord(&model.Compose{Name: "ghost", Path: "/opt/1panel/docker/compose/ghost/docker-compose.yml"}); err != nil {
		t.Fatalf("seed record failed: %v", err)
	}
	if err := svc.ComposeOperation(dto.ComposeOperation{Name: "ghost", Operation: "delete"}); err != nil {
		t.Fatalf("delete with empty path returned error: %v", err)
	}
	if item, err := composeRepo.GetRecord(commonRepo.WithByName("ghost")); err == nil && item.ID != 0 {
		t.Errorf("delete with empty path left the record behind")
	}
	// empty path + delete without a record: no error, record simply absent
	if err := svc.ComposeOperation(dto.ComposeOperation{Name: "nope", Operation: "delete"}); err != nil {
		t.Errorf("delete with empty path and no record returned error: %v", err)
	}
	// empty path on any other operation is rejected up front
	if err := svc.ComposeOperation(dto.ComposeOperation{Name: "ghost", Operation: "up"}); err == nil {
		t.Errorf("up with empty path did not return an error")
	}
	if err := svc.ComposeOperation(dto.ComposeOperation{Name: "ghost", Operation: "down"}); err == nil {
		t.Errorf("down with empty path did not return an error")
	}
}

// TestVerifyComposeOperationPathNameTraversal locks down the no-record branch
// against a malicious compose name: the conventional-dir fallback must not
// accept a name that escapes DataDir/docker/compose.
func TestVerifyComposeOperationPathNameTraversal(t *testing.T) {
	_, _, canaryDir := setupComposeValidateTest(t)
	svc := &ContainerService{}

	req := dto.ComposeOperation{Name: "../../pwned", Path: "/tmp/pwned/docker-compose.yml", Operation: "delete"}
	if _, err := svc.verifyComposeOperationPath(req); err == nil {
		t.Errorf("traversal name with arbitrary path did not return an error")
	}
	_ = os.RemoveAll(filepath.Join(canaryDir, "pwned"))
}
