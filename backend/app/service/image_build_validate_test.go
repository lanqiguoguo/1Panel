package service

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/app/dto"
	"github.com/1Panel-dev/1Panel/backend/buserr"
	"github.com/1Panel-dev/1Panel/backend/constant"
	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/1Panel-dev/1Panel/backend/utils/files"
	"github.com/sirupsen/logrus"
)

// TestValidNameComponent pins the whitelist that keeps the build directory
// (DataDir/docker/build/<name>), the build log path and the compose
// directory (DataDir/docker/compose/<name>) inside their roots.
func TestValidNameComponent(t *testing.T) {
	valid := []string{
		"myapp",
		"lib/nginx",
		"myapp:tag",
		"my-app_1.0",
		"Lib/nginx:1.2",
		"a", // single char
		strings.Repeat("a", 255),
	}
	for _, name := range valid {
		if !files.ValidNameComponent(name) {
			t.Errorf("ValidNameComponent(%q) = false, want true", name)
		}
	}

	invalid := []string{
		"../../evil",
		"x/../../evil",
		"..",
		".",
		"/abs",
		".hidden",
		"a//b", // empty component
		"a b",  // space
		"a$b",
		"a&b",
		"a;b",
		"a`b",
		"a<b",
		"a>b",
		"a(b)",
		"",
		strings.Repeat("a", 256),
	}
	for _, name := range invalid {
		if files.ValidNameComponent(name) {
			t.Errorf("ValidNameComponent(%q) = true, want false", name)
		}
	}
}

// TestImageBuildRejectsTraversal verifies that a malicious name is rejected
// before the docker client is created and before any directory or file is
// written. It uses a temp dir with an intentionally missing docker socket so
// that reaching docker.NewDockerClient would fail the test loudly; because
// the whitelist rejects the name first, the request never gets that far.
func TestImageBuildRejectsTraversal(t *testing.T) {
	if global.LOG == nil {
		global.LOG = logrus.New()
	}
	svc := &ImageService{}
	sock := os.Getenv("DOCKER_HOST")
	t.Cleanup(func() {
		if sock != "" {
			_ = os.Setenv("DOCKER_HOST", sock)
		} else {
			_ = os.Unsetenv("DOCKER_HOST")
		}
	})
	_ = os.Setenv("DOCKER_HOST", "unix:///nonexistent/1panel-test-docker.sock")

	cases := []dto.ImageBuild{
		{From: "edit", Name: "../../pwned", Dockerfile: "FROM alpine"},
		{From: "edit", Name: "x/../../pwned", Dockerfile: "FROM alpine"},
		{From: "edit", Name: "../pwned", Dockerfile: "FROM alpine"},
		{From: "edit", Name: "/abs", Dockerfile: "FROM alpine"},
		{From: "edit", Name: ".hidden", Dockerfile: "FROM alpine"},
		{From: "edit", Name: "a b", Dockerfile: "FROM alpine"},
		{From: "edit", Name: "a$b", Dockerfile: "FROM alpine"},
		{From: "edit", Name: "a//b", Dockerfile: "FROM alpine"},
	}
	for _, req := range cases {
		_, err := svc.ImageBuild(req)
		var be buserr.BusinessError
		if !errors.As(err, &be) || be.Msg != constant.ErrCmdIllegal {
			t.Errorf("ImageBuild(name=%q) error = %v, want ErrCmdIllegal", req.Name, err)
		}
	}
	for _, dir := range []string{"/tmp/pwned", "/tmp/1Panel-test-evil"} {
		if _, err := os.Stat(dir); err == nil {
			t.Errorf("traversal directory %s was created", dir)
		}
	}
}

// TestCreateComposeRejectsTraversal verifies the compose name whitelist
// rejects path traversal before any directory is created (loadPath runs
// after the validation).
func TestCreateComposeRejectsTraversal(t *testing.T) {
	if global.LOG == nil {
		global.LOG = logrus.New()
	}
	svc := &ContainerService{}
	cases := []dto.ComposeCreate{
		{Name: "../evil", From: "edit", File: "services:\n  app:\n    image: alpine\n"},
		{Name: "../../evil", From: "edit", File: "services:\n  app:\n    image: alpine\n"},
		{Name: "a/../evil", From: "edit", File: "services:\n  app:\n    image: alpine\n"},
		{Name: "a b", From: "edit", File: "services:\n  app:\n    image: alpine\n"},
		{Name: "a/b", From: "edit", File: "services:\n  app:\n    image: alpine\n"}, // frontend composeName allows no slash
	}
	for _, req := range cases {
		_, err := svc.CreateCompose(req)
		var be buserr.BusinessError
		if !errors.As(err, &be) || be.Msg != constant.ErrCmdIllegal {
			t.Errorf("CreateCompose(name=%q) error = %v, want ErrCmdIllegal", req.Name, err)
		}
	}

	// A valid name must be accepted by the whitelist and proceed to the
	// compose dir under DataDir. loadPath is the path-embedding sink for
	// CreateCompose; calling it directly avoids the docker-compose up goroutine
	// (which would deploy a real container on a reachable daemon).
	oldDataDir := global.CONF.System.DataDir
	oldConstantDataDir := constant.DataDir
	dataDir := t.TempDir()
	global.CONF.System.DataDir = dataDir
	constant.DataDir = dataDir
	t.Cleanup(func() {
		global.CONF.System.DataDir = oldDataDir
		constant.DataDir = oldConstantDataDir
	})

	req := dto.ComposeCreate{Name: "mycompose", From: "edit", File: "services:\n  app:\n    image: alpine\n"}
	if err := svc.loadPath(&req); err != nil {
		t.Fatalf("loadPath(valid name) unexpected error: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dataDir, "docker/compose/mycompose/docker-compose.yml")); err != nil {
		t.Errorf("valid compose name did not create compose file: %v", err)
	}
	_ = os.RemoveAll(filepath.Join(dataDir, "docker/compose/mycompose"))
}
