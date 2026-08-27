package service

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/1Panel-dev/1Panel/backend/app/dto"
	"github.com/1Panel-dev/1Panel/backend/app/model"
	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/glebarez/sqlite"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

// TestImagePushRealDaemon exercises ImagePush against the real local docker
// daemon and a throwaway registry container. Before the M4 fix the docker
// client was closed as ImagePush returned (defer in the caller) while the
// push goroutine was still using it, so the image never arrived; this test
// would time out and fail.
func TestImagePushRealDaemon(t *testing.T) {
	if global.LOG == nil {
		global.LOG = logrus.New()
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker CLI not found")
	}
	if out, err := exec.Command("docker", "info").CombinedOutput(); err != nil {
		t.Skipf("docker daemon not reachable: %v, out: %s", err, out)
	}

	// in-memory DB with an image repo row pointing at the local registry
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&model.ImageRepo{}); err != nil {
		t.Fatal(err)
	}
	oldDB := global.DB
	global.DB = db
	t.Cleanup(func() { global.DB = oldDB })

	port := freeTCPPort(t)
	repoName := fmt.Sprintf("127.0.0.1:%d", port)
	repo := model.ImageRepo{DownloadUrl: repoName}
	if err := db.Create(&repo).Error; err != nil {
		t.Fatal(err)
	}

	// throwaway registry container
	regCtr := "1panel-test-registry"
	_, _ = exec.Command("docker", "rm", "-f", regCtr).CombinedOutput()
	if out, err := exec.Command("docker", "run", "-d", "--name", regCtr,
		"-p", fmt.Sprintf("%d:5000", port), "registry:2").CombinedOutput(); err != nil {
		t.Skipf("cannot start registry (needs registry:2 image): %v, out: %s", err, out)
	}
	t.Cleanup(func() { _, _ = exec.Command("docker", "rm", "-f", regCtr).CombinedOutput() })

	// wait for the registry HTTP API
	waitRegistry(t, repoName)

	// tag a local image and push via ImagePush
	srcTag := "openresty/openresty:1.31-alpine-slim"
	targetName := "itest/hello:latest"
	if out, err := exec.Command("docker", "tag", srcTag, targetName).CombinedOutput(); err != nil {
		t.Skipf("cannot tag image: %v, out: %s", err, out)
	}
	t.Cleanup(func() { _, _ = exec.Command("docker", "rmi", targetName).CombinedOutput() })

	logFile, err := (&ImageService{}).ImagePush(dto.ImagePush{RepoID: repo.ID, TagName: targetName, Name: "hello"})
	if err != nil {
		t.Fatalf("ImagePush returned error: %v", err)
	}

	// wait for the async push goroutine to finish (it writes the log file)
	deadline := time.Now().Add(90 * time.Second)
	ok := false
	for time.Now().Before(deadline) {
		content, rerr := os.ReadFile(filepath.Join(global.CONF.System.TmpDir, "docker_logs", logFile))
		if rerr != nil && global.CONF.System.TmpDir == "" {
			content, rerr = os.ReadFile(filepath.Join("/docker_logs", logFile))
		}
		if rerr == nil && len(content) > 0 {
			if strings.Contains(string(content), "image push failed!") {
				t.Fatalf("push log indicates failure: %s", content)
			}
			if strings.Contains(string(content), "image push successful!") {
				ok = true
				break
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !ok {
		t.Fatal("push did not complete within 90s (use-after-close regression?)")
	}

	// confirm the image actually arrived in the registry
	manifestURL := fmt.Sprintf("http://%s/v2/hello/manifests/latest", repoName)
	req, _ := http.NewRequest(http.MethodHead, manifestURL, nil)
	req.Header.Set("Accept", "application/vnd.docker.distribution.manifest.v2+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("cannot reach registry manifest: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("image not found in registry: HTTP %d", resp.StatusCode)
	}
	t.Log("image push verified against real registry")
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func waitRegistry(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get("http://" + addr + "/v2/")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("registry %s HTTP API did not become ready", addr)
}

var _ = context.Background
