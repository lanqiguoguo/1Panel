package service

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/1Panel-dev/1Panel/backend/app/dto"
	"github.com/1Panel-dev/1Panel/backend/buserr"
	"github.com/1Panel-dev/1Panel/backend/constant"
	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/1Panel-dev/1Panel/backend/utils/cmd"
	"github.com/1Panel-dev/1Panel/backend/utils/common"
	"github.com/1Panel-dev/1Panel/backend/utils/files"
	httpUtil "github.com/1Panel-dev/1Panel/backend/utils/http"
	"github.com/1Panel-dev/1Panel/backend/utils/systemctl"
)

type UpgradeService struct{}

// validUpgradeVersionRegexp pins req.Version to the version charset before it
// is interpolated into the upgrade package file name, the download URL and
// paths under the upgrade tmp dir ("1panel-<version>-linux-<arch>.tar.gz").
var validUpgradeVersionRegexp = regexp.MustCompile(`^[0-9A-Za-z.\-]+$`)

type IUpgradeService interface {
	Upgrade(req dto.Upgrade) error
	LoadNotes(req dto.Upgrade) (string, error)
	SearchUpgrade() (*dto.UpgradeInfo, error)
}

func NewIUpgradeService() IUpgradeService {
	return &UpgradeService{}
}

// fetchPackageChecksum downloads the checksum sidecar published next to the
// upgrade package (<package>.sha256.txt, sha256sum format). HandleGet returns
// an error for any non-200 response, so a missing asset fails closed. It is a
// package variable so tests can inject a local implementation (same pattern
// as validateDownloadURL in utils/files/file_op.go).
var fetchPackageChecksum = func(url string) ([]byte, error) {
	_, body, err := httpUtil.HandleGet(url, http.MethodGet, constant.TimeOut20s)
	return body, err
}

// parseChecksum extracts the digest from a sha256sum-generated checksum file
// ("<hash>  <filename>"); blank lines and extra whitespace are tolerated.
func parseChecksum(content string) (string, error) {
	for _, line := range strings.Split(content, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		digest := strings.ToLower(fields[0])
		if len(digest) != 64 {
			break
		}
		if _, err := hex.DecodeString(digest); err != nil {
			break
		}
		return digest, nil
	}
	return "", fmt.Errorf("checksum file does not contain a valid sha256 digest")
}

// fileSHA256 streams path through crypto/sha256 without loading the whole
// file into memory.
func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open %s failed: %w", path, err)
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("hash %s failed: %w", path, err)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// verifyPackageDownload checks the downloaded package against the checksum
// sidecar published next to it in the release channel. Every failure path
// (fetch error, missing/malformed checksum, hash mismatch) returns a business
// error so the upgrade aborts before the package is extracted or executed.
func verifyPackageDownload(packageFile, checksumURL string) error {
	checksumData, err := fetchPackageChecksum(checksumURL)
	if err != nil {
		return buserr.WithDetail(constant.ErrUpgradeVerifyFailed,
			fmt.Sprintf("fetch checksum file %s failed: %v", checksumURL, err), nil)
	}
	expected, err := parseChecksum(string(checksumData))
	if err != nil {
		return buserr.WithDetail(constant.ErrUpgradeVerifyFailed, err.Error(), nil)
	}
	actual, err := fileSHA256(packageFile)
	if err != nil {
		return buserr.WithDetail(constant.ErrUpgradeVerifyFailed, err.Error(), nil)
	}
	if expected != actual {
		return buserr.WithDetail(constant.ErrUpgradeVerifyFailed,
			fmt.Sprintf("sha256 mismatch for %s: expected %s, got %s", filepath.Base(packageFile), expected, actual), nil)
	}
	return nil
}

func (u *UpgradeService) SearchUpgrade() (*dto.UpgradeInfo, error) {
	var upgrade dto.UpgradeInfo
	currentVersion, err := settingRepo.Get(settingRepo.WithByKey("SystemVersion"))
	if err != nil {
		return nil, err
	}
	DeveloperMode, err := settingRepo.Get(settingRepo.WithByKey("DeveloperMode"))
	if err != nil {
		return nil, err
	}

	upgrade.TestVersion, upgrade.NewVersion, upgrade.LatestVersion = u.loadVersionByMode(DeveloperMode.Value, currentVersion.Value)
	var itemVersion string
	if len(upgrade.LatestVersion) != 0 {
		itemVersion = upgrade.LatestVersion
	}
	if len(upgrade.NewVersion) != 0 {
		itemVersion = upgrade.NewVersion
	}
	if (global.CONF.System.Mode == "dev" || DeveloperMode.Value == "enable") && len(upgrade.TestVersion) != 0 {
		itemVersion = upgrade.TestVersion
	}
	if len(itemVersion) == 0 {
		return &upgrade, nil
	}
	mode := global.CONF.System.Mode
	if strings.Contains(itemVersion, "beta") {
		mode = "beta"
	}
	notes, err := u.loadReleaseNotes(fmt.Sprintf("%s/%s/%s/release/1panel-%s-release-notes", global.CONF.System.RepoUrl, mode, itemVersion, itemVersion))
	if err != nil {
		return nil, fmt.Errorf("load releases-notes of version %s failed, err: %v", itemVersion, err)
	}
	upgrade.ReleaseNote = notes
	return &upgrade, nil
}

// LoadNotes fetches the release notes of req.Version for display. req.Version
// is interpolated into the release-notes URL, so it must pass the same
// version-charset gate as Upgrade before any request is made.
func (u *UpgradeService) LoadNotes(req dto.Upgrade) (string, error) {
	if !validUpgradeVersionRegexp.MatchString(req.Version) {
		return "", fmt.Errorf("invalid upgrade version: %s", req.Version)
	}
	mode := global.CONF.System.Mode
	if strings.Contains(req.Version, "beta") {
		mode = "beta"
	}
	notes, err := u.loadReleaseNotes(fmt.Sprintf("%s/%s/%s/release/1panel-%s-release-notes", global.CONF.System.RepoUrl, mode, req.Version, req.Version))
	if err != nil {
		return "", fmt.Errorf("load releases-notes of version %s failed, err: %v", req.Version, err)
	}
	return notes, nil
}

func (u *UpgradeService) Upgrade(req dto.Upgrade) error {
	if !validUpgradeVersionRegexp.MatchString(req.Version) {
		return fmt.Errorf("invalid upgrade version: %s", req.Version)
	}
	global.LOG.Info("start to upgrade now...")
	fileOp := files.NewFileOp()
	timeStr := time.Now().Format(constant.DateTimeSlimLayout)
	rootDir := path.Join(global.CONF.System.TmpDir, fmt.Sprintf("upgrade/upgrade_%s/downloads", timeStr))
	originalDir := path.Join(global.CONF.System.TmpDir, fmt.Sprintf("upgrade/upgrade_%s/original", timeStr))
	if err := os.MkdirAll(rootDir, os.ModePerm); err != nil {
		return err
	}
	if err := os.MkdirAll(originalDir, os.ModePerm); err != nil {
		return err
	}
	itemArch, err := loadArch()
	if err != nil {
		return err
	}

	mode := global.CONF.System.Mode
	if strings.Contains(req.Version, "beta") {
		mode = "beta"
	}
	fileName := fmt.Sprintf("1panel-%s-%s-%s.tar.gz", req.Version, "linux", itemArch)
	downloadURL := fmt.Sprintf("%s/%s/%s/release/%s", global.CONF.System.RepoUrl, mode, req.Version, fileName)
	if global.CONF.System.PackageUrl != "" {
		downloadURL = fmt.Sprintf("%s/%s", global.CONF.System.PackageUrl, fileName)
	}
	serviceHandle, _ := systemctl.DefaultHandler("1panel")
	currentServiceName := serviceHandle.GetServiceName()
	// The GlobalLoading middleware only guards each request up to this point:
	// two concurrent Upgrade calls can both pass it and reach here before
	// either has written SystemStatus. Claim the status atomically below so
	// only one upgrade ever mutates the binaries/rollback copies, including
	// across panel processes on the same database. An upgrade request
	// arriving while the panel is already busy (another upgrade, a snapshot
	// recover/rollback or any other non-Free SystemStatus owner) is refused
	// without side effects: claimUpgradeStatus also fails fast when
	// SystemStatus is already non-Free.
	if err := u.claimUpgradeStatus(); err != nil {
		return err
	}
	go func() {
		defer func() {
			if err := settingRepo.Update("SystemStatus", "Free"); err != nil {
				global.LOG.Errorf("Reset system status failed: %v", err)
			}
		}()

		_ = global.Cron.Stop()
		defer global.Cron.Start()

		if err := fileOp.DownloadFileWithProxy(
			downloadURL,
			path.Join(rootDir, fileName),
		); err != nil {
			global.LOG.Errorf("Failed to download upgrade package: %v", err)
			return
		}
		defer os.RemoveAll(rootDir)

		// verify package integrity before anything is extracted or executed
		if err := verifyPackageDownload(path.Join(rootDir, fileName), downloadURL+".sha256.txt"); err != nil {
			global.LOG.Errorf("Upgrade aborted, package verification failed: %v", err)
			return
		}

		if err := handleUnTar(path.Join(rootDir, fileName), rootDir, ""); err != nil {
			global.LOG.Errorf("Failed to extract package: %v", err)
			return
		}

		tmpDir := path.Join(rootDir, strings.TrimSuffix(fileName, ".tar.gz"))

		if err := u.handleBackup(fileOp, originalDir); err != nil {
			global.LOG.Errorf("Backup failed: %v", err)
			return
		}

		binDir := systemctl.BinaryPath
		servicePath, _ := serviceHandle.GetServicePath()
		geoPath := path.Join(global.CONF.System.BaseDir, "1panel/geo/GeoIP.mmdb")

		criticalUpdates := []struct {
			src  string
			dest string
			step int
		}{
			{path.Join(tmpDir, "1panel"), path.Join(binDir, "1panel"), 1},
			{path.Join(tmpDir, "1pctl"), path.Join(binDir, "1pctl"), 2},
			{selectInitScript(path.Join(tmpDir, "initscript"), currentServiceName), servicePath, 3},
		}

		for _, update := range criticalUpdates {
			if err := common.Copy(update.src, update.dest); err != nil {
				global.LOG.Errorf("Update %s failed: %v", path.Base(update.dest), err)
				u.handleRollback(originalDir, update.step)
				return
			}
		}

		if err := u.migrate1pctlParams(path.Join(originalDir, "1pctl"), path.Join(binDir, "1pctl"), req.Version); err != nil {
			global.LOG.Errorf("Migrate 1pctl params failed: %v", err)
			u.handleRollback(originalDir, 2)
			return
		}

		langDir := path.Join(binDir, "lang")
		if err := common.Copy(path.Join(tmpDir, "lang"), langDir); err != nil {
			global.LOG.Errorf("Update language files failed: %v", err)
		}
		if err := common.Copy(path.Join(tmpDir, "GeoIP.mmdb"), geoPath); err != nil {
			global.LOG.Warnf("Update GeoIP database failed: %v", err)
		}

		global.LOG.Info("upgrade successful!")
		checkPointOfWal()
		if err := settingRepo.Update("SystemVersion", req.Version); err != nil {
			global.LOG.Errorf("Update system version failed: %v", err)
		}
		if serviceHandle.ManagerName() == "systemd" {
			_, _ = cmd.Exec("systemctl daemon-reload")
		}
		if err := systemctl.Restart("1panel"); err != nil {
			global.LOG.Errorf("Service restart failed: %v", err)
			return
		}
	}()
	return nil
}

// upgradeTaskMu serializes the SystemStatus claim inside this process.
// settingRepo.CAS is the authoritative gate (it also covers concurrent panel
// processes on the same database); the mutex additionally closes the window
// between two in-process calls, where the second CAS would otherwise fail
// only after the first goroutine had already started downloading.
var upgradeTaskMu sync.Mutex

// claimUpgradeStatus atomically takes ownership of the upgrade flow: it
// flips SystemStatus Free -> Upgrading exactly once. A concurrent upgrade
// (or any other flow that already holds SystemStatus non-Free, e.g. a
// snapshot recover/rollback that never releases it) fails the CAS and the
// request is refused with upgradeTaskBusy without any side effect: the
// panel never runs two flows that both replace /usr/local/bin/1panel and
// roll back each other's backup copies.
func (u *UpgradeService) claimUpgradeStatus() error {
	upgradeTaskMu.Lock()
	defer upgradeTaskMu.Unlock()
	// Fast path within this process: the status is already claimed by an
	// upgrade running right now, no DB round-trip needed.
	status, err := settingRepo.Get(settingRepo.WithByKey("SystemStatus"))
	if err != nil {
		return fmt.Errorf("load system status failed: %w", err)
	}
	if status.Value == "Upgrading" {
		return upgradeTaskBusy()
	}
	claimed, err := settingRepo.CAS("SystemStatus", "Free", "Upgrading")
	if err != nil {
		return fmt.Errorf("claim upgrade status failed: %w", err)
	}
	if !claimed {
		return upgradeTaskBusy()
	}
	return nil
}

// upgradeTaskBusy is the business error reported when the upgrade claim is
// held by another flow: an upgrade already in progress, or the panel is
// otherwise busy (SystemStatus non-Free, e.g. a snapshot recover/rollback).
// The losing request must not start any download or file mutation.
func upgradeTaskBusy() error {
	return buserr.New(constant.ErrUpgradeTaskBusy)
}

// migrate1pctlParams rewrites the freshly installed 1pctl so local
// installation parameters survive an upgrade; only ORIGINAL_VERSION comes
// from req.Version. Non-dev mode reads port/username/entrance/language from
// these keys (see init/viper). The password is persisted in the database after
// first boot and must never be copied into the executable control script.
func (u *UpgradeService) migrate1pctlParams(backupPath, targetPath string, newVersion string) error {
	backupData, err := os.ReadFile(backupPath)
	if err != nil {
		return fmt.Errorf("read backup 1pctl failed: %w", err)
	}
	params := map[string]string{}
	for _, line := range strings.Split(string(backupData), "\n") {
		key, value, found := strings.Cut(line, "=")
		if !found || value == "" {
			continue
		}
		switch key {
		case "BASE_DIR", "ORIGINAL_PORT", "ORIGINAL_USERNAME", "ORIGINAL_ENTRANCE", "LANGUAGE", "CHANGE_USER_INFO":
			params[key] = value
		}
	}
	if global.CONF.System.BaseDir != "" {
		params["BASE_DIR"] = global.CONF.System.BaseDir
	}
	params["ORIGINAL_VERSION"] = newVersion

	targetData, err := os.ReadFile(targetPath)
	if err != nil {
		return fmt.Errorf("read target 1pctl failed: %w", err)
	}
	lines := strings.Split(string(targetData), "\n")
	rewritten := make([]string, 0, len(lines)+len(params))
	for _, line := range lines {
		key, _, found := strings.Cut(line, "=")
		if !found {
			rewritten = append(rewritten, line)
			continue
		}
		if key == "ORIGINAL_PASSWORD" {
			continue
		}
		if value, ok := params[key]; ok {
			line = key + "=" + value
			delete(params, key)
		}
		rewritten = append(rewritten, line)
	}
	lines = rewritten
	insertAt := len(lines)
	if insertAt > 0 && lines[insertAt-1] == "" {
		insertAt--
	}
	appended := make([]string, 0, len(params))
	for key, value := range params {
		appended = append(appended, key+"="+value)
	}
	sort.Strings(appended)
	lines = append(lines[:insertAt], append(appended, lines[insertAt:]...)...)
	if err := os.WriteFile(targetPath, []byte(strings.Join(lines, "\n")), 0755); err != nil {
		return fmt.Errorf("write target 1pctl failed: %w", err)
	}
	return nil
}

func (u *UpgradeService) handleBackup(fileOp files.FileOp, originalDir string) error {
	global.LOG.Info("Initiating backup procedure...")
	h, _ := systemctl.DefaultHandler("1panel")
	binDir := systemctl.BinaryPath
	servicePath, _ := h.GetServicePath()
	geoPath := path.Join(global.CONF.System.BaseDir, "1panel/geo/GeoIP.mmdb")

	backupItems := []struct {
		src  string
		dest string
	}{
		{path.Join(binDir, "1panel"), originalDir},
		{path.Join(binDir, "1pctl"), originalDir},
		{servicePath, originalDir},
		{path.Join(binDir, "lang"), originalDir},
		{geoPath, originalDir},
	}

	for _, item := range backupItems {
		if err := fileOp.Copy(item.src, item.dest); err != nil {
			return fmt.Errorf("backup %s failed: %w", path.Base(item.src), err)
		}
	}
	// The previous control script may contain the legacy plaintext password.
	// Keep the rollback copy executable by root but unreadable to other local
	// users; the installed replacement never receives ORIGINAL_PASSWORD.
	if err := os.Chmod(path.Join(originalDir, "1pctl"), 0600); err != nil {
		return fmt.Errorf("secure backup 1pctl failed: %w", err)
	}

	if err := handleTar(
		path.Join(global.CONF.System.BaseDir, "1panel/db"),
		originalDir,
		"db.tar.gz",
		"db/1Panel.db-*",
		"",
	); err != nil {
		return fmt.Errorf("database backup failed: %w", err)
	}
	return nil
}

func (u *UpgradeService) handleRollback(originalDir string, errStep int) {
	global.LOG.Info("Initiating rollback procedure...")
	h, _ := systemctl.DefaultHandler("1panel")
	binDir := systemctl.BinaryPath
	servicePath, _ := h.GetServicePath()
	geoPath := path.Join(global.CONF.System.BaseDir, "1panel/geo/GeoIP.mmdb")

	rollbackSteps := []struct {
		src  string
		dest string
	}{
		{path.Join(originalDir, "1panel"), path.Join(binDir, "1panel")},
		{path.Join(originalDir, "1pctl"), path.Join(binDir, "1pctl")},
		{path.Join(originalDir, filepath.Base(servicePath)), servicePath},
		{path.Join(originalDir, "lang"), path.Join(binDir, "lang")},
		{path.Join(originalDir, "GeoIP.mmdb"), geoPath},
	}

	for _, step := range rollbackSteps[:errStep] {
		if err := common.CopyFile(step.src, step.dest); err != nil {
			global.LOG.Errorf("Rollback %s failed: %v", path.Base(step.src), err)
		}
	}

	if err := systemctl.Restart("1panel"); err != nil {
		global.LOG.Errorf("Service restart during rollback failed: %v", err)
	}
}

func (u *UpgradeService) loadVersionByMode(developer, currentVersion string) (string, string, string) {
	var current, latest string
	if global.CONF.System.Mode == "dev" {
		betaVersionLatest := u.loadVersion(true, currentVersion, "beta")
		devVersionLatest := u.loadVersion(true, currentVersion, "dev")
		if common.ComparePanelVersion(betaVersionLatest, devVersionLatest) {
			return betaVersionLatest, "", ""
		}
		return devVersionLatest, "", ""
	}

	betaVersionLatest := ""
	latest = u.loadVersion(true, currentVersion, "stable")
	current = u.loadVersion(false, currentVersion, "stable")
	if developer == "enable" {
		betaVersionLatest = u.loadVersion(true, currentVersion, "beta")
	}
	if current != latest {
		return betaVersionLatest, current, latest
	}

	versionPart := strings.Split(current, ".")
	if len(versionPart) < 3 {
		return betaVersionLatest, current, latest
	}
	num, _ := strconv.Atoi(versionPart[1])
	if num == 0 {
		return betaVersionLatest, current, latest
	}
	if num >= 10 {
		if current[:6] == currentVersion[:6] {
			return betaVersionLatest, current, ""
		}
		return betaVersionLatest, "", latest
	}
	if current[:5] == currentVersion[:5] {
		return betaVersionLatest, current, ""
	}
	return betaVersionLatest, "", latest
}

func (u *UpgradeService) loadVersion(isLatest bool, currentVersion, mode string) string {
	path := fmt.Sprintf("%s/%s/latest", global.CONF.System.RepoUrl, mode)
	if !isLatest {
		path = fmt.Sprintf("%s/%s/latest.current", global.CONF.System.RepoUrl, mode)
	}
	_, latestVersionRes, err := httpUtil.HandleGet(path, http.MethodGet, constant.TimeOut20s)
	if err != nil {
		global.LOG.Errorf("load latest version from oss failed, err: %v", err)
		return ""
	}
	version := strings.TrimSpace(string(latestVersionRes))
	if strings.Contains(version, "<") {
		global.LOG.Errorf("load latest version from oss failed, err: %v", version)
		return ""
	}
	if isLatest {
		return u.checkVersion(version, currentVersion)
	}

	versionMap := make(map[string]string)
	if err := json.Unmarshal(latestVersionRes, &versionMap); err != nil {
		global.LOG.Errorf("load latest version from oss failed (error unmarshal), err: %v", err)
		return ""
	}

	versionPart := strings.Split(currentVersion, ".")
	if len(versionPart) < 3 {
		global.LOG.Errorf("current version is error format: %s", currentVersion)
		return ""
	}
	num, _ := strconv.Atoi(versionPart[1])
	if num == 0 {
		global.LOG.Errorf("current version is error format: %s", currentVersion)
		return ""
	}
	if num >= 10 {
		if version, ok := versionMap[currentVersion[0:5]]; ok {
			return u.checkVersion(strings.TrimSpace(version), currentVersion)
		}
		return ""
	}
	if version, ok := versionMap[currentVersion[0:4]]; ok {
		return u.checkVersion(strings.TrimSpace(version), currentVersion)
	}
	return ""
}

func (u *UpgradeService) checkVersion(v2, v1 string) string {
	addSuffix := false
	v2 = strings.TrimSpace(v2)
	if !strings.Contains(v1, "-") {
		v1 = v1 + "-lts"
	}
	if !strings.Contains(v2, "-") {
		addSuffix = true
		v2 = v2 + "-lts"
	}
	if common.ComparePanelVersion(v2, v1) {
		if addSuffix {
			return strings.TrimSuffix(v2, "-lts")
		}
		return v2
	}
	return ""
}

func (u *UpgradeService) loadReleaseNotes(path string) (string, error) {
	_, releaseNotes, err := httpUtil.HandleGet(path, http.MethodGet, constant.TimeOut20s)
	if err != nil {
		return "", err
	}
	return string(releaseNotes), nil
}

func loadArch() (string, error) {
	std, err := cmd.Exec("uname -a")
	if err != nil {
		return "", fmt.Errorf("std: %s, err: %s", std, err.Error())
	}
	if strings.Contains(std, "x86_64") {
		return "amd64", nil
	}
	if strings.Contains(std, "arm64") || strings.Contains(std, "aarch64") {
		return "arm64", nil
	}
	if strings.Contains(std, "armv7l") {
		return "armv7", nil
	}
	if strings.Contains(std, "ppc64le") {
		return "ppc64le", nil
	}
	if strings.Contains(std, "s390x") {
		return "s390x", nil
	}
	if strings.Contains(std, "riscv64") {
		return "riscv64", nil
	}
	return "", fmt.Errorf("unsupported such arch: %s", std)
}

func selectInitScript(path string, serviceName string) string {
	path = strings.TrimSuffix(path, "/")
	mgr := systemctl.GetGlobalManager().Name()
	var serviceFileName string
	switch mgr {
	case "systemd":
		serviceFileName = "1panel.service"
	case "openrc":
		serviceFileName = "1paneld.openrc"
	case "sysvinit":
		isWrt := systemctl.FileExist("/etc/rc.common")
		if isWrt {
			serviceFileName = "1paneld.procd"
		} else {
			serviceFileName = "1paneld.init"
		}
	default:
		serviceFileName = serviceName
		global.LOG.Warnf("[%s]unselect InitScript, used default: %s", mgr, serviceName)
	}
	sourcePath := filepath.Join(path, serviceFileName)
	targetPath := filepath.Join(path, serviceName)

	if serviceFileName != serviceName {
		if _, err := cmd.Execf("cp %s %s", sourcePath, targetPath); err != nil {
			global.LOG.Errorf("Failed to copy init script from %s to %s: %v",
				serviceFileName, serviceName, err)
		}
	}

	return targetPath
}
