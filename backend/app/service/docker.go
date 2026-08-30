package service

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/1Panel-dev/1Panel/backend/app/dto"
	"github.com/1Panel-dev/1Panel/backend/constant"
	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/1Panel-dev/1Panel/backend/utils/cmd"
	"github.com/1Panel-dev/1Panel/backend/utils/docker"
	"github.com/1Panel-dev/1Panel/backend/utils/encrypt"
	"github.com/1Panel-dev/1Panel/backend/utils/systemctl"
	"github.com/pkg/errors"
)

type DockerService struct{}

// daemonJsonMu serializes every daemon.json read-modify-write + validate +
// restart critical section (UpdateConf, UpdateLogOption, UpdateIpv6Option,
// UpdateConfByFile, applyDaemonJsonProxies):
// daemon.json is a single-file global config, so writers must be mutually
// exclusive to prevent concurrent writes overwriting each other and rollbacks
// reading a half-written file.
var daemonJsonMu sync.Mutex

type IDockerService interface {
	UpdateConf(req dto.SettingUpdate) error
	UpdateLogOption(req dto.LogOption) error
	UpdateIpv6Option(req dto.Ipv6Option) error
	UpdateConfByFile(info dto.DaemonJsonUpdateByFile) error
	LoadDockerStatus() string
	LoadDockerConf() *dto.DaemonJsonConf
	OperateDocker(req dto.DockerOperation) error
}

func NewIDockerService() IDockerService {
	return &DockerService{}
}

type daemonJsonItem struct {
	Status       string    `json:"status"`
	Mirrors      []string  `json:"registry-mirrors"`
	Registries   []string  `json:"insecure-registries"`
	LiveRestore  bool      `json:"live-restore"`
	Ipv6         bool      `json:"ipv6"`
	FixedCidrV6  string    `json:"fixed-cidr-v6"`
	Ip6Tables    bool      `json:"ip6tables"`
	Experimental bool      `json:"experimental"`
	IPTables     bool      `json:"iptables"`
	ExecOpts     []string  `json:"exec-opts"`
	LogOption    logOption `json:"log-opts"`
}
type logOption struct {
	LogMaxSize string `json:"max-size"`
	LogMaxFile string `json:"max-file"`
}

func (u *DockerService) LoadDockerStatus() string {
	client, err := docker.NewDockerClient()
	if err != nil {
		return constant.Stopped
	}
	defer client.Close()
	if _, err := client.Ping(context.Background()); err != nil {
		return constant.Stopped
	}

	return constant.StatusRunning
}

func (u *DockerService) LoadDockerConf() *dto.DaemonJsonConf {
	ctx := context.Background()
	var data dto.DaemonJsonConf
	data.IPTables = true
	data.Status = constant.StatusRunning
	data.Version = "-"
	client, err := docker.NewDockerClient()
	if err != nil {
		data.Status = constant.Stopped
	} else {
		defer client.Close()
		if _, err := client.Ping(ctx); err != nil {
			data.Status = constant.Stopped
		}
		itemVersion, err := client.ServerVersion(ctx)
		if err == nil {
			data.Version = itemVersion.Version
		}
	}
	data.IsSwarm = false
	stdout2, _ := cmd.Exec("docker info  | grep Swarm")
	if string(stdout2) == " Swarm: active\n" {
		data.IsSwarm = true
	}
	if _, err := os.Stat(constant.DaemonJsonPath); err != nil {
		return &data
	}
	file, err := os.ReadFile(constant.DaemonJsonPath)
	if err != nil {
		return &data
	}
	var conf daemonJsonItem
	daemonMap := make(map[string]interface{})
	if err := json.Unmarshal(file, &daemonMap); err != nil {
		return &data
	}
	arr, err := json.Marshal(daemonMap)
	if err != nil {
		return &data
	}
	if err := json.Unmarshal(arr, &conf); err != nil {
		return &data
	}
	if _, ok := daemonMap["iptables"]; !ok {
		conf.IPTables = true
	}
	data.CgroupDriver = "cgroupfs"
	for _, opt := range conf.ExecOpts {
		if strings.HasPrefix(opt, "native.cgroupdriver=") {
			data.CgroupDriver = strings.ReplaceAll(opt, "native.cgroupdriver=", "")
			break
		}
	}
	data.Ipv6 = conf.Ipv6
	data.FixedCidrV6 = conf.FixedCidrV6
	data.Ip6Tables = conf.Ip6Tables
	data.Experimental = conf.Experimental
	data.LogMaxSize = conf.LogOption.LogMaxSize
	data.LogMaxFile = conf.LogOption.LogMaxFile
	data.Mirrors = conf.Mirrors
	data.Registries = conf.Registries
	data.IPTables = conf.IPTables
	data.LiveRestore = conf.LiveRestore
	return &data
}

func (u *DockerService) UpdateConf(req dto.SettingUpdate) error {
	daemonJsonMu.Lock()
	defer daemonJsonMu.Unlock()
	// Snapshot the current daemon.json before touching it: a config that
	// fails dockerd validation below would otherwise be left on disk, taking
	// the daemon down (or preventing a restart) until a manual fix.
	backup, err := backupDaemonJson(constant.DaemonJsonPath)
	if err != nil {
		return fmt.Errorf("backup %s failed: %w", constant.DaemonJsonPath, err)
	}
	err = createIfNotExistDaemonJsonFile(constant.DaemonJsonPath)
	if err != nil {
		return err
	}
	file, err := os.ReadFile(constant.DaemonJsonPath)
	if err != nil {
		return err
	}
	daemonMap := make(map[string]interface{})
	_ = json.Unmarshal(file, &daemonMap)

	switch req.Key {
	case "Registries":
		req.Value = strings.TrimSuffix(req.Value, ",")
		if len(req.Value) == 0 {
			delete(daemonMap, "insecure-registries")
		} else {
			daemonMap["insecure-registries"] = strings.Split(req.Value, ",")
		}
	case "Mirrors":
		req.Value = strings.TrimSuffix(req.Value, ",")
		if len(req.Value) == 0 {
			delete(daemonMap, "registry-mirrors")
		} else {
			daemonMap["registry-mirrors"] = strings.Split(req.Value, ",")
		}
	case "Ipv6":
		if req.Value == "disable" {
			delete(daemonMap, "ipv6")
			delete(daemonMap, "fixed-cidr-v6")
			delete(daemonMap, "ip6tables")
			delete(daemonMap, "experimental")
		}
	case "LogOption":
		if req.Value == "disable" {
			delete(daemonMap, "log-opts")
		}
	case "LiveRestore":
		if req.Value == "disable" {
			delete(daemonMap, "live-restore")
		} else {
			daemonMap["live-restore"] = true
		}
	case "IPtables":
		if req.Value == "enable" {
			delete(daemonMap, "iptables")
		} else {
			daemonMap["iptables"] = false
		}
	case "Driver":
		if opts, ok := daemonMap["exec-opts"]; ok {
			if optsValue, isArray := opts.([]interface{}); isArray {
				for i := 0; i < len(optsValue); i++ {
					if opt, isStr := optsValue[i].(string); isStr {
						if strings.HasPrefix(opt, "native.cgroupdriver=") {
							optsValue[i] = "native.cgroupdriver=" + req.Value
							break
						}
					}
				}
			}
		} else {
			if req.Value == "systemd" {
				daemonMap["exec-opts"] = []string{"native.cgroupdriver=systemd"}
			}
		}
	case "http-proxy", "https-proxy":
		delete(daemonMap, "proxies")
		if len(req.Value) > 0 {
			proxies := map[string]interface{}{
				req.Key: req.Value,
			}
			daemonMap["proxies"] = proxies
		}
	case "socks5-proxy", "close-proxy":
		delete(daemonMap, "proxies")
		if len(req.Value) > 0 {
			proxies := map[string]interface{}{
				"http-proxy":  req.Value,
				"https-proxy": req.Value,
			}
			daemonMap["proxies"] = proxies
		}
	}
	if len(daemonMap) == 0 {
		_ = os.Remove(constant.DaemonJsonPath)
		if err := restartDockerFn(); err != nil {
			return err
		}
		return nil
	}
	newJson, err := json.MarshalIndent(daemonMap, "", "\t")
	if err != nil {
		return err
	}
	if err := os.WriteFile(constant.DaemonJsonPath, newJson, 0640); err != nil {
		return err
	}
	if err := validateDockerConfigFn(); err != nil {
		// the write already landed; restore the previous state so a failed
		// validation cannot leave dockerd with a config it refuses to load
		return rollbackDaemonJson(constant.DaemonJsonPath, backup, err)
	}

	if err := restartDockerFn(); err != nil {
		return rollbackDaemonJson(constant.DaemonJsonPath, backup, err)
	}
	return nil
}

// createIfNotExistDaemonJsonFile ensures filePath (normally
// constant.DaemonJsonPath; injectable so tests can run against a temp file)
// and its parent directory exist. A newly created file — and an existing
// zero-byte one, e.g. left behind by an earlier failed write — is seeded with
// "{}": every writer unmarshals the file right after this call, and
// json.Unmarshal on an empty file fails with "unexpected end of JSON input".
func createIfNotExistDaemonJsonFile(filePath string) error {
	info, err := os.Stat(filePath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err == nil && info.Size() > 0 {
		return nil
	}
	if err := os.MkdirAll(path.Dir(filePath), os.ModePerm); err != nil {
		return err
	}
	return os.WriteFile(filePath, []byte("{}"), 0644)
}

func (u *DockerService) UpdateLogOption(req dto.LogOption) error {
	daemonJsonMu.Lock()
	defer daemonJsonMu.Unlock()
	// see UpdateConf: roll back on validation/restart failure instead of
	// leaving an unloadable config behind
	backup, err := backupDaemonJson(constant.DaemonJsonPath)
	if err != nil {
		return fmt.Errorf("backup %s failed: %w", constant.DaemonJsonPath, err)
	}
	err = createIfNotExistDaemonJsonFile(constant.DaemonJsonPath)
	if err != nil {
		return err
	}
	file, err := os.ReadFile(constant.DaemonJsonPath)
	if err != nil {
		return err
	}
	daemonMap := make(map[string]interface{})
	_ = json.Unmarshal(file, &daemonMap)

	changeLogOption(daemonMap, req.LogMaxFile, req.LogMaxSize)
	if len(daemonMap) == 0 {
		// Clearing the only log option empties daemon.json; removing the file
		// alone is not enough — dockerd keeps serving the stale in-memory
		// config until it is restarted. Removing the file and returning early
		// used to report success while the old config stayed active; restart
		// here matches UpdateConf's semantics. A missing file is fine (it was
		// created just above and is only absent if the removal raced, which the
		// daemonJsonMu critical section prevents), so os.IsNotExist is ignored.
		if err := os.Remove(constant.DaemonJsonPath); err != nil && !os.IsNotExist(err) {
			return err
		}
		return restartDockerFn()
	}
	newJson, err := json.MarshalIndent(daemonMap, "", "\t")
	if err != nil {
		return err
	}
	if err := os.WriteFile(constant.DaemonJsonPath, newJson, 0640); err != nil {
		return err
	}

	if err := validateDockerConfigFn(); err != nil {
		return rollbackDaemonJson(constant.DaemonJsonPath, backup, err)
	}

	if err := restartDockerFn(); err != nil {
		return rollbackDaemonJson(constant.DaemonJsonPath, backup, err)
	}
	return nil
}

func (u *DockerService) UpdateIpv6Option(req dto.Ipv6Option) error {
	daemonJsonMu.Lock()
	defer daemonJsonMu.Unlock()
	// see UpdateConf: roll back on validation/restart failure instead of
	// leaving an unloadable config behind
	backup, err := backupDaemonJson(constant.DaemonJsonPath)
	if err != nil {
		return fmt.Errorf("backup %s failed: %w", constant.DaemonJsonPath, err)
	}
	err = createIfNotExistDaemonJsonFile(constant.DaemonJsonPath)
	if err != nil {
		return err
	}

	file, err := os.ReadFile(constant.DaemonJsonPath)
	if err != nil {
		return err
	}
	daemonMap := make(map[string]interface{})
	_ = json.Unmarshal(file, &daemonMap)

	daemonMap["ipv6"] = true
	daemonMap["fixed-cidr-v6"] = req.FixedCidrV6
	if req.Ip6Tables {
		daemonMap["ip6tables"] = req.Ip6Tables
	}
	if req.Experimental {
		daemonMap["experimental"] = req.Experimental
	}
	if len(daemonMap) == 0 {
		// Clearing the only ipv6 option empties daemon.json; removing the file
		// alone is not enough — dockerd keeps serving the stale in-memory
		// config until it is restarted. Removing the file and returning early
		// used to report success while the old config stayed active; restart
		// here matches UpdateConf's semantics. A missing file is fine (it was
		// created just above and is only absent if the removal raced, which the
		// daemonJsonMu critical section prevents), so os.IsNotExist is ignored.
		if err := os.Remove(constant.DaemonJsonPath); err != nil && !os.IsNotExist(err) {
			return err
		}
		return restartDockerFn()
	}
	newJson, err := json.MarshalIndent(daemonMap, "", "\t")
	if err != nil {
		return err
	}
	if err := os.WriteFile(constant.DaemonJsonPath, newJson, 0640); err != nil {
		return err
	}

	if err := validateDockerConfigFn(); err != nil {
		return rollbackDaemonJson(constant.DaemonJsonPath, backup, err)
	}

	if err := restartDockerFn(); err != nil {
		return rollbackDaemonJson(constant.DaemonJsonPath, backup, err)
	}
	return nil
}

func (u *DockerService) UpdateConfByFile(req dto.DaemonJsonUpdateByFile) error {
	daemonJsonMu.Lock()
	defer daemonJsonMu.Unlock()
	if len(req.File) == 0 {
		_ = os.Remove(constant.DaemonJsonPath)
		if err := restartDockerFn(); err != nil {
			return err
		}
		return nil
	}
	// see UpdateConf: roll back on validation/restart failure instead of
	// leaving an unloadable config behind
	backup, err := backupDaemonJson(constant.DaemonJsonPath)
	if err != nil {
		return fmt.Errorf("backup %s failed: %w", constant.DaemonJsonPath, err)
	}
	err = createIfNotExistDaemonJsonFile(constant.DaemonJsonPath)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(constant.DaemonJsonPath, os.O_WRONLY|os.O_TRUNC, 0640)
	if err != nil {
		return err
	}
	defer file.Close()
	write := bufio.NewWriter(file)
	_, _ = write.WriteString(req.File)
	write.Flush()

	if err := validateDockerConfigFn(); err != nil {
		return rollbackDaemonJson(constant.DaemonJsonPath, backup, err)
	}

	if err := restartDockerFn(); err != nil {
		return rollbackDaemonJson(constant.DaemonJsonPath, backup, err)
	}
	return nil
}

func (u *DockerService) OperateDocker(req dto.DockerOperation) error {
	service := "docker"
	h, err := systemctl.DefaultHandler(service)
	if err != nil {
		return err
	}
	if req.Operation == "stop" {
		socketHandle, err := systemctl.DefaultHandler("docker.socket")
		if err == nil {
			status, err := socketHandle.IsActive()
			if err == nil && status.IsActive {
				if std, err := socketHandle.ExecuteAction("stop"); err != nil {
					global.LOG.Errorf("handle stop docker.socket failed, err: %v", std)
				}
			}
		}
	}

	if req.Operation == "restart" {
		if err := validateDockerConfig(); err != nil {
			return err
		}
	}

	if isDockerSnapInstalled() {
		command := fmt.Sprintf("snap %s docker", req.Operation)
		stdout, err := cmd.Exec(command)
		if err != nil {
			return fmt.Errorf("failed to restart docker: %v", stdout)
		}
		return nil
	}
	result, err := h.ExecuteAction(req.Operation)
	if err != nil {
		return errors.New(result.Output)
	}
	return nil
}
func changeLogOption(daemonMap map[string]interface{}, logMaxFile, logMaxSize string) {
	if opts, ok := daemonMap["log-opts"]; ok {
		if len(logMaxFile) != 0 || len(logMaxSize) != 0 {
			daemonMap["log-driver"] = "json-file"
		}
		optsMap, isMap := opts.(map[string]interface{})
		if isMap {
			if len(logMaxFile) != 0 {
				optsMap["max-file"] = logMaxFile
			} else {
				delete(optsMap, "max-file")
			}
			if len(logMaxSize) != 0 {
				optsMap["max-size"] = logMaxSize
			} else {
				delete(optsMap, "max-size")
			}
			if len(optsMap) == 0 {
				delete(daemonMap, "log-opts")
			}
		} else {
			optsMap := make(map[string]interface{})
			if len(logMaxFile) != 0 {
				optsMap["max-file"] = logMaxFile
			}
			if len(logMaxSize) != 0 {
				optsMap["max-size"] = logMaxSize
			}
			if len(optsMap) != 0 {
				daemonMap["log-opts"] = optsMap
			}
		}
	} else {
		if len(logMaxFile) != 0 || len(logMaxSize) != 0 {
			daemonMap["log-driver"] = "json-file"
		}
		optsMap := make(map[string]interface{})
		if len(logMaxFile) != 0 {
			optsMap["max-file"] = logMaxFile
		}
		if len(logMaxSize) != 0 {
			optsMap["max-size"] = logMaxSize
		}
		if len(optsMap) != 0 {
			daemonMap["log-opts"] = optsMap
		}
	}
}

func validateDockerConfig() error {
	if !cmd.Which("dockerd") {
		return nil
	}
	stdout, err := cmd.Exec("dockerd --validate")
	if strings.Contains(stdout, "unknown flag: --validate") {
		return nil
	}
	if err != nil || (stdout != "" && strings.TrimSpace(stdout) != "configuration OK") {
		return fmt.Errorf("docker configuration validation failed, err: %v", stdout)
	}
	return nil
}

func isDockerSnapInstalled() bool {
	stdout, err := cmd.Exec("which docker")
	if err != nil {
		return false
	}
	stdout = strings.TrimSpace(stdout)
	return strings.Contains(stdout, "snap")
}

func restartDocker() error {
	if isDockerSnapInstalled() {
		stdout, err := cmd.Exec("snap restart docker")
		if err != nil {
			return fmt.Errorf("failed to restart docker: %v", stdout)
		}
		return nil
	}
	return systemctl.Restart("docker")
}

// ---- panel proxy -> Docker daemon.json sync ----
//
// The panel proxy settings (ProxyType/Url/Port/User/Passwd) can optionally be
// mirrored into the Docker daemon configuration so image pulls etc. go through
// the same proxy. The full proxy URL is reused for both http-proxy and
// https-proxy; a socks5 proxy is written into http-proxy as a socks5:// URL
// because dockerd's config validation rejects a "socks5-proxy" key.

// dockerProxySyncAction decides what the daemon.json "proxies" key should look
// like for a proxy update. It returns nil (remove the key) or the proxies
// object to write, plus whether daemon.json needs to be touched at all:
//   - sync on  + proxy configured -> write the proxies object
//   - sync on  + proxy disabled   -> remove the key (the whole proxy is off)
//   - sync off + previously on    -> remove the key (uncheck after a sync)
//   - sync off + previously off   -> no-op (daemon.json left untouched)
func dockerProxySyncAction(prevSync, newSync, proxyURL string) (proxies map[string]interface{}, apply bool) {
	if newSync != "true" {
		if prevSync == "true" {
			return nil, true
		}
		return nil, false
	}
	if proxyURL == "" {
		return nil, true
	}
	return map[string]interface{}{
		"http-proxy":  proxyURL,
		"https-proxy": proxyURL,
		"no-proxy":    "127.0.0.0/8,::1",
	}, true
}

// daemonJsonBackup captures the previous state of daemon.json so a failed
// proxy sync can be rolled back.
type daemonJsonBackup struct {
	Existed bool
	Content []byte
}

// backupDaemonJson snapshots the daemon.json at filePath, recording whether the
// file exists so a rollback can recreate or drop it accordingly.
func backupDaemonJson(filePath string) (daemonJsonBackup, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return daemonJsonBackup{}, nil
		}
		return daemonJsonBackup{}, err
	}
	return daemonJsonBackup{Existed: true, Content: content}, nil
}

// restoreDaemonJson writes the backed-up content back, or removes the file
// when it did not exist before the change.
func restoreDaemonJson(filePath string, backup daemonJsonBackup) error {
	if !backup.Existed {
		if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	return os.WriteFile(filePath, backup.Content, 0640)
}

// writeDaemonJsonProxies merges the "proxies" key into the daemon.json at the
// given file path (proxies == nil removes the key), preserving every other
// existing key. The file is marshaled like UpdateConf does (tab indent, 0640).
// When the resulting config would be empty the file is removed, matching
// UpdateConf's convention.
func writeDaemonJsonProxies(filePath string, proxies map[string]interface{}) error {
	daemonMap := make(map[string]interface{})
	if content, err := os.ReadFile(filePath); err == nil {
		if err := json.Unmarshal(content, &daemonMap); err != nil {
			return fmt.Errorf("parse %s failed: %w", filePath, err)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if proxies == nil {
		delete(daemonMap, "proxies")
	} else {
		daemonMap["proxies"] = proxies
	}
	if len(daemonMap) == 0 {
		if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	if err := os.MkdirAll(path.Dir(filePath), 0755); err != nil {
		return err
	}
	newJSON, err := json.MarshalIndent(daemonMap, "", "\t")
	if err != nil {
		return err
	}
	return os.WriteFile(filePath, newJSON, 0640)
}

// waitDockerAlive pings the Docker daemon with retries (10 attempts, 2s apart)
// to wait out the restart window.
func waitDockerAlive() error {
	var lastErr error
	for i := 0; i < 10; i++ {
		time.Sleep(2 * time.Second)
		client, err := docker.NewDockerClient()
		if err != nil {
			lastErr = err
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err = client.Ping(ctx)
		cancel()
		client.Close()
		if err == nil {
			return nil
		}
		lastErr = err
	}
	return fmt.Errorf("docker daemon ping failed after 10 retries: %w", lastErr)
}

// rollbackDaemonJson restores the backed-up daemon.json and attempts one more
// docker restart. It returns a wrapped error describing both the original
// failure and the rollback outcome.
func rollbackDaemonJson(filePath string, backup daemonJsonBackup, cause error) error {
	global.LOG.Errorf("docker proxy sync failed (%v), rolling back daemon.json", cause)
	var rbErr error
	if err := restoreDaemonJson(filePath, backup); err != nil {
		rbErr = fmt.Errorf("restore daemon.json failed: %w", err)
	} else if err := restartDockerFn(); err != nil {
		rbErr = fmt.Errorf("restart docker after restore failed: %w", err)
	}
	if rbErr != nil {
		return fmt.Errorf("%w; rollback was attempted but failed: %v", cause, rbErr)
	}
	return fmt.Errorf("%w; daemon.json was rolled back to its previous state", cause)
}

// applyDaemonJsonProxies writes the daemon.json "proxies" key (nil removes it),
// then validates the config, restarts Docker and pings the daemon. On any
// failure (write/validate/restart/ping) the previous file state is restored
// (with one more restart attempt) and a wrapped error is returned.
func applyDaemonJsonProxies(filePath string, proxies map[string]interface{}) error {
	daemonJsonMu.Lock()
	defer daemonJsonMu.Unlock()
	backup, err := backupDaemonJson(filePath)
	if err != nil {
		return fmt.Errorf("backup %s failed: %w", filePath, err)
	}
	if err := writeDaemonJsonProxies(filePath, proxies); err != nil {
		return rollbackDaemonJson(filePath, backup, fmt.Errorf("write proxies to %s failed: %w", filePath, err))
	}
	if err := validateDockerConfig(); err != nil {
		return rollbackDaemonJson(filePath, backup, err)
	}
	if err := restartDocker(); err != nil {
		return rollbackDaemonJson(filePath, backup, err)
	}
	if err := waitDockerAlive(); err != nil {
		return rollbackDaemonJson(filePath, backup, err)
	}
	return nil
}

// syncDockerDaemonProxy mirrors a credential-free panel proxy into Docker's
// daemon.json per the ProxyDockerSync flag. Docker supports authenticated
// proxy URLs in daemon.json, but has no credential helper for daemon proxy
// settings; refusing those URLs here prevents the decrypted panel password
// from being persisted in daemon.json or copied by snapshots.
func syncDockerDaemonProxy(prevSync string, req dto.ProxyUpdate) error {
	if prevSync != "true" && req.ProxyDockerSync != "true" {
		return nil
	}
	pass := req.ProxyPasswd
	if pass == "" && req.ProxyPasswdKeep == "true" {
		if stored, err := settingRepo.Get(settingRepo.WithByKey("ProxyPasswd")); err == nil && stored.Value != "" {
			if plain, derr := encrypt.StringDecrypt(stored.Value); derr == nil {
				pass = plain
			} else {
				global.LOG.Errorf("decrypt stored proxy password for docker sync failed: %v", derr)
			}
		}
	}
	proxyURL := ""
	if u, err := buildProxyURL(req.ProxyType, req.ProxyUrl, req.ProxyPort, req.ProxyUser, pass); err != nil {
		return err
	} else if u != nil {
		proxyURL = u.String()
		if req.ProxyDockerSync == "true" && u.User != nil {
			if password, ok := u.User.Password(); ok && password != "" {
				return errors.New("Docker proxy synchronization with a password is disabled because daemon.json cannot store it securely")
			}
		}
	}
	proxies, apply := dockerProxySyncAction(prevSync, req.ProxyDockerSync, proxyURL)
	if !apply {
		return nil
	}
	return applyDaemonJsonProxies(constant.DaemonJsonPath, proxies)
}
