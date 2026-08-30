package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/1Panel-dev/1Panel/backend/app/dto"
	"github.com/1Panel-dev/1Panel/backend/buserr"
	"github.com/1Panel-dev/1Panel/backend/constant"
	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/1Panel-dev/1Panel/backend/utils/cmd"
	"github.com/1Panel-dev/1Panel/backend/utils/compose"
	"github.com/1Panel-dev/1Panel/backend/utils/docker"
	"github.com/1Panel-dev/1Panel/backend/utils/encrypt"
	"github.com/docker/docker/api/types/container"
	_ "github.com/go-sql-driver/mysql"
)

type RedisService struct{}

type IRedisService interface {
	UpdateConf(req dto.RedisConfUpdate) error
	UpdatePersistenceConf(req dto.RedisConfPersistenceUpdate) error
	ChangePassword(info dto.ChangeRedisPass) error

	LoadStatus(req dto.OperationWithName) (*dto.RedisStatus, error)
	LoadConf(req dto.OperationWithName) (*dto.RedisConf, error)
	LoadPersistenceConf(req dto.OperationWithName) (*dto.RedisPersistence, error)

	CheckHasCli() bool
	InstallCli() error
}

func NewIRedisService() IRedisService {
	return &RedisService{}
}

func (u *RedisService) UpdateConf(req dto.RedisConfUpdate) error {
	redisInfo, err := appInstallRepo.LoadBaseInfo("redis", req.Database)
	if err != nil {
		return err
	}

	if err := validateRedisConfValue(req.Timeout, redisConfValueInt); err != nil {
		return err
	}
	if err := validateRedisConfValue(req.Maxclients, redisConfValueInt); err != nil {
		return err
	}
	if err := validateRedisConfValue(req.Maxmemory, redisConfValueMemory); err != nil {
		return err
	}

	var confs []redisConfig
	confs = append(confs, redisConfig{key: "timeout", value: req.Timeout})
	confs = append(confs, redisConfig{key: "maxclients", value: req.Maxclients})
	confs = append(confs, redisConfig{key: "maxmemory", value: req.Maxmemory})
	if err := confSet(redisInfo.Name, "", confs); err != nil {
		return err
	}
	if _, err := compose.Restart(fmt.Sprintf("%s/redis/%s/docker-compose.yml", constant.AppInstallDir, redisInfo.Name)); err != nil {
		return err
	}

	return nil
}

func (u *RedisService) CheckHasCli() bool {
	client, err := docker.NewDockerClient()
	if err != nil {
		return false
	}
	defer client.Close()
	containerLists, err := client.ContainerList(context.Background(), container.ListOptions{})
	if err != nil {
		return false
	}
	for _, item := range containerLists {
		if strings.ReplaceAll(item.Names[0], "/", "") == "1Panel-redis-cli-tools" {
			return true
		}
	}
	return false
}

func (u *RedisService) InstallCli() error {
	item := dto.ContainerOperate{
		Name:    "1Panel-redis-cli-tools",
		Image:   "redis:7.2.4",
		Network: "1panel-network",
	}
	return NewIContainerService().ContainerCreate(item)
}

func (u *RedisService) ChangePassword(req dto.ChangeRedisPass) error {
	if err := updateInstallInfoInDB("redis", req.Database, "password", req.Value); err != nil {
		return err
	}
	remote, err := databaseRepo.Get(commonRepo.WithByName(req.Database))
	if err != nil {
		return err
	}
	if remote.From == "local" {
		pass, err := encrypt.StringEncrypt(req.Value)
		if err != nil {
			return fmt.Errorf("decrypt database password failed, err: %v", err)
		}
		_ = databaseRepo.Update(remote.ID, map[string]interface{}{"password": pass})
	}

	return nil
}

func (u *RedisService) UpdatePersistenceConf(req dto.RedisConfPersistenceUpdate) error {
	redisInfo, err := appInstallRepo.LoadBaseInfo("redis", req.Database)
	if err != nil {
		return err
	}

	var confs []redisConfig
	if req.Type == "rbd" {
		if err := validateRedisConfValue(req.Save, redisConfValueSave); err != nil {
			return err
		}
		confs = append(confs, redisConfig{key: "save", value: req.Save})
	} else {
		if err := validateRedisConfValue(req.Appendonly, redisConfValueEnum, "yes", "no"); err != nil {
			return err
		}
		if err := validateRedisConfValue(req.Appendfsync, redisConfValueEnum, "always", "everysec", "no"); err != nil {
			return err
		}
		confs = append(confs, redisConfig{key: "appendonly", value: req.Appendonly})
		confs = append(confs, redisConfig{key: "appendfsync", value: req.Appendfsync})
	}
	if err := confSet(redisInfo.Name, req.Type, confs); err != nil {
		return err
	}
	if _, err := compose.Restart(fmt.Sprintf("%s/redis/%s/docker-compose.yml", constant.AppInstallDir, redisInfo.Name)); err != nil {
		return err
	}

	return nil
}

func (u *RedisService) LoadStatus(req dto.OperationWithName) (*dto.RedisStatus, error) {
	redisInfo, err := appInstallRepo.LoadBaseInfo("redis", req.Name)
	if err != nil {
		return nil, err
	}
	commands := append(redisExec(redisInfo.ContainerName, redisInfo.Password), "info")
	fullArgs, cleanup, err := redisExecEnvFile(commands, redisInfo.Password)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	cmdItem := exec.Command("docker", fullArgs...)
	stdout, err := cmdItem.CombinedOutput()
	if err != nil {
		return nil, errors.New(string(stdout))
	}
	rows := strings.Split(string(stdout), "\r\n")
	rowMap := make(map[string]string)
	for _, v := range rows {
		itemRow := strings.Split(v, ":")
		if len(itemRow) == 2 {
			rowMap[itemRow[0]] = itemRow[1]
		}
	}
	var info dto.RedisStatus
	arr, err := json.Marshal(rowMap)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(arr, &info)
	return &info, nil
}

func (u *RedisService) LoadConf(req dto.OperationWithName) (*dto.RedisConf, error) {
	redisInfo, err := appInstallRepo.LoadBaseInfo("redis", req.Name)
	if err != nil {
		return nil, err
	}

	var item dto.RedisConf
	item.ContainerName = redisInfo.ContainerName
	item.Name = redisInfo.Name
	item.Port = redisInfo.Port
	item.Requirepass = redisInfo.Password
	item.Timeout, _ = configGetStr(redisInfo.ContainerName, redisInfo.Password, "timeout")
	item.Maxclients, _ = configGetStr(redisInfo.ContainerName, redisInfo.Password, "maxclients")
	item.Maxmemory, _ = configGetStr(redisInfo.ContainerName, redisInfo.Password, "maxmemory")
	return &item, nil
}

func (u *RedisService) LoadPersistenceConf(req dto.OperationWithName) (*dto.RedisPersistence, error) {
	redisInfo, err := appInstallRepo.LoadBaseInfo("redis", req.Name)
	if err != nil {
		return nil, err
	}
	var item dto.RedisPersistence
	if item.Appendonly, err = configGetStr(redisInfo.ContainerName, redisInfo.Password, "appendonly"); err != nil {
		return nil, err
	}
	if item.Appendfsync, err = configGetStr(redisInfo.ContainerName, redisInfo.Password, "appendfsync"); err != nil {
		return nil, err
	}
	if item.Save, err = configGetStr(redisInfo.ContainerName, redisInfo.Password, "save"); err != nil {
		return nil, err
	}
	return &item, nil
}

func configGetStr(containerName, password, param string) (string, error) {
	commands := append(redisExec(containerName, password), []string{"config", "get", param}...)
	fullArgs, cleanup, err := redisExecEnvFile(commands, password)
	if err != nil {
		return "", err
	}
	defer cleanup()
	cmdItem := exec.Command("docker", fullArgs...)
	stdout, err := cmdItem.CombinedOutput()
	if err != nil {
		return "", errors.New(string(stdout))
	}
	rows := strings.Split(string(stdout), "\r\n")
	for _, v := range rows {
		itemRow := strings.Split(v, "\n")
		if len(itemRow) == 3 {
			return itemRow[1], nil
		}
	}
	return "", nil
}

type redisConfig struct {
	key   string
	value string
}

// redis.conf value validation.
//
// Values written by UpdateConf / UpdatePersistenceConf end up verbatim on a
// redis.conf line ("maxmemory 100mb"), so a value containing a newline could
// inject arbitrary extra configuration directives (e.g. "100mb\nrequirepass
// evil"). Every value is therefore validated against a strict per-key rule
// before it is written; values that fail the rule are rejected without
// touching the file.
//
// The rules below intentionally mirror what the 1Panel frontend itself
// produces (see frontend/src/views/database/redis/):
//   - timeout / maxclients: plain digits ("900", "65504")
//   - maxmemory: plain digits followed by a size suffix ("100mb", "1gb")
//   - save: "second changes" pairs, comma separated ("900 1,300 10")
//   - appendonly / appendfsync: enum values ("yes"/"no"/"always"/"everysec")
//
// Empty values are legal (the confSet writer treats them like "0": the
// directive line is commented out).
type redisConfValidator func(value string, allowed ...string) bool

var (
	redisConfIntRE    = regexp.MustCompile(`^[0-9]+$`)
	redisConfMemoryRE = regexp.MustCompile(`^[0-9]+(kb|mb|gb)?$`)
	redisConfSaveRE   = regexp.MustCompile(`^[0-9]+\s+[0-9]+(\s*,\s*[0-9]+\s+[0-9]+)*$`)
)

func redisConfValueInt(value string, _ ...string) bool {
	if value == "" {
		return true
	}
	return redisConfIntRE.MatchString(value)
}

func redisConfValueMemory(value string, _ ...string) bool {
	if value == "" {
		return true
	}
	return redisConfMemoryRE.MatchString(value)
}

func redisConfValueSave(value string, _ ...string) bool {
	if value == "" {
		return true
	}
	return redisConfSaveRE.MatchString(value)
}

func redisConfValueEnum(value string, allowed ...string) bool {
	if value == "" {
		return true
	}
	for _, item := range allowed {
		if value == item {
			return true
		}
	}
	return false
}

// redisConfValidators maps every directive confSet may rewrite to its value
// validator. Keys not listed here are rejected by confSet.
var redisConfValidators = map[string]redisConfValidator{
	"timeout":     redisConfValueInt,
	"maxclients":  redisConfValueInt,
	"maxmemory":   redisConfValueMemory,
	"save":        redisConfValueSave,
	"appendonly":  redisConfValueEnum,
	"appendfsync": redisConfValueEnum,
}

// redisConfAllowedValues holds the whitelist for enum-validated directives.
var redisConfAllowedValues = map[string][]string{
	"appendonly":  {"yes", "no"},
	"appendfsync": {"always", "everysec", "no"},
}

// validateRedisConfigList rejects any value that would not be safe to write
// verbatim onto a redis.conf line. It is the last line of defense behind the
// per-field checks in UpdateConf / UpdatePersistenceConf.
func validateRedisConfigList(confs []redisConfig) error {
	for _, item := range confs {
		validate, ok := redisConfValidators[item.key]
		if !ok {
			return buserr.New("ErrInvalidChar")
		}
		if err := validateRedisConfValue(item.value, validate, redisConfAllowedValues[item.key]...); err != nil {
			return err
		}
	}
	return nil
}

func validateRedisConfValue(value string, validate redisConfValidator, allowed ...string) error {
	if !validate(value, allowed...) {
		// ErrInvalidChar is a plain i18n key (see backend/app/service/file.go).
		return buserr.New("ErrInvalidChar")
	}
	return nil
}

func confSet(redisName string, updateType string, changeConf []redisConfig) error {
	if err := validateRedisConfigList(changeConf); err != nil {
		return err
	}
	path := fmt.Sprintf("%s/redis/%s/conf/redis.conf", constant.AppInstallDir, redisName)
	lineBytes, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	files := strings.Split(string(lineBytes), "\n")

	startIndex, endIndex, emptyLine := 0, 0, 0
	var newFiles []string
	for i := 0; i < len(files); i++ {
		if files[i] == "# Redis configuration rewrite by 1Panel" {
			startIndex = i
			newFiles = append(newFiles, files[i])
			continue
		}
		if files[i] == "# End Redis configuration rewrite by 1Panel" {
			endIndex = i
			break
		}
		if startIndex == 0 && strings.HasPrefix(files[i], "save ") {
			newFiles = append(newFiles, "#   "+files[i])
			continue
		}
		if startIndex != 0 && endIndex == 0 && (len(files[i]) == 0 || (updateType == "rbd" && strings.HasPrefix(files[i], "save "))) {
			emptyLine++
			continue
		}
		newFiles = append(newFiles, files[i])
	}
	endIndex = endIndex - emptyLine
	for _, item := range changeConf {
		if item.key == "save" {
			saveVal := strings.Split(item.value, ",")
			for i := 0; i < len(saveVal); i++ {
				newFiles = append(newFiles, "save "+saveVal[i])
			}
			continue
		}

		isExist := false
		for i := startIndex; i < endIndex; i++ {
			if strings.HasPrefix(newFiles[i], item.key) || strings.HasPrefix(newFiles[i], "# "+item.key) {
				if item.value == "0" || len(item.value) == 0 {
					newFiles[i] = fmt.Sprintf("# %s %s", item.key, item.value)
				} else {
					newFiles[i] = fmt.Sprintf("%s %s", item.key, item.value)
				}
				isExist = true
				break
			}
		}
		if !isExist {
			if item.value == "0" || len(item.value) == 0 {
				newFiles = append(newFiles, fmt.Sprintf("# %s %s", item.key, item.value))
			} else {
				newFiles = append(newFiles, fmt.Sprintf("%s %s", item.key, item.value))
			}
		}
	}
	newFiles = append(newFiles, "# End Redis configuration rewrite by 1Panel")

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0666)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.WriteString(strings.Join(newFiles, "\n"))
	if err != nil {
		return err
	}
	return nil
}

func redisExec(containerName, password string) []string {
	// The password is NOT passed as `-a <password>` (world-readable in the
	// process argv under /proc): callers inject it through
	// redisExecEnvFile with `docker exec --env-file` instead, and redis-cli
	// picks it up from the REDISCLI_AUTH environment variable (redis >= 6).
	cmds := []string{"exec", containerName, "redis-cli", "--no-auth-warning"}
	if len(password) == 0 {
		cmds = []string{"exec", containerName, "redis-cli"}
	}
	return cmds
}

// redisExecEnvFile writes the redis password to a fresh 0600 file and wraps
// the given docker exec args with `--env-file`, so the password never shows
// up in the world-readable process argv. The file is removed as soon as the
// command finishes.
func redisExecEnvFile(commands []string, password string) ([]string, func(), error) {
	envFile, err := cmd.WriteDockerEnvFile(global.CONF.System.TmpDir, map[string]string{"REDISCLI_AUTH": password})
	if err != nil {
		return nil, nil, err
	}
	if len(commands) == 0 {
		_ = os.Remove(envFile)
		return nil, nil, errors.New("empty docker exec command")
	}
	cleanup := func() { _ = os.Remove(envFile) }
	fullArgs := make([]string, 0, len(commands)+2)
	fullArgs = append(fullArgs, "exec", "--env-file", envFile)
	fullArgs = append(fullArgs, commands[1:]...)
	return fullArgs, cleanup, nil
}
