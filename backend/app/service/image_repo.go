package service

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/1Panel-dev/1Panel/backend/app/dto"
	"github.com/1Panel-dev/1Panel/backend/buserr"
	"github.com/1Panel-dev/1Panel/backend/constant"
	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/1Panel-dev/1Panel/backend/utils/cmd"
	"github.com/1Panel-dev/1Panel/backend/utils/common"
	"github.com/jinzhu/copier"
	"github.com/pkg/errors"
)

type ImageRepoService struct{}

type IImageRepoService interface {
	Page(search dto.SearchWithPage) (int64, interface{}, error)
	List() ([]dto.ImageRepoOption, error)
	Login(req dto.OperateByID) error
	Create(req dto.ImageRepoCreate) error
	Update(req dto.ImageRepoUpdate) error
	Delete(req dto.OperateByID) error
}

func NewIImageRepoService() IImageRepoService {
	return &ImageRepoService{}
}

func (u *ImageRepoService) Page(req dto.SearchWithPage) (int64, interface{}, error) {
	total, ops, err := imageRepoRepo.Page(req.Page, req.PageSize, commonRepo.WithLikeName(req.Info), commonRepo.WithOrderBy("created_at desc"))
	var dtoOps []dto.ImageRepoInfo
	for _, op := range ops {
		var item dto.ImageRepoInfo
		if err := copier.Copy(&item, &op); err != nil {
			return 0, nil, errors.WithMessage(constant.ErrStructTransform, err.Error())
		}
		dtoOps = append(dtoOps, item)
	}
	return total, dtoOps, err
}

func (u *ImageRepoService) Login(req dto.OperateByID) error {
	repo, err := imageRepoRepo.Get(commonRepo.WithByID(req.ID))
	if err != nil {
		return err
	}
	if repo.Auth {
		if err := u.CheckConn(repo.DownloadUrl, repo.Username, repo.Password); err != nil {
			_ = imageRepoRepo.Update(repo.ID, map[string]interface{}{"status": constant.StatusFailed, "message": err.Error()})
			return err
		}
	}
	_ = imageRepoRepo.Update(repo.ID, map[string]interface{}{"status": constant.StatusSuccess})
	return nil
}

func (u *ImageRepoService) List() ([]dto.ImageRepoOption, error) {
	ops, err := imageRepoRepo.List(commonRepo.WithOrderBy("created_at desc"))
	var dtoOps []dto.ImageRepoOption
	for _, op := range ops {
		if op.Status == constant.StatusSuccess {
			var item dto.ImageRepoOption
			if err := copier.Copy(&item, &op); err != nil {
				return nil, errors.WithMessage(constant.ErrStructTransform, err.Error())
			}
			dtoOps = append(dtoOps, item)
		}
	}
	return dtoOps, err
}

func (u *ImageRepoService) Create(req dto.ImageRepoCreate) error {
	if cmd.CheckIllegal(req.Username, req.Password, req.DownloadUrl) {
		return buserr.New(constant.ErrCmdIllegal)
	}
	imageRepo, _ := imageRepoRepo.Get(commonRepo.WithByName(req.Name))
	if imageRepo.ID != 0 {
		return constant.ErrRecordExist
	}

	if req.Protocol == "http" {
		if err := u.applyRegistriesChange(constant.DaemonJsonPath, req.DownloadUrl, "", "create"); err != nil {
			return fmt.Errorf("create registry %s failed, err: %v", req.DownloadUrl, err)
		}
	}
	if req.Auth {
		if err := u.CheckConn(req.DownloadUrl, req.Username, req.Password); err != nil {
			return err
		}
	}

	if err := copier.Copy(&imageRepo, &req); err != nil {
		return errors.WithMessage(constant.ErrStructTransform, err.Error())
	}

	imageRepo.Status = constant.StatusSuccess
	return imageRepoRepo.Create(&imageRepo)
}

func (u *ImageRepoService) Delete(req dto.OperateByID) error {
	if req.ID == 1 {
		return errors.New("The default value cannot be edit !")
	}
	itemRepo, _ := imageRepoRepo.Get(commonRepo.WithByID(req.ID))
	if itemRepo.ID == 0 {
		return buserr.New("ErrRecordNotFound")
	}
	if itemRepo.Auth {
		_, _ = cmd.Execf("docker logout -i %s", itemRepo.DownloadUrl)
	}
	if itemRepo.Protocol == "https" {
		return imageRepoRepo.Delete(commonRepo.WithByID(req.ID))
	}
	if err := u.removeInsecureRegistry(constant.DaemonJsonPath, itemRepo.DownloadUrl, req.ID); err != nil {
		return fmt.Errorf("delete registry %s failed, err: %v", itemRepo.DownloadUrl, err)
	}
	return nil
}

func (u *ImageRepoService) Update(req dto.ImageRepoUpdate) error {
	if req.ID == 1 {
		return errors.New("The default value cannot be deleted !")
	}
	if cmd.CheckIllegal(req.Username, req.Password, req.DownloadUrl) {
		return buserr.New(constant.ErrCmdIllegal)
	}
	repo, err := imageRepoRepo.Get(commonRepo.WithByID(req.ID))
	if err != nil {
		return err
	}
	// The branches are mutually exclusive; applyRegistriesChange bundles the
	// daemon.json write, validation and restart into one locked critical
	// section, so no separate restart step is needed afterwards.
	if repo.Protocol == "http" && req.Protocol == "https" {
		if err := u.applyRegistriesChange(constant.DaemonJsonPath, "", repo.DownloadUrl, "delete"); err != nil {
			return fmt.Errorf("delete registry %s failed, err: %v", repo.DownloadUrl, err)
		}
	}
	if repo.Protocol == "http" && req.Protocol == "http" && repo.DownloadUrl != req.DownloadUrl {
		if err := u.applyRegistriesChange(constant.DaemonJsonPath, req.DownloadUrl, repo.DownloadUrl, "update"); err != nil {
			return fmt.Errorf("update registry %s => %s failed, err: %v", repo.DownloadUrl, req.DownloadUrl, err)
		}
	}
	if repo.Protocol == "https" && req.Protocol == "http" {
		if err := u.applyRegistriesChange(constant.DaemonJsonPath, req.DownloadUrl, "", "create"); err != nil {
			return fmt.Errorf("create registry %s failed, err: %v", req.DownloadUrl, err)
		}
	}
	if repo.Auth {
		_, _ = cmd.Execf("docker logout -i %s", repo.DownloadUrl)
	}
	if req.Auth {
		if err := u.CheckConn(req.DownloadUrl, req.Username, req.Password); err != nil {
			return err
		}
	}

	upMap := make(map[string]interface{})
	upMap["download_url"] = req.DownloadUrl
	upMap["protocol"] = req.Protocol
	upMap["username"] = req.Username
	upMap["password"] = req.Password
	upMap["auth"] = req.Auth
	upMap["status"] = constant.StatusSuccess
	upMap["message"] = ""
	return imageRepoRepo.Update(req.ID, upMap)
}

func (u *ImageRepoService) CheckConn(host, user, password string) error {
	stdout, err := cmd.ExecWithCheck("docker", "login", "-u", user, "-p", password, host)
	if err != nil {
		return fmt.Errorf("stdout: %s, stderr: %v", stdout, err)
	}
	if strings.Contains(string(stdout), "Login Succeeded") {
		return nil
	}
	return errors.New(string(stdout))
}

// Indirections over the docker control-plane steps, for tests only: unit
// tests cannot restart the host docker daemon, so they stub these to observe
// call order and lock coverage. Production code must always see the real
// validateDockerConfig/restartDocker through these defaults.
var (
	validateDockerConfigFn = validateDockerConfig
	restartDockerFn        = restartDocker
	waitForDockerActiveFn  = waitForDockerActive
)

// applyRegistriesChange performs the full daemon.json lifecycle of an
// insecure-registries change under ONE daemonJsonMu critical section:
// read-modify-write, dockerd config validation, daemon restart and the
// wait-for-active poll. The write must be mutually exclusive with the other
// daemon.json writers (docker.go UpdateConf/UpdateLogOption/UpdateIpv6Option/
// UpdateConfByFile/applyDaemonJsonProxies all hold daemonJsonMu across
// write+validate+restart): dockerd --validate and the restart read the whole
// file, so a writer interleaved between our write and our restart could make
// the validation run against (or the restart apply) a config nobody meant to
// ship. The restart is deliberately synchronous under the lock, matching
// applyDaemonJsonProxies which holds the lock for restart + waitDockerAlive;
// an async restart would let the next writer rewrite/validate the file while
// the daemon is still reloading the previous content.
func (u *ImageRepoService) applyRegistriesChange(filePath, newHost, delHost, handle string) error {
	daemonJsonMu.Lock()
	defer daemonJsonMu.Unlock()
	if err := u.handleRegistriesLocked(filePath, newHost, delHost, handle); err != nil {
		return err
	}
	if err := validateDockerConfigFn(); err != nil {
		return err
	}
	if err := restartDockerFn(); err != nil {
		return err
	}
	return waitForDockerActiveFn()
}

// removeInsecureRegistry is the delete-path variant of applyRegistriesChange:
// same locked write+validate, then the repo row is removed and the restart
// runs inside the same critical section. A failed restart must not fail the
// deletion — the daemon.json entry and the row are already gone — but it must
// not be silent either: the daemon keeps serving with the deleted registry
// until a manual restart.
func (u *ImageRepoService) removeInsecureRegistry(filePath, host string, id uint) error {
	daemonJsonMu.Lock()
	defer daemonJsonMu.Unlock()
	if err := u.handleRegistriesLocked(filePath, "", host, "delete"); err != nil {
		return err
	}
	if err := validateDockerConfigFn(); err != nil {
		return err
	}
	if err := imageRepoRepo.Delete(commonRepo.WithByID(id)); err != nil {
		return err
	}
	if err := restartDockerFn(); err != nil {
		global.LOG.Errorf("restart docker after deleting insecure registry %s failed, err: %v", host, err)
	}
	return nil
}

// handleRegistriesLocked performs the insecure-registries read-modify-write on
// the daemon.json at filePath. The caller must hold daemonJsonMu (see
// applyRegistriesChange for why the lock must also cover validate/restart).
func (u *ImageRepoService) handleRegistriesLocked(filePath, newHost, delHost, handle string) error {
	err := createIfNotExistDaemonJsonFile(filePath)
	if err != nil {
		return err
	}
	daemonMap := make(map[string]interface{})
	file, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(file, &daemonMap); err != nil {
		return err
	}

	iRegistries := daemonMap["insecure-registries"]
	registries, _ := iRegistries.([]interface{})
	switch handle {
	case "create":
		registries = common.RemoveRepeatElement(append(registries, newHost))
	case "update":
		for i, regi := range registries {
			if regi == delHost {
				registries = append(registries[:i], registries[i+1:]...)
			}
		}
		registries = common.RemoveRepeatElement(append(registries, newHost))
	case "delete":
		for i, regi := range registries {
			if regi == delHost {
				registries = append(registries[:i], registries[i+1:]...)
			}
		}
	}
	if len(registries) == 0 {
		delete(daemonMap, "insecure-registries")
	} else {
		daemonMap["insecure-registries"] = registries
	}
	newJson, err := json.MarshalIndent(daemonMap, "", "\t")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filePath, newJson, 0640); err != nil {
		return err
	}
	return nil
}

// waitForDockerActive polls `systemctl is-active docker` until the daemon
// answers again after a restart (30s timeout).
func waitForDockerActive() error {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()
	for {
		select {
		case <-ctx.Done():
			return errors.New("the docker service cannot be restarted")
		case <-ticker.C:
			stdout, err := cmd.Exec("systemctl is-active docker")
			if string(stdout) == "active\n" && err == nil {
				global.LOG.Info("docker restart with new conf successful!")
				return nil
			}
		}
	}
}
