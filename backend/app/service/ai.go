package service

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"regexp"
	"strings"

	"github.com/1Panel-dev/1Panel/backend/app/dto"
	"github.com/1Panel-dev/1Panel/backend/app/dto/request"
	"github.com/1Panel-dev/1Panel/backend/app/model"
	"github.com/1Panel-dev/1Panel/backend/app/repo"
	"github.com/1Panel-dev/1Panel/backend/buserr"
	"github.com/1Panel-dev/1Panel/backend/constant"
	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/1Panel-dev/1Panel/backend/utils/cmd"
	"github.com/jinzhu/copier"
	"github.com/pkg/errors"
)

type AIToolService struct{}

type IAIToolService interface {
	Search(search dto.SearchWithPage) (int64, []dto.OllamaModelInfo, error)
	Create(name string) error
	Close(name string) error
	Recreate(name string) error
	Delete(req dto.ForceDelete) error
	Sync() ([]dto.OllamaModelDropList, error)
	LoadDetail(name string) (string, error)
	BindDomain(req dto.OllamaBindDomain) error
	GetBindDomain(req dto.OllamaBindDomainReq) (*dto.OllamaBindDomainRes, error)
	UpdateBindDomain(req dto.OllamaBindDomain) error
}

func NewIAIToolService() IAIToolService {
	return &AIToolService{}
}

// ollamaModelNameRegexp matches valid ollama model names: alphanumerics plus
// ".", "_", "-", ":" and "/" (e.g. "llama3:8b", "qwen/qwen2.5:7b"), capped at
// 128 characters. "/" is intentionally allowed because namespaced model names
// ("user/model") are legal ollama identifiers. The name is both interpolated
// into `docker exec ... ollama pull <name>` (via bash -c) and joined into the
// DataDir/log/AITools log path, so ".." segments and shell metacharacters must
// not appear: CheckIllegal gates the shell charset first, the regex excludes
// spaces/backslashes, and validOllamaModelName rejects ".." segments so the
// joined log path can never escape the AITools directory.
var ollamaModelNameRegexp = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:/-]{0,127}$`)

// validOllamaModelName reports whether name is a safe ollama model name. In
// addition to the charset whitelist it rejects ".." path segments, so the
// value can never traverse out of DataDir/log/AITools when joined into the
// log file path.
func validOllamaModelName(name string) bool {
	if !ollamaModelNameRegexp.MatchString(name) {
		return false
	}
	if name == ".." || strings.HasPrefix(name, "../") || strings.Contains(name, "/../") || strings.HasSuffix(name, "/..") {
		return false
	}
	return true
}

// ollamaModelLogPath joins the model log path under DataDir/log/AITools and
// re-checks the result stayed inside that directory. Used as defense in depth
// behind validOllamaModelName: with path.Join cleaning, a whitelisted name can
// no longer escape, but the containment check makes the invariant explicit. An
// empty result means the path escaped and must not be used.
func ollamaModelLogPath(dataDir, name string) string {
	baseDir := path.Join(dataDir, "log", "AITools")
	logPath := path.Join(baseDir, name)
	if !strings.HasPrefix(logPath+string(os.PathSeparator), baseDir+string(os.PathSeparator)) {
		return ""
	}
	return logPath
}

func (u *AIToolService) Search(req dto.SearchWithPage) (int64, []dto.OllamaModelInfo, error) {
	var options []repo.DBOption
	if len(req.Info) != 0 {
		options = append(options, commonRepo.WithLikeName(req.Info))
	}
	total, list, err := aiRepo.Page(req.Page, req.PageSize, options...)
	if err != nil {
		return 0, nil, err
	}
	var dtoLists []dto.OllamaModelInfo
	for _, itemModel := range list {
		var item dto.OllamaModelInfo
		if err := copier.Copy(&item, &itemModel); err != nil {
			return 0, nil, errors.WithMessage(constant.ErrStructTransform, err.Error())
		}
		logPath := path.Join(global.CONF.System.DataDir, "log", "AITools", itemModel.Name)
		if _, err := os.Stat(logPath); err == nil {
			item.LogFileExist = true
		}
		dtoLists = append(dtoLists, item)
	}
	return int64(total), dtoLists, err
}

func (u *AIToolService) LoadDetail(name string) (string, error) {
	if cmd.CheckIllegal(name) {
		return "", buserr.New(constant.ErrCmdIllegal)
	}
	containerName, err := LoadContainerName()
	if err != nil {
		return "", err
	}
	stdout, err := cmd.Execf("docker exec %s ollama show %s", containerName, name)
	if err != nil {
		return "", err
	}
	return stdout, err
}

func (u *AIToolService) Create(name string) error {
	if cmd.CheckIllegal(name) || !validOllamaModelName(name) {
		return buserr.New(constant.ErrCmdIllegal)
	}
	modelInfo, _ := aiRepo.Get(commonRepo.WithByName(name))
	if modelInfo.ID != 0 {
		return constant.ErrRecordExist
	}
	containerName, err := LoadContainerName()
	if err != nil {
		return err
	}
	logItem := ollamaModelLogPath(global.CONF.System.DataDir, name)
	if logItem == "" {
		return buserr.New(constant.ErrCmdIllegal)
	}
	if _, err := os.Stat(path.Dir(logItem)); err != nil && os.IsNotExist(err) {
		if err = os.MkdirAll(path.Dir(logItem), os.ModePerm); err != nil {
			return err
		}
	}
	info := model.OllamaModel{
		Name:   name,
		From:   "local",
		Status: constant.StatusWaiting,
	}
	if err := aiRepo.Create(&info); err != nil {
		return err
	}
	file, err := os.OpenFile(logItem, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		return err
	}
	go pullOllamaModel(file, containerName, info)
	return nil
}

func (u *AIToolService) Close(name string) error {
	if cmd.CheckIllegal(name) {
		return buserr.New(constant.ErrCmdIllegal)
	}
	containerName, err := LoadContainerName()
	if err != nil {
		return err
	}
	stdout, err := cmd.Execf("docker exec %s ollama stop %s", containerName, name)
	if err != nil {
		return fmt.Errorf("handle ollama stop %s failed, stdout: %s, err: %v", name, stdout, err)
	}
	return nil
}

func (u *AIToolService) Recreate(name string) error {
	if cmd.CheckIllegal(name) || !validOllamaModelName(name) {
		return buserr.New(constant.ErrCmdIllegal)
	}
	modelInfo, _ := aiRepo.Get(commonRepo.WithByName(name))
	if modelInfo.ID == 0 {
		return constant.ErrRecordNotFound
	}
	containerName, err := LoadContainerName()
	if err != nil {
		return err
	}
	if err := aiRepo.Update(modelInfo.ID, map[string]interface{}{"status": constant.StatusWaiting, "from": "local"}); err != nil {
		return err
	}
	logItem := ollamaModelLogPath(global.CONF.System.DataDir, name)
	if logItem == "" {
		return buserr.New(constant.ErrCmdIllegal)
	}
	if _, err := os.Stat(path.Dir(logItem)); err != nil && os.IsNotExist(err) {
		if err = os.MkdirAll(path.Dir(logItem), os.ModePerm); err != nil {
			return err
		}
	}
	file, err := os.OpenFile(logItem, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		return err
	}
	go pullOllamaModel(file, containerName, modelInfo)
	return nil
}

func (u *AIToolService) Delete(req dto.ForceDelete) error {
	ollamaList, _ := aiRepo.List(commonRepo.WithIdsIn(req.IDs))
	if len(ollamaList) == 0 {
		return constant.ErrRecordNotFound
	}
	containerName, err := LoadContainerName()
	if err != nil && !req.ForceDelete {
		return err
	}
	for _, item := range ollamaList {
		if item.Status != constant.StatusDeleted {
			// validOllamaModelName is the same gate Create/Sync apply before
			// a name reaches docker, covering legacy rows stored before that
			// gate existed. The delete runs via argv (no shell), so a
			// rejected value is skipped rather than failing the batch.
			if !validOllamaModelName(item.Name) {
				global.LOG.Errorf("skip ollama rm of model %q: invalid model name", item.Name)
			} else {
				stdout, err := cmd.ExecWithCheck("docker", "exec", containerName, "ollama", "rm", item.Name)
				if err != nil && !req.ForceDelete {
					return fmt.Errorf("handle ollama rm %s failed, stdout: %s, err: %v", item.Name, stdout, err)
				}
			}
		}
		_ = aiRepo.Delete(commonRepo.WithByID(item.ID))
		logItem := path.Join(global.CONF.System.DataDir, "log", "AITools", item.Name)
		_ = os.Remove(logItem)
	}
	return nil
}

func (u *AIToolService) Sync() ([]dto.OllamaModelDropList, error) {
	containerName, err := LoadContainerName()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.Execf("docker exec %s ollama list", containerName)
	if err != nil {
		return nil, err
	}
	list := parseOllamaModelList(stdout)
	listInDB, _ := aiRepo.List()
	var dropList []dto.OllamaModelDropList
	for _, itemModel := range listInDB {
		isExit := false
		for i := 0; i < len(list); i++ {
			if list[i].Name == itemModel.Name {
				_ = aiRepo.Update(itemModel.ID, map[string]interface{}{"status": constant.StatusSuccess, "message": "", "size": list[i].Size})
				list = append(list[:i], list[(i+1):]...)
				isExit = true
				break
			}
		}
		if !isExit && itemModel.Status != constant.StatusWaiting {
			_ = aiRepo.Update(itemModel.ID, map[string]interface{}{"status": constant.StatusDeleted, "message": "not exist", "size": ""})
			dropList = append(dropList, dto.OllamaModelDropList{ID: itemModel.ID, Name: itemModel.Name})
			continue
		}
	}
	for _, item := range list {
		item.Status = constant.StatusSuccess
		item.From = "remote"
		_ = aiRepo.Create(&item)
	}

	return dropList, nil
}

// parseOllamaModelList turns `ollama list` stdout into model rows, dropping
// header/blank lines and any model name that fails validOllamaModelName:
// only whitelisted names may be persisted, because Delete and loadModelSize
// later hand the stored value to docker. A single odd entry is skipped (with
// a log entry) instead of failing the whole sync.
func parseOllamaModelList(stdout string) []model.OllamaModel {
	var list []model.OllamaModel
	for _, line := range strings.Split(stdout, "\n") {
		parts := strings.Fields(line)
		if len(parts) < 5 {
			continue
		}
		if parts[0] == "NAME" {
			continue
		}
		if !validOllamaModelName(parts[0]) {
			global.LOG.Errorf("skip ollama model %q from sync: invalid model name", parts[0])
			continue
		}
		list = append(list, model.OllamaModel{Name: parts[0], Size: parts[2] + " " + parts[3]})
	}
	return list
}

func (u *AIToolService) BindDomain(req dto.OllamaBindDomain) error {
	nginxInstall, _ := getAppInstallByKey(constant.AppOpenresty)
	if nginxInstall.ID == 0 {
		return buserr.New("ErrOpenrestyInstall")
	}
	var (
		ipList []string
		err    error
	)
	// The Ollama API proxied here has no built-in auth and allows model
	// pull/delete and inference, so an IP whitelist is mandatory.
	ipList, err = validateBindDomainIPs(req.IPList)
	if err != nil {
		return err
	}
	if req.SSLID > 0 {
		ssl, err := websiteSSLRepo.GetFirst(commonRepo.WithByID(req.SSLID))
		if err != nil {
			return err
		}
		if ssl.Pem == "" {
			return buserr.New("ErrSSL")
		}
	}
	createWebsiteReq := request.WebsiteCreate{
		PrimaryDomain: req.Domain,
		Alias:         strings.ToLower(req.Domain),
		Type:          constant.Deployment,
		AppType:       constant.InstalledApp,
		AppInstallID:  req.AppInstallID,
	}
	websiteService := NewIWebsiteService()
	if err := websiteService.CreateWebsite(createWebsiteReq); err != nil {
		return err
	}
	website, err := websiteRepo.GetFirst(websiteRepo.WithAlias(strings.ToLower(req.Domain)))
	if err != nil {
		return err
	}
	if len(ipList) > 0 {
		if err = ConfigAllowIPs(ipList, website); err != nil {
			return err
		}
	}
	if req.SSLID > 0 {
		sslReq := request.WebsiteHTTPSOp{
			WebsiteID:    website.ID,
			Enable:       true,
			Type:         "existed",
			WebsiteSSLID: req.SSLID,
			HttpConfig:   "HTTPSOnly",
		}
		if _, err = websiteService.OpWebsiteHTTPS(context.Background(), sslReq); err != nil {
			return err
		}
	}
	if err = ConfigAIProxy(website); err != nil {
		return err
	}
	return nil
}

func (u *AIToolService) GetBindDomain(req dto.OllamaBindDomainReq) (*dto.OllamaBindDomainRes, error) {
	install, err := appInstallRepo.GetFirst(commonRepo.WithByID(req.AppInstallID))
	if err != nil {
		return nil, err
	}
	res := &dto.OllamaBindDomainRes{}
	website, _ := websiteRepo.GetFirst(websiteRepo.WithAppInstallId(install.ID))
	if website.ID == 0 {
		return res, nil
	}
	res.WebsiteID = website.ID
	res.Domain = website.PrimaryDomain
	if website.WebsiteSSLID > 0 {
		res.SSLID = website.WebsiteSSLID
		ssl, _ := websiteSSLRepo.GetFirst(commonRepo.WithByID(website.WebsiteSSLID))
		res.AcmeAccountID = ssl.AcmeAccountID
	}
	res.ConnUrl = fmt.Sprintf("%s://%s", strings.ToLower(website.Protocol), website.PrimaryDomain)
	res.AllowIPs = GetAllowIps(website)
	return res, nil
}

func (u *AIToolService) UpdateBindDomain(req dto.OllamaBindDomain) error {
	nginxInstall, _ := getAppInstallByKey(constant.AppOpenresty)
	if nginxInstall.ID == 0 {
		return buserr.New("ErrOpenrestyInstall")
	}
	var (
		ipList []string
		err    error
	)
	// The Ollama API proxied here has no built-in auth and allows model
	// pull/delete and inference, so an IP whitelist is mandatory.
	ipList, err = validateBindDomainIPs(req.IPList)
	if err != nil {
		return err
	}
	if req.SSLID > 0 {
		ssl, err := websiteSSLRepo.GetFirst(commonRepo.WithByID(req.SSLID))
		if err != nil {
			return err
		}
		if ssl.Pem == "" {
			return buserr.New("ErrSSL")
		}
	}
	websiteService := NewIWebsiteService()
	website, err := websiteRepo.GetFirst(commonRepo.WithByID(req.WebsiteID))
	if err != nil {
		return err
	}
	if err = ConfigAllowIPs(ipList, website); err != nil {
		return err
	}
	if req.SSLID > 0 {
		sslReq := request.WebsiteHTTPSOp{
			WebsiteID:    website.ID,
			Enable:       true,
			Type:         "existed",
			WebsiteSSLID: req.SSLID,
			HttpConfig:   "HTTPSOnly",
		}
		if _, err = websiteService.OpWebsiteHTTPS(context.Background(), sslReq); err != nil {
			return err
		}
		return nil
	}
	if website.WebsiteSSLID > 0 && req.SSLID == 0 {
		sslReq := request.WebsiteHTTPSOp{
			WebsiteID: website.ID,
			Enable:    false,
		}
		if _, err = websiteService.OpWebsiteHTTPS(context.Background(), sslReq); err != nil {
			return err
		}
	}
	return nil
}

func LoadContainerName() (string, error) {
	ollamaBaseInfo, err := appInstallRepo.LoadBaseInfo("ollama", "")
	if err != nil {
		return "", fmt.Errorf("ollama service is not found, err: %v", err)
	}
	if ollamaBaseInfo.Status != constant.Running {
		return "", fmt.Errorf("container %s of ollama is not running, please check and retry!", ollamaBaseInfo.ContainerName)
	}
	return ollamaBaseInfo.ContainerName, nil
}

func pullOllamaModel(file *os.File, containerName string, info model.OllamaModel) {
	defer file.Close()
	cmd := exec.Command("docker", "exec", containerName, "ollama", "pull", info.Name)
	multiWriter := io.MultiWriter(os.Stdout, file)
	cmd.Stdout = multiWriter
	cmd.Stderr = multiWriter
	_ = cmd.Run()
	itemSize, err := loadModelSize(info.Name, containerName)
	if len(itemSize) != 0 {
		_ = aiRepo.Update(info.ID, map[string]interface{}{"status": constant.StatusSuccess, "size": itemSize})
	} else {
		_ = aiRepo.Update(info.ID, map[string]interface{}{"status": constant.StatusFailed, "message": err.Error()})
	}
	_, _ = file.WriteString("ollama pull completed!")
}

func loadModelSize(name string, containerName string) (string, error) {
	// name comes from the DB row of a pull this panel started (Create/
	// Recreate validate it before persisting), but the row may predate the
	// whitelist, so re-check defensively before the value reaches docker.
	if !validOllamaModelName(name) {
		return "", buserr.New(constant.ErrCmdIllegal)
	}
	stdout, err := cmd.ExecWithCheck("docker", "exec", containerName, "ollama", "list")
	if err != nil {
		return "", err
	}
	size, err := matchModelSize(stdout, name)
	if err != nil {
		return "", err
	}
	return size, nil
}

// matchModelSize scans `ollama list` stdout for the row whose NAME column
// equals name and returns its SIZE columns. The old `grep`-based lookup
// matched any column and any prefix; matching the NAME column exactly keeps
// loadModelSize honest.
func matchModelSize(stdout, name string) (string, error) {
	for _, line := range strings.Split(stdout, "\n") {
		parts := strings.Fields(line)
		if len(parts) < 5 {
			continue
		}
		if parts[0] == name {
			return parts[2] + " " + parts[3], nil
		}
	}
	return "", fmt.Errorf("no such model %s in ollama list, std: %s", name, stdout)
}
