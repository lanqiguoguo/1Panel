package service

import (
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/1Panel-dev/1Panel/backend/app/dto"
	"github.com/1Panel-dev/1Panel/backend/app/model"
	"github.com/1Panel-dev/1Panel/backend/buserr"
	"github.com/1Panel-dev/1Panel/backend/constant"
	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/1Panel-dev/1Panel/backend/utils/cmd"
	"github.com/1Panel-dev/1Panel/backend/utils/common"
	"github.com/1Panel-dev/1Panel/backend/utils/systemctl"
	"github.com/jinzhu/copier"
	"github.com/robfig/cron/v3"

	"github.com/pkg/errors"
)

const (
	clamServiceKey      = "clam"
	freshClamServiceKey = "freshclam"
	resultDir           = "clamav"
)

// clamNameRegexp matches the charset the frontend offers for ClamAV rule
// names (Rules.simpleName): alphanumerics, underscore and dash, capped at the
// 64 characters of the model.Clam name column. Clam names
// are both a directory under DataDir/clamav/ and an unquoted interpolation
// of `clamdscan ... -l <logFile>` (bash -c, see cmd.Execf), so a strict
// whitelist is the safest gate: it cannot smuggle path separators, "..",
// spaces, backslashes or shell metacharacters into either data flow.
var clamNameRegexp = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`)

// clamRecordNameRegexp matches a scan-record log file name. Records are
// created by HandleOnce as DataDir/clamav/<name>/<DateTimeSlimLayout>, i.e.
// a plain 14-digit timestamp ("20060102150405"), so the whitelist accepts
// exactly that shape and rejects anything that could traverse (RecordName is
// joined into the tail'd path of LoadRecordLog).
var clamRecordNameRegexp = regexp.MustCompile(`^[0-9]{14}$`)

// validClamName reports whether name is a safe ClamAV rule name (see
// clamNameRegexp).
func validClamName(name string) bool {
	return clamNameRegexp.MatchString(name)
}

// validClamRecordName reports whether name is a safe scan-record log file
// name (see clamRecordNameRegexp).
func validClamRecordName(name string) bool {
	return clamRecordNameRegexp.MatchString(name)
}

// validClamShellArg reports whether s can be safely interpolated unquoted
// into the `bash -c "clamdscan ..."` command (see cmd.Execf). cmd.CheckIllegal
// rejects the shell metacharacters but deliberately keeps spaces and
// backslashes legal file-name characters; here they must be refused as well,
// because bash word-splits on spaces and treats backslash as an escape in the
// unquoted interpolation.
func validClamShellArg(s string) bool {
	if s == "" || cmd.CheckIllegal(s) {
		return false
	}
	return !strings.ContainsAny(s, " \\")
}

// validClamScanDir reports whether an infected directory is safe for both of
// its data flows: it is interpolated unquoted into `--move=<dir>` /
// `--copy=<dir>` (validClamShellArg) and it is joined with path/filepath to
// locate files, so it must be an absolute path. Any ".." path segment is
// refused outright: filepath.Clean would fold it into a valid absolute
// target, but a value like "/tmp/../../etc" retargets the quarantine dir to
// a location the admin never typed, and normal quarantine paths have no
// reason to carry dot-dot segments.
func validClamScanDir(dir string) bool {
	if !validClamShellArg(dir) {
		return false
	}
	if !filepath.IsAbs(filepath.Clean(dir)) {
		return false
	}
	for _, seg := range strings.Split(dir, "/") {
		if seg == ".." {
			return false
		}
	}
	return true
}

// validClamTail reports whether tail is a plain number, as sent by the
// frontend tail select ("0", "10", ... ). LoadRecordLog passes it as a
// separate tail argv, but a value like "-1 /etc/x" or "+1;id" must still be
// refused; digits-only keeps the whitelist minimal.
func validClamTail(tail string) bool {
	if tail == "" || len(tail) > 9 {
		return false
	}
	for _, r := range tail {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

type ClamService struct {
	serviceName      string
	freshClamService string
}

type IClamService interface {
	LoadBaseInfo() (dto.ClamBaseInfo, error)
	Operate(operate string) error
	SearchWithPage(search dto.SearchClamWithPage) (int64, interface{}, error)
	Create(req dto.ClamCreate) error
	Update(req dto.ClamUpdate) error
	Delete(req dto.ClamDelete) error
	HandleOnce(req dto.OperateByID) error
	LoadFile(req dto.ClamFileReq) (string, error)
	UpdateFile(req dto.UpdateByNameAndFile) error
	LoadRecords(req dto.ClamLogSearch) (int64, interface{}, error)
	CleanRecord(req dto.OperateByID) error

	LoadRecordLog(req dto.ClamLogReq) (string, error)
}

func NewIClamService() IClamService {
	return &ClamService{}
}

func (c *ClamService) LoadBaseInfo() (dto.ClamBaseInfo, error) {
	var baseInfo dto.ClamBaseInfo
	baseInfo.Version = "-"
	baseInfo.FreshVersion = "-"
	clamSvc, err := systemctl.GetServiceName(clamServiceKey)
	if err != nil {
		baseInfo.IsExist = false
		return baseInfo, nil
	}
	c.serviceName = clamSvc
	isExist, err := systemctl.IsExist(c.serviceName)
	if err != nil {
		baseInfo.IsExist = false
	}
	baseInfo.IsExist = isExist
	baseInfo.IsActive, _ = systemctl.IsActive(clamSvc)

	freshSvc, err := systemctl.GetServiceName(freshClamServiceKey)
	if err != nil {
		baseInfo.FreshIsExist = false
		return baseInfo, nil
	}
	c.freshClamService = freshSvc
	freshisExist, err := systemctl.IsExist(c.freshClamService)
	if err != nil {
		baseInfo.FreshIsExist = false
	}
	baseInfo.FreshIsExist = freshisExist
	baseInfo.FreshIsActive, _ = systemctl.IsActive(freshSvc)

	if !cmd.Which("clamdscan") {
		baseInfo.IsActive = false
	}

	if baseInfo.IsActive {
		version, err := cmd.Exec("clamdscan --version")
		if err == nil {
			if strings.Contains(version, "/") {
				baseInfo.Version = strings.TrimPrefix(strings.Split(version, "/")[0], "ClamAV ")
			} else {
				baseInfo.Version = strings.TrimPrefix(version, "ClamAV ")
			}
		}
	} else {
		_ = StopAllCronJob(false)
	}
	if baseInfo.FreshIsActive {
		version, err := cmd.Exec("freshclam --version")
		if err == nil {
			if strings.Contains(version, "/") {
				baseInfo.FreshVersion = strings.TrimPrefix(strings.Split(version, "/")[0], "ClamAV ")
			} else {
				baseInfo.FreshVersion = strings.TrimPrefix(version, "ClamAV ")
			}
		}
	}
	return baseInfo, nil
}

func (c *ClamService) Operate(operate string) error {
	var err error
	switch operate {
	case "start":
		err = systemctl.Start(c.serviceName)
	case "stop":
		err = systemctl.Stop(c.serviceName)
	case "restart":
		err = systemctl.Restart(c.serviceName)
	case "fresh-start":
		err = systemctl.Start(c.freshClamService)
	case "fresh-stop":
		err = systemctl.Stop(c.freshClamService)
	case "fresh-restart":
		err = systemctl.Restart(c.freshClamService)
	default:
		return fmt.Errorf("unsupported operation: %s", operate)
	}
	if err != nil {
		return fmt.Errorf("%s %s failed: %v", operate, c.serviceName, err)
	}
	return nil
}

func (c *ClamService) SearchWithPage(req dto.SearchClamWithPage) (int64, interface{}, error) {
	total, commands, err := clamRepo.Page(req.Page, req.PageSize, commonRepo.WithLikeName(req.Info), commonRepo.WithOrderRuleBy(req.OrderBy, req.Order))
	if err != nil {
		return 0, nil, err
	}
	var datas []dto.ClamInfo
	for _, command := range commands {
		var item dto.ClamInfo
		if err := copier.Copy(&item, &command); err != nil {
			return 0, nil, errors.WithMessage(constant.ErrStructTransform, err.Error())
		}
		item.LastHandleDate = "-"
		datas = append(datas, item)
	}
	nyc, _ := time.LoadLocation(common.LoadTimeZoneByCmd())
	for i := 0; i < len(datas); i++ {
		// Defensive re-validation: a tampered name would make
		// loadFileByName walk arbitrary directories; skip such rows.
		if !validClamName(datas[i].Name) {
			continue
		}
		logPaths := loadFileByName(datas[i].Name)
		sort.Slice(logPaths, func(i, j int) bool {
			return logPaths[i] > logPaths[j]
		})
		if len(logPaths) != 0 {
			t1, err := time.ParseInLocation(constant.DateTimeSlimLayout, logPaths[0], nyc)
			if err != nil {
				continue
			}
			datas[i].LastHandleDate = t1.Format(constant.DateTimeLayout)
		}
	}
	return total, datas, err
}

func (c *ClamService) Create(req dto.ClamCreate) error {
	// Name becomes the log directory under DataDir/clamav/ and part of the
	// unquoted clamdscan command, Path and InfectedDir are unquoted
	// command interpolations, so all three are validated here at the
	// service boundary (see validClamName / validClamScanDir).
	if err := validateClamParams(req.Name, req.Path, req.InfectedStrategy, req.InfectedDir); err != nil {
		return err
	}
	clam, _ := clamRepo.Get(commonRepo.WithByName(req.Name))
	if clam.ID != 0 {
		return constant.ErrRecordExist
	}
	if err := copier.Copy(&clam, &req); err != nil {
		return errors.WithMessage(constant.ErrStructTransform, err.Error())
	}
	if clam.InfectedStrategy == "none" || clam.InfectedStrategy == "remove" {
		clam.InfectedDir = ""
	}
	if err := clamRepo.Create(&clam); err != nil {
		return err
	}

	return nil
}

func (c *ClamService) Update(req dto.ClamUpdate) error {
	if err := validateClamParams(req.Name, req.Path, req.InfectedStrategy, req.InfectedDir); err != nil {
		return err
	}
	clam, _ := clamRepo.Get(commonRepo.WithByName(req.Name))
	if clam.ID == 0 {
		return constant.ErrRecordNotFound
	}
	if req.InfectedStrategy == "none" || req.InfectedStrategy == "remove" {
		req.InfectedDir = ""
	}
	upMap := map[string]interface{}{}
	upMap["name"] = req.Name
	upMap["path"] = req.Path
	upMap["infected_dir"] = req.InfectedDir
	upMap["infected_strategy"] = req.InfectedStrategy
	upMap["spec"] = req.Spec
	upMap["description"] = req.Description
	if err := clamRepo.Update(req.ID, upMap); err != nil {
		return err
	}
	return nil

}

// validateClamParams is the shared service-boundary gate for Create/Update.
// strategy none/remove leaves InfectedDir unused (Create/Update blank it
// afterwards, matching the pre-existing behavior), so it is only required
// for move/copy. Path is interpolated unquoted into the clamdscan command,
// so it goes through the same shell-arg gate as InfectedDir.
func validateClamParams(name, scanPath, strategy, infectedDir string) error {
	if !validClamName(name) {
		return buserr.New(constant.ErrCmdIllegal)
	}
	if !validClamShellArg(scanPath) {
		return buserr.New(constant.ErrCmdIllegal)
	}
	switch strategy {
	case "none", "remove":
	case "move", "copy":
		if !validClamScanDir(infectedDir) {
			return buserr.New(constant.ErrCmdIllegal)
		}
	case "": // legacy rows without an explicit strategy behave like "none"
	default:
		return buserr.New(constant.ErrTypeInvalidParams)
	}
	return nil
}

// validateClamScanRow is the defensive re-validation HandleOnce applies to a
// DB-stored row before the scan: Path is interpolated unquoted into the
// `clamdscan ... %s` command (bash -c, see cmd.Execf) so it must pass the
// same gate as Create/Update (validClamShellArg — cmd.CheckIllegal alone
// would still let spaces word-split and backslashes escape into extra argv),
// Name becomes the log directory and part of the same command line, and
// InfectedDir is interpolated unquoted into `--move=`/`--copy=` when the
// strategy needs it. This protects against pre-existing dirty rows.
func validateClamScanRow(clam model.Clam) error {
	if !validClamShellArg(clam.Path) {
		return buserr.New(constant.ErrCmdIllegal)
	}
	if !validClamName(clam.Name) {
		return buserr.New(constant.ErrCmdIllegal)
	}
	switch clam.InfectedStrategy {
	case "none", "remove", "":
	case "move", "copy":
		if !validClamScanDir(clam.InfectedDir) {
			return buserr.New(constant.ErrCmdIllegal)
		}
	default:
		return buserr.New(constant.ErrTypeInvalidParams)
	}
	return nil
}

func (c *ClamService) Delete(req dto.ClamDelete) error {
	for _, id := range req.Ids {
		clam, _ := clamRepo.Get(commonRepo.WithByID(id))
		if clam.ID == 0 {
			continue
		}
		// Defensive re-validation of the DB-stored values: both are joined
		// into os.RemoveAll targets below, so a tampered row must not turn
		// into an arbitrary directory deletion.
		if !validClamName(clam.Name) {
			return buserr.New(constant.ErrCmdIllegal)
		}
		if req.RemoveInfected {
			// none/remove rows legitimately store an empty InfectedDir (and
			// pre-fix rows may keep other legacy values); only a non-empty
			// value is joined into the os.RemoveAll target below, so only
			// that case must pass the full dir gate.
			switch clam.InfectedStrategy {
			case "", "none", "remove":
			case "move", "copy":
				// validClamScanDir implies non-empty, no shell
				// metacharacters and an absolute cleaned path.
				if !validClamScanDir(clam.InfectedDir) {
					return buserr.New(constant.ErrCmdIllegal)
				}
			default:
				return buserr.New(constant.ErrTypeInvalidParams)
			}
		}
		if req.RemoveRecord {
			_ = os.RemoveAll(path.Join(global.CONF.System.DataDir, resultDir, clam.Name))
		}
		if req.RemoveInfected {
			_ = os.RemoveAll(path.Join(clam.InfectedDir, "1panel-infected", clam.Name))
		}
		if err := clamRepo.Delete(commonRepo.WithByID(id)); err != nil {
			return err
		}
	}
	return nil
}

func (c *ClamService) HandleOnce(req dto.OperateByID) error {
	if cleaned := StopAllCronJob(true); cleaned {
		return buserr.New("ErrClamdscanNotFound")
	}
	clam, _ := clamRepo.Get(commonRepo.WithByID(req.ID))
	if clam.ID == 0 {
		return constant.ErrRecordNotFound
	}
	if err := validateClamScanRow(clam); err != nil {
		return err
	}
	timeNow := time.Now().Format(constant.DateTimeSlimLayout)
	logFile := path.Join(global.CONF.System.DataDir, resultDir, clam.Name, timeNow)
	if _, err := os.Stat(path.Dir(logFile)); err != nil {
		_ = os.MkdirAll(path.Dir(logFile), os.ModePerm)
	}
	go func() {
		strategy := ""
		switch clam.InfectedStrategy {
		case "remove":
			strategy = "--remove"
		case "move":
			dir := path.Join(clam.InfectedDir, "1panel-infected", clam.Name, timeNow)
			strategy = "--move=" + dir
			if _, err := os.Stat(dir); err != nil {
				_ = os.MkdirAll(dir, os.ModePerm)
			}
		case "copy":
			dir := path.Join(clam.InfectedDir, "1panel-infected", clam.Name, timeNow)
			strategy = "--copy=" + dir
			if _, err := os.Stat(dir); err != nil {
				_ = os.MkdirAll(dir, os.ModePerm)
			}
		}
		global.LOG.Debugf("clamdscan --fdpass %s %s -l %s", strategy, clam.Path, logFile)
		stdout, err := cmd.Execf("clamdscan --fdpass %s %s -l %s", strategy, clam.Path, logFile)
		if err != nil {
			global.LOG.Errorf("clamdscan failed, stdout: %v, err: %v", stdout, err)
		}
	}()
	return nil
}

func (c *ClamService) LoadRecords(req dto.ClamLogSearch) (int64, interface{}, error) {
	clam, _ := clamRepo.Get(commonRepo.WithByID(req.ClamID))
	if clam.ID == 0 {
		return 0, nil, constant.ErrRecordNotFound
	}
	// Defensive re-validation: the DB-stored name is joined into the walked
	// and read log paths below.
	if !validClamName(clam.Name) {
		return 0, nil, buserr.New(constant.ErrCmdIllegal)
	}
	logPaths := loadFileByName(clam.Name)
	if len(logPaths) == 0 {
		return 0, nil, nil
	}

	var filterFiles []string
	nyc, _ := time.LoadLocation(common.LoadTimeZoneByCmd())
	for _, item := range logPaths {
		t1, err := time.ParseInLocation(constant.DateTimeSlimLayout, item, nyc)
		if err != nil {
			continue
		}
		if t1.After(req.StartTime) && t1.Before(req.EndTime) {
			filterFiles = append(filterFiles, item)
		}
	}
	if len(filterFiles) == 0 {
		return 0, nil, nil
	}

	sort.Slice(filterFiles, func(i, j int) bool {
		return filterFiles[i] > filterFiles[j]
	})

	var records []string
	total, start, end := len(filterFiles), (req.Page-1)*req.PageSize, req.Page*req.PageSize
	if start > total {
		records = make([]string, 0)
	} else {
		if end >= total {
			end = total
		}
		records = filterFiles[start:end]
	}

	var datas []dto.ClamLog
	for i := 0; i < len(records); i++ {
		item := loadResultFromLog(path.Join(global.CONF.System.DataDir, resultDir, clam.Name, records[i]))
		datas = append(datas, item)
	}
	return int64(total), datas, nil
}
func (c *ClamService) LoadRecordLog(req dto.ClamLogReq) (string, error) {
	// ClamName/RecordName are joined into the tail'd path below, so a
	// traversal pair like "../.." + "../../../etc/shadow" must be refused;
	// Tail is passed to the tail command, so it stays digits-only.
	if !validClamName(req.ClamName) || !validClamRecordName(req.RecordName) || !validClamTail(req.Tail) {
		return "", buserr.New(constant.ErrTypeInvalidParams)
	}
	logPath := path.Join(global.CONF.System.DataDir, resultDir, req.ClamName, req.RecordName)
	var tail string
	if req.Tail != "0" {
		tail = req.Tail
	} else {
		tail = "+1"
	}
	cmd := exec.Command("tail", "-n", tail, logPath)
	stdout, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("tail -n %v failed, err: %v", req.Tail, err)
	}
	return string(stdout), nil
}

func (c *ClamService) CleanRecord(req dto.OperateByID) error {
	clam, _ := clamRepo.Get(commonRepo.WithByID(req.ID))
	if clam.ID == 0 {
		return constant.ErrRecordNotFound
	}
	// Defensive re-validation: the DB-stored name is joined into the
	// os.RemoveAll target below.
	if !validClamName(clam.Name) {
		return buserr.New(constant.ErrCmdIllegal)
	}
	pathItem := path.Join(global.CONF.System.DataDir, resultDir, clam.Name)
	_ = os.RemoveAll(pathItem)
	return nil
}

func (c *ClamService) LoadFile(req dto.ClamFileReq) (string, error) {
	filePath := ""
	switch req.Name {
	case "clamd":
		filePath = c.getConfigPath("clamd")
	case "clamd-log":
		filePath = c.loadLogPath("clamd-log")
	case "freshclam":
		filePath = c.getConfigPath("freshclam")
	case "freshclam-log":
		filePath = c.loadLogPath("freshclam-log")
	default:
		return "", fmt.Errorf("unsupported file type")
	}

	content, err := systemctl.ViewConfig(filePath, systemctl.ConfigOption{TailLines: req.Tail})
	if err != nil {
		return "", buserr.New("ErrHttpReqNotFound")
	}
	return content, nil
}

func (c *ClamService) UpdateFile(req dto.UpdateByNameAndFile) error {
	var (
		filePath string
		service  string
	)

	switch req.Name {
	case "clamd":
		filePath = c.getConfigPath("clamd")
		service = c.serviceName
	case "freshclam":
		filePath = c.getConfigPath("freshclam")
		service = c.freshClamService
	default:
		return fmt.Errorf("unsupported file type")
	}

	file, err := os.OpenFile(filePath, os.O_WRONLY|os.O_TRUNC, 0640)
	if err != nil {
		return err
	}
	defer file.Close()

	if _, err := file.WriteString(req.File); err != nil {
		return err
	}

	if err := systemctl.Restart(service); err != nil {
		return fmt.Errorf("restart %s failed: %v", service, err)
	}
	return nil
}

func (c *ClamService) getConfigPath(confType string) string {
	switch confType {
	case "clamd":
		if _, err := os.Stat("/etc/clamav/clamd.conf"); err == nil {
			return "/etc/clamav/clamd.conf"
		}
		return "/etc/clamd.d/scan.conf"
	case "freshclam":
		if _, err := os.Stat("/etc/clamav/freshclam.conf"); err == nil {
			return "/etc/clamav/freshclam.conf"
		}
		return "/etc/freshclam.conf"
	default:
		return ""
	}
}

func StopAllCronJob(withCheck bool) bool {
	if withCheck {
		isActive := false
		isexist, _ := systemctl.IsExist(clamServiceKey)
		if isexist {
			isActive, _ = systemctl.IsActive(clamServiceKey)
		}
		if isActive {
			return false
		}
	}
	clams, _ := clamRepo.List(commonRepo.WithByStatus(constant.StatusEnable))
	for i := 0; i < len(clams); i++ {
		global.Cron.Remove(cron.EntryID(clams[i].EntryID))
		_ = clamRepo.Update(clams[i].ID, map[string]interface{}{"status": constant.StatusDisable, "entry_id": 0})
	}
	return true
}

func loadFileByName(name string) []string {
	var logPaths []string
	pathItem := path.Join(global.CONF.System.DataDir, resultDir, name)
	_ = filepath.Walk(pathItem, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() || info.Name() == name {
			return nil
		}
		logPaths = append(logPaths, info.Name())
		return nil
	})
	return logPaths
}
func loadResultFromLog(pathItem string) dto.ClamLog {
	var data dto.ClamLog
	data.Name = path.Base(pathItem)
	data.Status = constant.StatusWaiting
	file, err := os.ReadFile(pathItem)
	if err != nil {
		return data
	}
	lines := strings.Split(string(file), "\n")
	for _, line := range lines {
		if strings.Contains(line, "- SCAN SUMMARY -") {
			data.Status = constant.StatusDone
		}
		if data.Status != constant.StatusDone {
			continue
		}
		switch {
		case strings.HasPrefix(line, "Infected files:"):
			data.InfectedFiles = strings.TrimPrefix(line, "Infected files:")
		case strings.HasPrefix(line, "Total errors:"):
			data.TotalError = strings.TrimPrefix(line, "Total errors:")
		case strings.HasPrefix(line, "Time:"):
			if strings.Contains(line, "(") {
				data.ScanTime = strings.ReplaceAll(strings.Split(line, "(")[1], ")", "")
				continue
			}
			data.ScanTime = strings.TrimPrefix(line, "Time:")
		case strings.HasPrefix(line, "Start Date:"):
			data.ScanDate = strings.TrimPrefix(line, "Start Date:")
		}
	}
	return data
}
func (c *ClamService) loadLogPath(name string) string {
	configKey := "clamd"
	searchPrefix := "LogFile "
	if name != "clamd-log" {
		configKey = "freshclam"
		searchPrefix = "UpdateLogFile "
	}
	confPath := c.getConfigPath(configKey)

	content, err := os.ReadFile(confPath)
	if err != nil {
		global.LOG.Debugf("Failed to read %s config: %v", configKey, err)
		return ""
	}

	for _, line := range strings.Split(string(content), "\n") {
		if strings.HasPrefix(line, searchPrefix) {
			return strings.TrimSpace(strings.TrimPrefix(line, searchPrefix))
		}
	}
	return ""
}
