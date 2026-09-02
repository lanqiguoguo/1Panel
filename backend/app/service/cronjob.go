package service

import (
	"bufio"
	"fmt"
	"os"
	"path"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/1Panel-dev/1Panel/backend/app/dto"
	"github.com/1Panel-dev/1Panel/backend/app/model"
	"github.com/1Panel-dev/1Panel/backend/buserr"
	"github.com/1Panel-dev/1Panel/backend/constant"
	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/1Panel-dev/1Panel/backend/utils/cmd"
	"github.com/1Panel-dev/1Panel/backend/utils/files"
	"github.com/jinzhu/copier"
	"github.com/pkg/errors"
	"github.com/robfig/cron/v3"
)

type CronjobService struct{}

type ICronjobService interface {
	SearchWithPage(search dto.PageCronjob) (int64, interface{}, error)
	SearchRecords(search dto.SearchRecord) (int64, interface{}, error)
	Create(cronjobDto dto.CronjobCreate) error
	HandleOnce(id uint) error
	Update(id uint, req dto.CronjobUpdate) error
	UpdateStatus(id uint, status string) error
	Delete(req dto.CronjobBatchDelete) error
	Download(down dto.CronjobDownload) (string, error)
	StartJob(cronjob *model.Cronjob, isUpdate bool) (string, error)
	CleanRecord(req dto.CronjobClean) error

	LoadRecordLog(req dto.OperateByID) string
}

func NewICronjobService() ICronjobService {
	return &CronjobService{}
}

func (u *CronjobService) SearchWithPage(search dto.PageCronjob) (int64, interface{}, error) {
	total, cronjobs, err := cronjobRepo.Page(search.Page, search.PageSize, commonRepo.WithLikeName(search.Info), commonRepo.WithOrderRuleBy(search.OrderBy, search.Order))
	var dtoCronjobs []dto.CronjobInfo
	for _, cronjob := range cronjobs {
		var item dto.CronjobInfo
		if err := copier.Copy(&item, &cronjob); err != nil {
			return 0, nil, errors.WithMessage(constant.ErrStructTransform, err.Error())
		}
		record, _ := cronjobRepo.RecordFirst(cronjob.ID)
		if record.ID != 0 {
			item.LastRecordTime = record.StartTime.Format(constant.DateTimeLayout)
		} else {
			item.LastRecordTime = "-"
		}
		dtoCronjobs = append(dtoCronjobs, item)
	}
	return total, dtoCronjobs, err
}

func (u *CronjobService) SearchRecords(search dto.SearchRecord) (int64, interface{}, error) {
	total, records, err := cronjobRepo.PageRecords(
		search.Page,
		search.PageSize,
		commonRepo.WithByStatus(search.Status),
		cronjobRepo.WithByJobID(search.CronjobID),
		commonRepo.WithByDate(search.StartTime, search.EndTime))
	var dtoCronjobs []dto.Record
	for _, record := range records {
		var item dto.Record
		if err := copier.Copy(&item, &record); err != nil {
			return 0, nil, errors.WithMessage(constant.ErrStructTransform, err.Error())
		}
		item.StartTime = record.StartTime.Format(constant.DateTimeLayout)
		dtoCronjobs = append(dtoCronjobs, item)
	}
	return total, dtoCronjobs, err
}

func (u *CronjobService) LoadRecordLog(req dto.OperateByID) string {
	record, err := cronjobRepo.GetRecord(commonRepo.WithByID(req.ID))
	if err != nil {
		return ""
	}
	if _, err := os.Stat(record.Records); err != nil {
		return ""
	}
	content, err := os.ReadFile(record.Records)
	if err != nil {
		return ""
	}
	return string(content)
}

func (u *CronjobService) CleanRecord(req dto.CronjobClean) error {
	// Phase 1 runs outside the run lock: it may delete remote backups or
	// expire old logs, which can take a long time and must not stall the
	// record insertion of every other running job.
	if err := u.cleanRecordPreflight(req); err != nil {
		return err
	}
	// Phase 2 serializes the record wipe against a job body starting right now
	// (HandleJob inserts its record under the same lock) so the wipe below is
	// atomic with respect to new record creation. A body already in flight is
	// not interrupted: its EndRecords update simply matches zero rows once the
	// record is gone.
	cronjobRunMu.Lock()
	defer cronjobRunMu.Unlock()
	return u.cleanRecordWipe(req)
}

// cleanRecordPreflight executes the data-removal phase of CleanRecord
// (remote backups / expired logs) without holding cronjobRunMu.
func (u *CronjobService) cleanRecordPreflight(req dto.CronjobClean) error {
	cronjob, err := cronjobRepo.Get(commonRepo.WithByID(req.CronjobID))
	if err != nil {
		return err
	}
	if req.CleanData {
		if hasBackup(cronjob.Type) {
			accountMap, err := loadClientMap(cronjob.BackupAccounts)
			if err != nil {
				return err
			}
			if !req.CleanRemoteData {
				for key := range accountMap {
					if key != constant.Local {
						delete(accountMap, key)
					}
				}
			}
			cronjob.RetainCopies = 0
			if len(accountMap) != 0 {
				u.removeExpiredBackup(cronjob, accountMap, model.BackupRecord{})
			}
		} else {
			u.removeExpiredLog(cronjob)
		}
	}
	return nil
}

// cleanRecordWipe detaches backup records, deletes the log files of every
// remaining JobRecords row and deletes the rows themselves. Callers must
// hold cronjobRunMu (CleanRecord does; Delete holds it across this and the
// cronjob row delete so no record can be created for the deleted job
// afterwards).
func (u *CronjobService) cleanRecordWipe(req dto.CronjobClean) error {
	cronjob, err := cronjobRepo.Get(commonRepo.WithByID(req.CronjobID))
	if err != nil {
		return err
	}
	if req.IsDelete {
		records, _ := backupRepo.ListRecord(backupRepo.WithByCronID(cronjob.ID))
		for _, records := range records {
			records.CronjobID = 0
			_ = backupRepo.UpdateRecord(&records)
		}
	}
	delRecords, err := cronjobRepo.ListRecord(cronjobRepo.WithByJobID(int(req.CronjobID)))
	if err != nil {
		return err
	}
	for _, del := range delRecords {
		_ = os.RemoveAll(del.Records)
	}
	if err := cronjobRepo.DeleteRecord(cronjobRepo.WithByJobID(int(req.CronjobID))); err != nil {
		return err
	}
	return nil
}

func (u *CronjobService) Download(down dto.CronjobDownload) (string, error) {
	record, _ := cronjobRepo.GetRecord(commonRepo.WithByID(down.RecordID))
	if record.ID == 0 {
		return "", constant.ErrRecordNotFound
	}
	backup, _ := backupRepo.Get(commonRepo.WithByID(down.BackupAccountID))
	if backup.ID == 0 {
		return "", constant.ErrRecordNotFound
	}
	if backup.Type == "LOCAL" || record.FromLocal {
		if _, err := os.Stat(record.File); err != nil && os.IsNotExist(err) {
			return "", err
		}
		return record.File, nil
	}
	tempPath := fmt.Sprintf("%s/download/%s", constant.DataDir, record.File)
	if _, err := os.Stat(tempPath); err != nil && os.IsNotExist(err) {
		client, err := NewIBackupService().NewClient(&backup)
		if err != nil {
			return "", err
		}
		_ = os.MkdirAll(path.Dir(tempPath), os.ModePerm)
		isOK, err := client.Download(record.File, tempPath)
		if !isOK || err != nil {
			return "", err
		}
	}
	return tempPath, nil
}

func (u *CronjobService) HandleOnce(id uint) error {
	cronjob, _ := cronjobRepo.Get(commonRepo.WithByID(id))
	if cronjob.ID == 0 {
		return constant.ErrRecordNotFound
	}
	// HandleJob runs synchronously now, so trigger it in the background to
	// keep the HTTP request non-blocking for long-running jobs. The guard and
	// recover inside HandleJob still cover this goroutine: a trigger while the
	// same job is already running is skipped with a log entry, and a panicking
	// job body cannot take down the panel process.
	// The job row is re-read inside the goroutine (handleOnceBackground): a
	// concurrent Delete may remove the row after the check above but before
	// the goroutine starts, and running a deleted job would recreate its
	// task directory and logs (and orphan JobRecords) after the cleanup.
	go u.handleOnceBackground(id)
	return nil
}

// handleOnceBackground runs the manual-trigger body against a freshly loaded
// cronjob row. If the job was deleted in the meantime the run is skipped with
// a log entry, so a manual trigger can never race a Delete into recreating
// the removed task artifacts.
func (u *CronjobService) handleOnceBackground(id uint) {
	cronjob, _ := cronjobRepo.Get(commonRepo.WithByID(id))
	if cronjob.ID == 0 {
		global.LOG.Infof("skip manual trigger of cronjob %d: the job has been deleted", id)
		return
	}
	u.HandleJob(&cronjob)
}

// validCronjobName reports whether name is safe to embed into shell commands
// and filesystem paths under DataDir/task/<type>/<name>. The frontend only
// enforces required + no-space for cronjob names and Chinese names are a
// pre-existing legal value, so the check is a denylist rather than an ASCII
// whitelist: valid UTF-8, no control characters, no shell metacharacters and
// no path separators or ".." components (which would escape the per-job task
// and backup directories).
func validCronjobName(name string) bool {
	if name == "" || len(name) > 255 || !utf8.ValidString(name) {
		return false
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	if strings.ContainsAny(name, `/\`) || strings.Contains(name, "..") {
		return false
	}
	return !cmd.CheckIllegal(name)
}

// validCronjobExclusionRules reports whether every comma-separated exclusion
// rule is free of shell metacharacters. Glob characters ('*', '?', '[]') and
// path separators are legal here because rules look like "*.log" or
// "/path/to/dir", so cmd.CheckIllegal (which rejects &, |, ;, $, quotes,
// backticks, parentheses, redirections and newlines) is the right fit.
func validCronjobExclusionRules(rules string) bool {
	if rules == "" {
		return true
	}
	for _, rule := range strings.Split(rules, ",") {
		if len(rule) != 0 && cmd.CheckIllegal(rule) {
			return false
		}
	}
	return true
}

// validCronjobURL reports whether url is safe to interpolate into
// `curl '<url>'`, which the host shell executes for curl cronjobs. The URL is
// optional (an empty value makes the job body a no-op), must use the http(s)
// scheme and must be free of shell metacharacters and quotes so it can never
// break out of the single quoting. Shared by the Create/Update entry-point
// checks and the runtime HandleJob guard.
func validCronjobURL(url string) bool {
	if url == "" {
		return true
	}
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		return false
	}
	// The URL is interpolated into `curl '<url>'`; a quote or any
	// shell metacharacter would break out of it.
	return !cmd.CheckIllegal(url) && !strings.ContainsAny(url, `"'`)
}

// validCronjobContainerFields reports whether the docker-exec container name
// and the in-container shell command of a shell cronjob are safe to
// interpolate into `docker exec -i <container> <command>`, which the host
// shell runs via bash -c (cmd.ExecCronjobWithTimeOutStdin). The container
// name must match the docker name charset, a strict whitelist
// ([a-zA-Z0-9][a-zA-Z0-9_.-]*) that also excludes every shell metacharacter,
// so cmd.CheckIllegal is subsumed for it. The command is the path of the
// shell executable inside the container (e.g. "sh", "bash", "/bin/sh"): it
// must be free of shell metacharacters, whitespace (multi-word commands would
// smuggle extra docker exec arguments) and ".." components. Empty values are
// legal: an empty container name runs the script on the host shell and an
// empty command defaults to "sh".
func validCronjobContainerFields(containerName, command string) bool {
	if containerName != "" && !files.ValidContainerName(containerName) {
		return false
	}
	if command != "" && (cmd.CheckIllegal(command) || strings.ContainsAny(command, " \t") || strings.Contains(command, "..")) {
		return false
	}
	return true
}

// validateCronjobFields enforces the entry-point checks shared by Create and
// Update. Every value that later lands in a shell command or in a filesystem
// path derived from the cronjob name is validated here; handleTar and the
// handleShell/mkdirAndWriteFile paths re-check defensively at runtime.
func validateCronjobFields(cronjobType, name, sourceDir, exclusionRules, url, containerName, command string) error {
	if !validCronjobName(name) {
		return buserr.New(constant.ErrCmdIllegal)
	}
	switch cronjobType {
	case "shell":
		// ContainerName and Command are interpolated into
		// `docker exec -i <container> <command>` executed by the host shell;
		// reject anything that could break out of the word boundaries.
		if !validCronjobContainerFields(containerName, command) {
			return buserr.New(constant.ErrCmdIllegal)
		}
	case "directory":
		// An empty sourceDir is legal (the job body no-ops on it), so only
		// values that will actually reach a shell command are validated.
		if sourceDir != "" && !files.ValidShellArgs(sourceDir) {
			return buserr.New(constant.ErrCmdIllegal)
		}
		if !validCronjobExclusionRules(exclusionRules) {
			return buserr.New(constant.ErrCmdIllegal)
		}
	case "curl":
		if !validCronjobURL(url) {
			return buserr.New(constant.ErrCmdIllegal)
		}
	}
	return nil
}

func (u *CronjobService) Create(cronjobDto dto.CronjobCreate) error {
	if err := validateCronjobFields(cronjobDto.Type, cronjobDto.Name, cronjobDto.SourceDir, cronjobDto.ExclusionRules, cronjobDto.URL, cronjobDto.ContainerName, cronjobDto.Command); err != nil {
		return err
	}
	cronjob, _ := cronjobRepo.Get(commonRepo.WithByName(cronjobDto.Name))
	if cronjob.ID != 0 {
		return constant.ErrRecordExist
	}
	cronjob.Secret = cronjobDto.Secret
	if err := copier.Copy(&cronjob, &cronjobDto); err != nil {
		return errors.WithMessage(constant.ErrStructTransform, err.Error())
	}
	cronjob.Status = constant.StatusEnable

	global.LOG.Infof("create cronjob %s successful, spec: %s", cronjob.Name, cronjob.Spec)
	spec := cronjob.Spec
	entryIDs, err := u.StartJob(&cronjob, false)
	if err != nil {
		return err
	}
	cronjob.Spec = spec
	cronjob.EntryIDs = entryIDs
	if err := cronjobRepo.Create(&cronjob); err != nil {
		return err
	}
	return nil
}

func (u *CronjobService) StartJob(cronjob *model.Cronjob, isUpdate bool) (string, error) {
	if len(cronjob.EntryIDs) != 0 && isUpdate {
		ids := strings.Split(cronjob.EntryIDs, ",")
		for _, id := range ids {
			idItem, _ := strconv.Atoi(id)
			global.Cron.Remove(cron.EntryID(idItem))
		}
	}
	specs := strings.Split(cronjob.Spec, ",")
	var ids []string
	for _, spec := range specs {
		cronjob.Spec = spec
		entryID, err := u.AddCronJob(cronjob)
		if err != nil {
			return "", err
		}
		ids = append(ids, fmt.Sprintf("%v", entryID))
	}
	return strings.Join(ids, ","), nil
}

func (u *CronjobService) Delete(req dto.CronjobBatchDelete) error {
	for _, id := range req.IDs {
		cronjob, _ := cronjobRepo.Get(commonRepo.WithByID(id))
		if cronjob.ID == 0 {
			return errors.New("find cronjob in db failed")
		}
		ids := strings.Split(cronjob.EntryIDs, ",")
		for _, id := range ids {
			idItem, _ := strconv.Atoi(id)
			global.Cron.Remove(cron.EntryID(idItem))
		}
		global.LOG.Infof("stop cronjob entryID: %s", cronjob.EntryIDs)
		// Data removal (remote backups / expired logs) runs before the run
		// lock: it can be slow and must not stall the record insertion of
		// every other running job.
		if err := u.cleanRecordPreflight(dto.CronjobClean{CronjobID: id, CleanData: req.CleanData, CleanRemoteData: req.CleanRemoteData, IsDelete: true}); err != nil {
			return err
		}
		// Serialize the record cleanup against a job body that may be
		// starting right now (HandleJob inserts its record under this lock):
		// the deletion order below (records first, then the cronjob row)
		// guarantees that no record or log file of a deleted job can be
		// created afterwards — a body that already holds the lock inserts
		// its record before the wipe, and a body waiting for the lock
		// re-loads the row, finds it gone and skips itself.
		cronjobRunMu.Lock()
		if err := u.cleanRecordWipe(dto.CronjobClean{CronjobID: id, CleanData: req.CleanData, CleanRemoteData: req.CleanRemoteData, IsDelete: true}); err != nil {
			cronjobRunMu.Unlock()
			return err
		}
		if err := cronjobRepo.Delete(commonRepo.WithByID(id)); err != nil {
			cronjobRunMu.Unlock()
			return err
		}
		cronjobRunMu.Unlock()
	}

	return nil
}

func (u *CronjobService) Update(id uint, req dto.CronjobUpdate) error {
	if err := validateCronjobFields(req.Type, req.Name, req.SourceDir, req.ExclusionRules, req.URL, req.ContainerName, req.Command); err != nil {
		return err
	}
	var cronjob model.Cronjob
	if err := copier.Copy(&cronjob, &req); err != nil {
		return errors.WithMessage(constant.ErrStructTransform, err.Error())
	}
	cronModel, err := cronjobRepo.Get(commonRepo.WithByID(id))
	if err != nil {
		return constant.ErrRecordNotFound
	}
	// The persisted/executed job type is the one already stored in the DB
	// (cronjob.Type is overwritten with cronModel.Type below and req.Type is
	// discarded), so the values that will actually be executed by that type
	// must be validated against it, not against req.Type. Otherwise a request
	// declaring type=shell bypasses the URL check while req.URL is still
	// persisted and later interpolated into `curl '<url>'` by the curl branch
	// of the stored type=curl job (shell-quote escape, root RCE). If the
	// request carries a field that the stored type would execute but the
	// request type would not, the update is rejected.
	if err := validateCronjobFields(cronModel.Type, req.Name, req.SourceDir, req.ExclusionRules, req.URL, req.ContainerName, req.Command); err != nil {
		return err
	}
	if req.Type != cronModel.Type && req.URL != "" && !validCronjobURL(req.URL) {
		return buserr.New(constant.ErrCmdIllegal)
	}
	upMap := make(map[string]interface{})
	cronjob.EntryIDs = cronModel.EntryIDs
	cronjob.Type = cronModel.Type
	spec := cronjob.Spec
	if cronModel.Status == constant.StatusEnable {
		newEntryIDs, err := u.StartJob(&cronjob, true)
		if err != nil {
			return err
		}
		upMap["entry_ids"] = newEntryIDs
	} else {
		ids := strings.Split(cronjob.EntryIDs, ",")
		for _, id := range ids {
			idItem, _ := strconv.Atoi(id)
			global.Cron.Remove(cron.EntryID(idItem))
		}
	}

	upMap["name"] = req.Name
	upMap["spec"] = spec
	upMap["script"] = req.Script
	upMap["command"] = req.Command
	upMap["container_name"] = req.ContainerName
	upMap["app_id"] = req.AppID
	upMap["website"] = req.Website
	upMap["exclusion_rules"] = req.ExclusionRules
	upMap["db_type"] = req.DBType
	upMap["db_name"] = req.DBName
	upMap["url"] = req.URL
	upMap["source_dir"] = req.SourceDir

	upMap["backup_accounts"] = req.BackupAccounts
	upMap["default_download"] = req.DefaultDownload
	upMap["retain_copies"] = req.RetainCopies
	upMap["secret"] = req.Secret
	err = cronjobRepo.Update(id, upMap)
	if err != nil {
		return err
	}
	return nil
}

func (u *CronjobService) UpdateStatus(id uint, status string) error {
	cronjob, _ := cronjobRepo.Get(commonRepo.WithByID(id))
	if cronjob.ID == 0 {
		return errors.WithMessage(constant.ErrRecordNotFound, "record not found")
	}
	var (
		entryIDs string
		err      error
	)

	if status == constant.StatusEnable {
		entryIDs, err = u.StartJob(&cronjob, false)
		if err != nil {
			return err
		}
	} else {
		ids := strings.Split(cronjob.EntryIDs, ",")
		for _, id := range ids {
			idItem, _ := strconv.Atoi(id)
			global.Cron.Remove(cron.EntryID(idItem))
		}
		global.LOG.Infof("stop cronjob entryID: %s", cronjob.EntryIDs)
	}
	return cronjobRepo.Update(cronjob.ID, map[string]interface{}{"status": status, "entry_ids": entryIDs})
}

func (u *CronjobService) AddCronJob(cronjob *model.Cronjob) (int, error) {
	addFunc := func() {
		// Re-load the row when the scheduler fires: Delete may have removed
		// the cronjob and its records between the schedule tick and this
		// callback (the scheduler hands every registered entry a goroutine
		// the moment it fires). Running the stale row would recreate the
		// task directory and log files the delete just removed. The reload
		// also picks up the latest spec/script edits.
		latest, err := cronjobRepo.Get(commonRepo.WithByID(cronjob.ID))
		if err != nil {
			global.LOG.Infof("skip run of cronjob %s(%d): the job has been deleted", cronjob.Name, cronjob.ID)
			return
		}
		u.HandleJob(&latest)
	}
	global.LOG.Infof("add %s job %s successful", cronjob.Type, cronjob.Name)
	entryID, err := global.Cron.AddFunc(cronjob.Spec, addFunc)
	if err != nil {
		return 0, err
	}
	global.LOG.Infof("start cronjob entryID: %d", entryID)
	return int(entryID), nil
}

func mkdirAndWriteFile(cronjob *model.Cronjob, startTime time.Time, msg []byte) (string, error) {
	dir := fmt.Sprintf("%s/task/%s/%s", constant.DataDir, cronjob.Type, cronjob.Name)
	if _, err := os.Stat(dir); err != nil && os.IsNotExist(err) {
		// Task dirs hold job logs and script output; 0750 (owner rwx, group
		// rx) instead of os.ModePerm keeps other local users out.
		if err = os.MkdirAll(dir, 0750); err != nil {
			return "", err
		}
	}

	path := fmt.Sprintf("%s/%s.log", dir, startTime.Format(constant.DateTimeSlimLayout))
	global.LOG.Infof("cronjob %s has generated some logs %s", cronjob.Name, path)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0666)
	if err != nil {
		return "", err
	}
	defer file.Close()
	write := bufio.NewWriter(file)
	_, _ = write.WriteString(string(msg))
	write.Flush()
	return path, nil
}
