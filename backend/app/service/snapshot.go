package service

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/1Panel-dev/1Panel/backend/app/dto"
	"github.com/1Panel-dev/1Panel/backend/app/model"
	"github.com/1Panel-dev/1Panel/backend/constant"
	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/1Panel-dev/1Panel/backend/utils/common"
	"github.com/1Panel-dev/1Panel/backend/utils/compose"
	"github.com/1Panel-dev/1Panel/backend/utils/files"
	"github.com/jinzhu/copier"
	"github.com/pkg/errors"
	"github.com/shirou/gopsutil/v3/host"
	"gorm.io/gorm"
)

type SnapshotService struct {
	OriginalPath string
}

type ISnapshotService interface {
	SearchWithPage(req dto.PageSnapshot) (int64, interface{}, error)
	LoadSize(req dto.PageSnapshot) ([]dto.SnapshotFile, error)
	SnapshotCreate(req dto.SnapshotCreate) error
	SnapshotRecover(req dto.SnapshotRecover) error
	SnapshotRollback(req dto.SnapshotRecover) error
	SnapshotImport(req dto.SnapshotImport) error
	Delete(req dto.SnapshotBatchDelete) error

	LoadSnapShotStatus(id uint) (*dto.SnapshotStatus, error)

	UpdateDescription(req dto.UpdateDescription) error
	readFromJson(path string) (SnapshotJson, error)

	HandleSnapshot(isCronjob bool, logPath string, req dto.SnapshotCreate, timeNow string, secret string) (string, error)
}

func NewISnapshotService() ISnapshotService {
	return &SnapshotService{}
}

func (u *SnapshotService) SearchWithPage(req dto.PageSnapshot) (int64, interface{}, error) {
	total, records, err := snapshotRepo.Page(req.Page, req.PageSize, commonRepo.WithLikeName(req.Info), commonRepo.WithOrderRuleBy(req.OrderBy, req.Order))
	if err != nil {
		return 0, nil, err
	}
	var data []dto.SnapshotInfo
	for _, record := range records {
		var item dto.SnapshotInfo
		if err := copier.Copy(&item, &record); err != nil {
			return 0, nil, errors.WithMessage(constant.ErrStructTransform, err.Error())
		}
		data = append(data, item)
	}
	return total, data, err
}

func (u *SnapshotService) LoadSize(req dto.PageSnapshot) ([]dto.SnapshotFile, error) {
	_, records, err := snapshotRepo.Page(req.Page, req.PageSize, commonRepo.WithLikeName(req.Info), commonRepo.WithOrderRuleBy(req.OrderBy, req.Order))
	if err != nil {
		return nil, err
	}
	data, err := loadSnapSize(records)
	if err != nil {
		return nil, err
	}
	return data, err
}

func (u *SnapshotService) SnapshotImport(req dto.SnapshotImport) error {
	if len(req.Names) == 0 {
		return fmt.Errorf("incorrect snapshot request body: %v", req.Names)
	}
	for _, snapName := range req.Names {
		snap, _ := snapshotRepo.Get(commonRepo.WithByName(strings.ReplaceAll(snapName, ".tar.gz", "")))
		if snap.ID != 0 {
			return constant.ErrRecordExist
		}
	}
	for _, snap := range req.Names {
		// The name is persisted in the snapshot table and later reused to
		// locate and restore packages, so pin it to a safe charset on top of
		// the structural checks below (defense in depth; the shell-facing
		// arguments are validated downstream as well).
		if !validSnapshotImportName(snap) {
			return fmt.Errorf("incorrect snapshot name format of %s", snap)
		}
		shortName := strings.TrimPrefix(snap, "snapshot_")
		nameItems := strings.Split(shortName, "_")
		if !strings.HasPrefix(shortName, "1panel_v") || !strings.HasSuffix(shortName, ".tar.gz") || len(nameItems) < 3 {
			return fmt.Errorf("incorrect snapshot name format of %s", shortName)
		}
		if req.From == constant.Local {
			// The import flow trusts names coming from the configured LOCAL
			// backup directory: an attacker who can write there (or who tricks
			// an admin into importing a crafted package) could otherwise feed
			// the recovery flow a snapshot.json whose restore targets
			// overwrite arbitrary host paths. The package must be a valid
			// gzip/tar archive with a parseable snapshot.json whose path
			// fields stay inside the panel data/backup/tmp directories before
			// the record is accepted.
			localDir, err := loadLocalDir()
			if err != nil {
				return fmt.Errorf("load local backup dir for snapshot import failed, err: %v", err)
			}
			packageFile := path.Join(localDir, "system_snapshot", strings.ReplaceAll(snap, ".tar.gz", "")+".tar.gz")
			if err := validateSnapshotPackage(packageFile); err != nil {
				return fmt.Errorf("validate imported snapshot package %s failed: %v", snap, err)
			}
		}
		if strings.HasSuffix(snap, ".tar.gz") {
			snap = strings.ReplaceAll(snap, ".tar.gz", "")
		}
		itemSnap := model.Snapshot{
			Name:            snap,
			From:            req.From,
			DefaultDownload: req.From,
			Version:         nameItems[1],
			Description:     req.Description,
			Status:          constant.StatusSuccess,
		}
		if err := snapshotRepo.Create(&itemSnap); err != nil {
			return err
		}
	}
	return nil
}

func (u *SnapshotService) UpdateDescription(req dto.UpdateDescription) error {
	return snapshotRepo.Update(req.ID, map[string]interface{}{"description": req.Description})
}

func (u *SnapshotService) LoadSnapShotStatus(id uint) (*dto.SnapshotStatus, error) {
	var data dto.SnapshotStatus
	status, err := snapshotRepo.GetStatus(id)
	if err != nil {
		return nil, err
	}
	if err := copier.Copy(&data, &status); err != nil {
		return nil, errors.WithMessage(constant.ErrStructTransform, err.Error())
	}
	return &data, nil
}

type SnapshotJson struct {
	OldBaseDir       string `json:"oldBaseDir"`
	OldDockerDataDir string `json:"oldDockerDataDir"`
	OldBackupDataDir string `json:"oldBackupDataDir"`
	OldPanelDataDir  string `json:"oldPanelDataDir"`

	BaseDir            string `json:"baseDir"`
	DockerDataDir      string `json:"dockerDataDir"`
	BackupDataDir      string `json:"backupDataDir"`
	PanelDataDir       string `json:"panelDataDir"`
	LiveRestoreEnabled bool   `json:"liveRestoreEnabled"`
}

// validSnapshotImportName reports whether the raw snapshot import name stays
// within the safe charset [A-Za-z0-9._-] (covering the "snapshot_" prefix and
// the ".tar.gz" suffix handled by the caller). Metacharacters such as ';',
// spaces or quotes must never reach the snapshot table even though the
// shell-facing arguments are validated downstream (defense in depth).
func validSnapshotImportName(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.' || r == '_' || r == '-':
		default:
			return false
		}
	}
	return true
}

// PathInsideDir is the exported form of pathInsideDir for callers outside
// the service package that must enforce the same containment rule, e.g. the
// upload-recover target check in api/v1.
func PathInsideDir(pathItem, dir string, allowEqual bool) bool {
	return pathInsideDir(pathItem, dir, allowEqual)
}

// pathInsideDir reports whether pathItem, after cleaning, is an absolute path
// strictly inside dir (or equal to dir for allowEqual). ".." components and
// path separators are rejected by filepath.Clean + filepath.Rel, so a value
// like "../../etc" or "etc" can never fold onto a location outside dir.
func pathInsideDir(pathItem, dir string, allowEqual bool) bool {
	if pathItem == "" || dir == "" {
		return false
	}
	cleanItem := filepath.Clean(filepath.FromSlash(pathItem))
	if !filepath.IsAbs(cleanItem) {
		return false
	}
	cleanDir := filepath.Clean(filepath.FromSlash(dir))
	if !filepath.IsAbs(cleanDir) {
		return false
	}
	rel, err := filepath.Rel(cleanDir, cleanItem)
	if err != nil {
		return false
	}
	if rel == "." {
		return allowEqual
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return false
	}
	return true
}

// pathHasTraversalComponent rejects paths whose raw form contains ".."
// components (pathInsideDir already folds those away via Clean, but a raw ".."
// anywhere in the string is always rejected explicitly so no value can resolve
// ambiguously on case-insensitive or junction-heavy filesystems).
func pathHasTraversalComponent(pathItem string) bool {
	for _, comp := range strings.Split(filepath.FromSlash(pathItem), string(filepath.Separator)) {
		if comp == ".." {
			return true
		}
	}
	return false
}

// validateSnapshotJsonPaths enforces the restore-target whitelist of a
// snapshot's snapshot.json before ANY untar runs. Recovery uses these fields
// verbatim as extraction destinations (1panel_backup.tar.gz ->
// BackupDataDir, 1panel_data.tar.gz -> BaseDir/1panel), so a hostile or
// tampered snapshot package could otherwise overwrite arbitrary host paths
// (e.g. "/etc" or "/usr/local/bin"), including the panel database with its
// stored credentials. Every restore target must be an absolute path with no
// ".." component that lies inside the panel data directory (DataDir), the
// configured local backup directory (global.CONF.System.Backup, which is
// DataDir/backup by default but configurable), or the panel tmp directory
// (DataDir/tmp by default). These are the only locations a restore is allowed
// to write to.
func validateSnapshotJsonPaths(jsonItem SnapshotJson) error {
	allowedDirs := []string{global.CONF.System.DataDir, global.CONF.System.Backup, global.CONF.System.TmpDir}
	check := func(field, pathItem string) error {
		if pathHasTraversalComponent(pathItem) {
			return fmt.Errorf("invalid snapshot path: field %s of snapshot.json must not contain '..' components, got %q", field, pathItem)
		}
		for _, dir := range allowedDirs {
			if pathInsideDir(pathItem, dir, true) {
				return nil
			}
		}
		return fmt.Errorf("invalid snapshot path: field %s of snapshot.json (%q) must be an absolute path inside one of %s", field, pathItem, strings.Join(allowedDirs, ", "))
	}
	if err := check("baseDir", jsonItem.BaseDir); err != nil {
		return err
	}
	if err := check("backupDataDir", jsonItem.BackupDataDir); err != nil {
		return err
	}
	if err := check("panelDataDir", jsonItem.PanelDataDir); err != nil {
		return err
	}
	return nil
}

// validateSnapshotPackage checks that a snapshot tarball is a valid gzip/tar
// archive containing a parseable snapshot.json whose restore-target paths pass
// validateSnapshotJsonPaths. It is the integrity gate for every imported
// snapshot package (SnapshotImport for local files, HandleSnapshotRecover for
// files downloaded from cloud storage) before any extraction or recovery step
// runs.
func validateSnapshotPackage(packageFile string) error {
	f, err := os.Open(packageFile)
	if err != nil {
		return fmt.Errorf("open snapshot package failed, err: %v", err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("snapshot package is not a valid gzip archive: %v", err)
	}
	defer zr.Close()
	tr := tar.NewReader(zr)
	var jsonFound bool
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("snapshot package is not a valid tar archive: %v", err)
		}
		if hdr.Typeflag == tar.TypeDir || strings.HasSuffix(hdr.Name, "/") {
			continue
		}
		base := filepath.Base(hdr.Name)
		if base == "snapshot.json" {
			jsonFound = true
			if hdr.Size > 4*1024*1024 {
				return fmt.Errorf("snapshot package snapshot.json is too large (%d bytes)", hdr.Size)
			}
			jsonBytes, err := io.ReadAll(io.LimitReader(tr, 4*1024*1024+1))
			if err != nil {
				return fmt.Errorf("read snapshot.json from snapshot package failed, err: %v", err)
			}
			var jsonItem SnapshotJson
			if err := json.Unmarshal(jsonBytes, &jsonItem); err != nil {
				return fmt.Errorf("parse snapshot.json from snapshot package failed, err: %v", err)
			}
			if err := validateSnapshotJsonPaths(jsonItem); err != nil {
				return err
			}
			break
		}
	}
	if !jsonFound {
		return fmt.Errorf("snapshot.json is missing from snapshot package %s", path.Base(packageFile))
	}
	return nil
}

func (u *SnapshotService) SnapshotCreate(req dto.SnapshotCreate) error {
	if _, err := u.HandleSnapshot(false, "", req, time.Now().Format(constant.DateTimeSlimLayout), req.Secret); err != nil {
		return err
	}
	return nil
}

func (u *SnapshotService) SnapshotRecover(req dto.SnapshotRecover) error {
	global.LOG.Info("start to recover panel by snapshot now")
	snap, err := snapshotRepo.Get(commonRepo.WithByID(req.ID))
	if err != nil {
		return err
	}
	if hasOs(snap.Name) && !strings.Contains(snap.Name, loadOs()) {
		return fmt.Errorf("restoring snapshots(%s) between different server architectures(%s) is not supported", snap.Name, loadOs())
	}
	if !req.IsNew && len(snap.InterruptStep) != 0 && len(snap.RollbackStatus) != 0 {
		return fmt.Errorf("the snapshot has been rolled back and cannot be restored again")
	}

	baseDir := path.Join(global.CONF.System.TmpDir, fmt.Sprintf("system/%s", snap.Name))
	if _, err := os.Stat(baseDir); err != nil && os.IsNotExist(err) {
		_ = os.MkdirAll(baseDir, os.ModePerm)
	}

	if err := snapshotRepo.Update(snap.ID, map[string]interface{}{"recover_status": constant.StatusWaiting}); err != nil {
		global.LOG.Errorf("update snapshot recover status to waiting failed, err: %v", err)
	}
	if err := settingRepo.Update("SystemStatus", "Recovering"); err != nil {
		global.LOG.Errorf("update system status to Recovering failed, err: %v", err)
	}
	go u.HandleSnapshotRecover(snap, true, req)
	return nil
}

func (u *SnapshotService) SnapshotRollback(req dto.SnapshotRecover) error {
	global.LOG.Info("start to rollback now")
	snap, err := snapshotRepo.Get(commonRepo.WithByID(req.ID))
	if err != nil {
		return err
	}
	req.IsNew = false
	snap.InterruptStep = "Readjson"
	go u.HandleSnapshotRecover(snap, false, req)
	return nil
}

func (u *SnapshotService) readFromJson(path string) (SnapshotJson, error) {
	var snap SnapshotJson
	if _, err := os.Stat(path); err != nil {
		return snap, fmt.Errorf("find snapshot json file in recover package failed, err: %v", err)
	}
	fileByte, err := os.ReadFile(path)
	if err != nil {
		return snap, fmt.Errorf("read file from path %s failed, err: %v", path, err)
	}
	if err := json.Unmarshal(fileByte, &snap); err != nil {
		return snap, fmt.Errorf("unmarshal snapjson failed, err: %v", err)
	}
	return snap, nil
}

// snapshotNameMu serializes snapshot name allocation. Naming is check-then-act
// by nature: the same-second duplicate detection is a DB read and the snapshot
// row is only persisted afterwards, so two concurrent creations in the same
// second could both observe the name as free. The timestamp has second-level
// precision (and the cronjob path's random suffix is only appended by the
// caller, not guaranteed unique either), so without mutual exclusion the rows
// would collide — at best the second insert fails on the unique name
// constraint, at worst both rows exist and the tarballs overwrite each other.
// Both creation paths (manual SnapshotCreate and cronjob) funnel through
// HandleSnapshot, so wrapping the dedup read and the row insert in one
// critical section here covers them all.
var snapshotNameMu sync.Mutex

// buildSnapshotName builds a snapshot name from the version, os and timestamp
// and appends a random suffix when a snapshot with that name already exists.
// It must run under snapshotNameMu together with the snapshot row insert (see
// allocateSnapshot): on its own the duplicate check is still check-then-act.
func buildSnapshotName(version, os, timeNow string, isCronjob bool) string {
	name := fmt.Sprintf("1panel_%s_%s_%s", version, os, timeNow)
	if isCronjob {
		name = fmt.Sprintf("snapshot_1panel_%s_%s_%s", version, os, timeNow)
	}
	existing, err := snapshotRepo.Get(commonRepo.WithByName(name))
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		// Keep the previous "treat unreadable DB as no duplicate" behaviour,
		// but log it: the insert below is what will surface the real problem
		// (e.g. via the unique name constraint).
		global.LOG.Errorf("check existing snapshot name %s failed, err: %v", name, err)
	}
	if existing.ID == 0 {
		return name
	}
	return fmt.Sprintf("%s-%s", name, common.RandStrAndNum(4))
}

// allocateSnapshot picks a unique name for snap and persists the snapshot row
// inside one snapshotNameMu critical section, so the duplicate-name check and
// the row insert cannot interleave with a concurrent creation (see
// snapshotNameMu for why both must be atomic together).
func allocateSnapshot(version, os, timeNow string, isCronjob bool, snap *model.Snapshot) error {
	snapshotNameMu.Lock()
	defer snapshotNameMu.Unlock()
	snap.Name = buildSnapshotName(version, os, timeNow, isCronjob)
	if err := snapshotRepo.Create(snap); err != nil {
		return fmt.Errorf("create snapshot record failed, err: %v", err)
	}
	return nil
}

func (u *SnapshotService) HandleSnapshot(isCronjob bool, logPath string, req dto.SnapshotCreate, timeNow string, secret string) (string, error) {
	localDir, err := loadLocalDir()
	if err != nil {
		return "", err
	}
	var (
		rootDir    string
		snap       model.Snapshot
		snapStatus model.SnapshotStatus
	)

	if req.ID == 0 {
		versionItem, _ := settingRepo.Get(settingRepo.WithByKey("SystemVersion"))

		snap = model.Snapshot{
			Description:     req.Description,
			From:            req.From,
			DefaultDownload: req.DefaultDownload,
			Version:         versionItem.Value,
			Status:          constant.StatusWaiting,
		}
		if err := allocateSnapshot(versionItem.Value, loadOs(), timeNow, isCronjob, &snap); err != nil {
			return "", err
		}
		snapStatus.SnapID = snap.ID
		if err := snapshotRepo.CreateStatus(&snapStatus); err != nil {
			global.LOG.Errorf("create snapshot status failed, err: %v", err)
			return "", fmt.Errorf("create snapshot status failed, err: %v", err)
		}
	} else {
		snap, err = snapshotRepo.Get(commonRepo.WithByID(req.ID))
		if err != nil {
			return "", err
		}
		if err := snapshotRepo.Update(snap.ID, map[string]interface{}{"status": constant.StatusWaiting}); err != nil {
			global.LOG.Errorf("update snapshot status to waiting failed, err: %v", err)
		}
		snapStatus, err = snapshotRepo.GetStatus(snap.ID)
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			// A missing status row (record not found) is expected on a retry
			// and handled by the CreateStatus below; any other read failure
			// must not pass silently, it would create a duplicate status row.
			global.LOG.Errorf("query status of snapshot %d failed, err: %v", snap.ID, err)
		}
		if snapStatus.ID == 0 {
			snapStatus.SnapID = snap.ID
			if err := snapshotRepo.CreateStatus(&snapStatus); err != nil {
				global.LOG.Errorf("create snapshot status failed, err: %v", err)
				return "", fmt.Errorf("create snapshot status failed, err: %v", err)
			}
		}
	}
	rootDir = path.Join(localDir, "system", snap.Name)

	var wg sync.WaitGroup
	itemHelper := snapHelper{SnapID: snap.ID, Status: &snapStatus, Wg: &wg, FileOp: files.NewFileOp(), Ctx: context.Background()}
	backupPanelDir := path.Join(rootDir, "1panel")
	_ = os.MkdirAll(backupPanelDir, os.ModePerm)
	backupDockerDir := path.Join(rootDir, "docker")
	_ = os.MkdirAll(backupDockerDir, os.ModePerm)

	jsonItem := SnapshotJson{
		BaseDir:       global.CONF.System.BaseDir,
		BackupDataDir: localDir,
		PanelDataDir:  path.Join(global.CONF.System.BaseDir, "1panel"),
	}
	loadSnapLog(snap.ID, logPath)
	if snapStatus.PanelInfo != constant.StatusDone {
		wg.Add(1)
		go snapJson(itemHelper, jsonItem, rootDir)
	}
	if snapStatus.Panel != constant.StatusDone {
		wg.Add(1)
		go snapPanel(itemHelper, backupPanelDir)
	}
	if snapStatus.DaemonJson != constant.StatusDone {
		wg.Add(1)
		go snapDaemonJson(itemHelper, backupDockerDir)
	}
	if snapStatus.AppData != constant.StatusDone {
		wg.Add(1)
		go snapAppData(itemHelper, backupDockerDir)
	}
	if snapStatus.BackupData != constant.StatusDone {
		wg.Add(1)
		go snapBackup(itemHelper, localDir, backupPanelDir)
	}

	if !isCronjob {
		go func() {
			wg.Wait()
			allDone, err := checkIsAllDone(snap.ID)
			if err != nil {
				// A status read that still fails after retries must not be
				// read as "not done": the zero value would look unfinished
				// and either re-run a healthy phase or fail the snapshot
				// without a reason.
				markSnapshotFailed(snap.ID, fmt.Sprintf("status query failed: %v", err))
				return
			}
			if !allDone {
				if err := snapshotRepo.Update(snap.ID, map[string]interface{}{"status": constant.StatusFailed}); err != nil {
					global.LOG.Errorf("update snapshot status to failed failed, err: %v", err)
				}
				return
			}
			statusItem, err := loadSnapStatus(snap.ID, "panel_data")
			if err != nil {
				markSnapshotFailed(snap.ID, fmt.Sprintf("status query failed: %v", err))
				return
			}
			if statusItem.PanelData != constant.StatusDone {
				snapPanelData(itemHelper, localDir, backupPanelDir)
			}
			statusItem, err = loadSnapStatus(snap.ID, "panel_data")
			if err != nil {
				markSnapshotFailed(snap.ID, fmt.Sprintf("status query failed: %v", err))
				return
			}
			if statusItem.PanelData != constant.StatusDone {
				markSnapshotFailed(snap.ID, fmt.Sprintf("panel data phase failed: %s", statusItem.PanelData))
				return
			}
			if statusItem.Compress != constant.StatusDone {
				snapCompress(itemHelper, rootDir, secret)
			}
			statusItem, err = loadSnapStatus(snap.ID, "compress")
			if err != nil {
				markSnapshotFailed(snap.ID, fmt.Sprintf("status query failed: %v", err))
				return
			}
			if statusItem.Compress != constant.StatusDone {
				markSnapshotFailed(snap.ID, fmt.Sprintf("compress phase failed: %s", statusItem.Compress))
				return
			}
			if statusItem.Upload != constant.StatusDone {
				snapUpload(itemHelper, req.From, fmt.Sprintf("%s.tar.gz", rootDir))
			}
			statusItem, err = loadSnapStatus(snap.ID, "upload")
			if err != nil {
				markSnapshotFailed(snap.ID, fmt.Sprintf("status query failed: %v", err))
				return
			}
			if statusItem.Upload != constant.StatusDone {
				markSnapshotFailed(snap.ID, fmt.Sprintf("upload phase failed: %s", statusItem.Upload))
				return
			}
			if err := snapshotRepo.Update(snap.ID, map[string]interface{}{"status": constant.StatusSuccess}); err != nil {
				global.LOG.Errorf("update snapshot status to success failed, err: %v", err)
			}
		}()
		return "", nil
	}
	wg.Wait()
	allDone, err := checkIsAllDone(snap.ID)
	if err != nil {
		markSnapshotFailed(snap.ID, fmt.Sprintf("status query failed: %v", err))
		loadSnapLog(snap.ID, logPath)
		return snap.Name, fmt.Errorf("query status of snapshot %s failed, err: %v", snap.Name, err)
	}
	if !allDone {
		if err := snapshotRepo.Update(snap.ID, map[string]interface{}{"status": constant.StatusFailed}); err != nil {
			global.LOG.Errorf("update snapshot status to failed failed, err: %v", err)
		}
		loadSnapLog(snap.ID, logPath)
		return snap.Name, fmt.Errorf("snapshot %s backup failed", snap.Name)
	}
	loadSnapLog(snap.ID, logPath)
	snapPanelData(itemHelper, localDir, backupPanelDir)
	statusItem, err := loadSnapStatus(snap.ID, "panel_data")
	if err != nil {
		markSnapshotFailed(snap.ID, fmt.Sprintf("status query failed: %v", err))
		loadSnapLog(snap.ID, logPath)
		return snap.Name, fmt.Errorf("query status of snapshot %s failed, err: %v", snap.Name, err)
	}
	if statusItem.PanelData != constant.StatusDone {
		markSnapshotFailed(snap.ID, fmt.Sprintf("panel data phase failed: %s", statusItem.PanelData))
		loadSnapLog(snap.ID, logPath)
		return snap.Name, fmt.Errorf("snapshot %s 1panel data failed", snap.Name)
	}
	loadSnapLog(snap.ID, logPath)
	snapCompress(itemHelper, rootDir, secret)
	statusItem, err = loadSnapStatus(snap.ID, "compress")
	if err != nil {
		markSnapshotFailed(snap.ID, fmt.Sprintf("status query failed: %v", err))
		loadSnapLog(snap.ID, logPath)
		return snap.Name, fmt.Errorf("query status of snapshot %s failed, err: %v", snap.Name, err)
	}
	if statusItem.Compress != constant.StatusDone {
		markSnapshotFailed(snap.ID, fmt.Sprintf("compress phase failed: %s", statusItem.Compress))
		loadSnapLog(snap.ID, logPath)
		return snap.Name, fmt.Errorf("snapshot %s compress failed", snap.Name)
	}
	loadSnapLog(snap.ID, logPath)
	snapUpload(itemHelper, req.From, fmt.Sprintf("%s.tar.gz", rootDir))
	statusItem, err = loadSnapStatus(snap.ID, "upload")
	if err != nil {
		markSnapshotFailed(snap.ID, fmt.Sprintf("status query failed: %v", err))
		loadSnapLog(snap.ID, logPath)
		return snap.Name, fmt.Errorf("query status of snapshot %s failed, err: %v", snap.Name, err)
	}
	if statusItem.Upload != constant.StatusDone {
		markSnapshotFailed(snap.ID, fmt.Sprintf("upload phase failed: %s", statusItem.Upload))
		loadSnapLog(snap.ID, logPath)
		return snap.Name, fmt.Errorf("snapshot %s upload failed", snap.Name)
	}
	if err := snapshotRepo.Update(snap.ID, map[string]interface{}{"status": constant.StatusSuccess}); err != nil {
		global.LOG.Errorf("update snapshot status to success failed, err: %v", err)
	}
	loadSnapLog(snap.ID, logPath)
	return snap.Name, nil
}

func (u *SnapshotService) Delete(req dto.SnapshotBatchDelete) error {
	snaps, _ := snapshotRepo.GetList(commonRepo.WithIdsIn(req.Ids))
	localDir, err := loadLocalDir()
	if err != nil {
		global.LOG.Errorf("load local backup dir for snapshot cleanup failed, err: %v", err)
	}
	for _, snap := range snaps {
		if req.DeleteWithFile {
			targetAccounts, err := loadClientMap(snap.From)
			if err != nil {
				return err
			}
			for _, item := range targetAccounts {
				global.LOG.Debugf("remove snapshot file %s.tar.gz from %s", snap.Name, item.backType)
				_, _ = item.client.Delete(path.Join(item.backupPath, "system_snapshot", snap.Name+".tar.gz"))
			}
		}

		removeSnapshotLocalFiles(snap, localDir)

		_ = snapshotRepo.DeleteStatus(snap.ID)
		if err := snapshotRepo.Delete(commonRepo.WithByID(snap.ID)); err != nil {
			return err
		}
	}
	return nil
}

// removeSnapshotLocalFiles deletes the local artifacts a snapshot leaves
// behind in the panel directories: the creation working directory
// <localDir>/system/<name> (created by HandleSnapshot) and the compressed
// tarball <TmpDir>/system/<name>.tar.gz (produced by snapCompress), as well as
// the recover scratch directory <TmpDir>/system/<name> (created by
// HandleSnapshotRecover, which downloads and decompresses into it and removes
// it only on success). Failed operations never reach the step that normally
// removes these (snapCompress removes rootDir only after a successful tar,
// snapUpload removes the tarball only after a successful upload, and
// HandleSnapshotRecover removes the scratch dir only at the end), so they would
// otherwise pile up on disk. Cleanup is best-effort: failures are logged and
// never returned, and the record deletion in Delete stays the primary
// operation. The name is validated before any path is built so a malformed
// database value can never escape the snapshot directories.
func removeSnapshotLocalFiles(snap model.Snapshot, localDir string) {
	if snap.Name == "" || strings.ContainsAny(snap.Name, "/\\") {
		global.LOG.Errorf("skip local cleanup of snapshot %d: invalid name %q", snap.ID, snap.Name)
		return
	}
	if localDir != "" {
		rootDir := path.Join(localDir, "system", snap.Name)
		if _, err := os.Stat(rootDir); err == nil {
			if err := os.RemoveAll(rootDir); err != nil {
				global.LOG.Errorf("remove snapshot work dir %s failed, err: %v", rootDir, err)
			}
		}
	}
	tmpSystemDir := path.Join(global.CONF.System.TmpDir, "system")
	if tmpSystemDir != "" {
		source := path.Join(tmpSystemDir, fmt.Sprintf("%s.tar.gz", snap.Name))
		if err := os.Remove(source); err != nil && !os.IsNotExist(err) {
			global.LOG.Errorf("remove snapshot tar file %s failed, err: %v", source, err)
		}
		// A recover downloads and decompresses into the directory
		// <TmpDir>/system/<name>, which is the same name as the creation
		// tarball minus the .tar.gz suffix. HandleSnapshotRecover only removes
		// it on success, so a failed restore (e.g. an aborted download or
		// decompress) leaves it behind too. It coexists with the tarball above
		// (a directory and a file with neighbouring names), so both are
		// handled here.
		recoverDir := path.Join(tmpSystemDir, snap.Name)
		if _, err := os.Stat(recoverDir); err == nil {
			if err := os.RemoveAll(recoverDir); err != nil {
				global.LOG.Errorf("remove snapshot recover scratch dir %s failed, err: %v", recoverDir, err)
			}
		}
	}
}

func updateRecoverStatus(id uint, isRecover bool, interruptStep, status, message string) {
	if isRecover {
		if status != constant.StatusSuccess {
			global.LOG.Errorf("recover failed, err: %s", message)
		}
		if err := snapshotRepo.Update(id, map[string]interface{}{
			"interrupt_step":    interruptStep,
			"recover_status":    status,
			"recover_message":   message,
			"last_recovered_at": time.Now().Format(constant.DateTimeLayout),
		}); err != nil {
			global.LOG.Errorf("update snap recover status failed, err: %v", err)
		}
		if err := settingRepo.Update("SystemStatus", "Free"); err != nil {
			global.LOG.Errorf("update system status to Free after recover failed, err: %v", err)
		}
		return
	}
	if err := settingRepo.Update("SystemStatus", "Free"); err != nil {
		global.LOG.Errorf("update system status to Free after rollback failed, err: %v", err)
	}
	if status == constant.StatusSuccess {
		if err := snapshotRepo.Update(id, map[string]interface{}{
			"recover_status":     "",
			"recover_message":    "",
			"interrupt_step":     "",
			"rollback_status":    "",
			"rollback_message":   "",
			"last_rollbacked_at": time.Now().Format(constant.DateTimeLayout),
		}); err != nil {
			global.LOG.Errorf("update snap recover status failed, err: %v", err)
		}
		return
	}
	global.LOG.Errorf("rollback failed, err: %s", message)
	if err := snapshotRepo.Update(id, map[string]interface{}{
		"rollback_status":    status,
		"rollback_message":   message,
		"last_rollbacked_at": time.Now().Format(constant.DateTimeLayout),
	}); err != nil {
		global.LOG.Errorf("update snap recover status failed, err: %v", err)
	}
}

func (u *SnapshotService) handleUnTar(sourceDir, targetDir string, secret string) error {
	return handleSafeUnTar(sourceDir, targetDir, secret)
}

func rebuildAllAppInstall() error {
	global.LOG.Debug("start to rebuild all app")
	appInstalls, err := appInstallRepo.ListBy()
	if err != nil {
		global.LOG.Errorf("get all app installed for rebuild failed, err: %v", err)
		return err
	}
	var wg sync.WaitGroup
	for i := 0; i < len(appInstalls); i++ {
		wg.Add(1)
		appInstalls[i].Status = constant.Rebuilding
		if err := appInstallRepo.Save(context.Background(), &appInstalls[i]); err != nil {
			global.LOG.Errorf("update app [%s] status to rebuilding failed, err: %v", appInstalls[i].Name, err)
		}
		go func(app model.AppInstall) {
			defer wg.Done()
			dockerComposePath := app.GetComposePath()
			if out, err := compose.Up(dockerComposePath); err != nil {
				if out != "" {
					err = errors.New(out)
				}
				global.LOG.Errorf("compose up app [%s] after rebuild failed, err: %v", app.Name, err)
				return
			}
			app.Status = constant.Running
			if err := appInstallRepo.Save(context.Background(), &app); err != nil {
				global.LOG.Errorf("update app [%s] status to running failed, err: %v", app.Name, err)
			}
		}(appInstalls[i])
	}
	wg.Wait()
	return nil
}

// snapshotStatusRetries bounds the short retry loop of loadSnapStatus: the
// phase sequencing below reads the status row from the database, and a
// transient query error (e.g. sqlite busy) must not be mistaken for a phase
// that never ran.
const snapshotStatusRetries = 3

// snapshotStatusRetryInterval is the wait between loadSnapStatus attempts. Var
// instead of const so tests can shrink the backoff.
var snapshotStatusRetryInterval = time.Second

// snapshotGetStatusFn indirections snapshotRepo.GetStatus so tests can inject
// transient query failures (same pattern as restartDockerFn in image_repo.go).
var snapshotGetStatusFn = func(snapID uint) (model.SnapshotStatus, error) {
	return snapshotRepo.GetStatus(snapID)
}

// loadSnapStatus reads the status row of snapID, retrying briefly and logging
// every failed attempt. Callers branch on the returned status to decide
// whether a snapshot phase must (re-)run or the snapshot failed; a swallowed
// query error would return a zero-value status where every field looks
// "not done", re-running a finished phase or marking a healthy snapshot
// failed. When all attempts fail, the error is returned so the caller can
// fail the snapshot with an explicit "status query failed" reason instead of
// mis-reading the zero value as a phase outcome.
func loadSnapStatus(snapID uint, phase string) (model.SnapshotStatus, error) {
	for attempt := 1; attempt <= snapshotStatusRetries; attempt++ {
		status, err := snapshotGetStatusFn(snapID)
		if err == nil {
			return status, nil
		}
		global.LOG.Errorf("query status of snapshot %d (phase %s) failed, attempt %d/%d, err: %v", snapID, phase, attempt, snapshotStatusRetries, err)
		if attempt < snapshotStatusRetries {
			timer := time.NewTimer(snapshotStatusRetryInterval)
			<-timer.C
		}
	}
	return model.SnapshotStatus{}, errors.New("status query kept failing after retries")
}

// markSnapshotFailed records the terminal StatusFailed of a snapshot run
// together with a human readable reason. The message matters: a bare
// StatusFailed row gives the user nothing to act on. message is capped at the
// model column width (256).
func markSnapshotFailed(snapID uint, message string) {
	if runes := []rune(message); len(runes) > 256 {
		message = string(runes[:256])
	}
	if err := snapshotRepo.Update(snapID, map[string]interface{}{"status": constant.StatusFailed, "message": message}); err != nil {
		global.LOG.Errorf("update snapshot status to failed failed, err: %v", err)
	}
}

// checkIsAllDone reports whether every backup phase of snapID recorded
// StatusDone. The status read retries briefly and its error is propagated:
// the caller must neither treat a failed read as "not done" (the zero value
// would mark a healthy snapshot failed) nor silently as "done".
func checkIsAllDone(snapID uint) (bool, error) {
	status, err := loadSnapStatus(snapID, "final check")
	if err != nil {
		return false, err
	}
	isOK, _ := checkAllDone(status)
	return isOK, nil
}

func checkAllDone(status model.SnapshotStatus) (bool, string) {
	if status.Panel != constant.StatusDone {
		return false, status.Panel
	}
	if status.PanelInfo != constant.StatusDone {
		return false, status.PanelInfo
	}
	if status.DaemonJson != constant.StatusDone {
		return false, status.DaemonJson
	}
	if status.AppData != constant.StatusDone {
		return false, status.AppData
	}
	if status.BackupData != constant.StatusDone {
		return false, status.BackupData
	}
	return true, ""
}

// loadSnapLog reads the latest snapshot status from the database and writes a
// human readable progress log. Reading from the database keeps the log in sync
// with the per-worker DB status updates instead of a shared in-memory status.
func loadSnapLog(snapID uint, logPath string) {
	status, err := snapshotRepo.GetStatus(snapID)
	if err != nil {
		// Rendering the progress file from a zero-value status would report
		// every phase as blank, so skip the file and log why instead.
		global.LOG.Errorf("load status of snapshot %d for progress log failed, err: %v", snapID, err)
		return
	}
	logs := ""
	logs += fmt.Sprintf("Write 1Panel basic information: %s \n", status.PanelInfo)
	logs += fmt.Sprintf("Backup 1Panel system files: %s \n", status.Panel)
	logs += fmt.Sprintf("Backup Docker configuration file: %s \n", status.DaemonJson)
	logs += fmt.Sprintf("Backup installed apps from 1Panel: %s \n", status.AppData)
	logs += fmt.Sprintf("Backup 1Panel data directory: %s \n", status.PanelData)
	logs += fmt.Sprintf("Backup local backup directory for 1Panel: %s \n", status.BackupData)
	logs += fmt.Sprintf("Create snapshot file: %s \n", status.Compress)
	logs += fmt.Sprintf("Snapshot size: %s \n", status.Size)
	logs += fmt.Sprintf("Upload snapshot file: %s \n", status.Upload)

	file, err := os.OpenFile(logPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		return
	}
	defer file.Close()
	_, _ = file.Write([]byte(logs))
}

func hasOs(name string) bool {
	return strings.Contains(name, "amd64") ||
		strings.Contains(name, "arm64") ||
		strings.Contains(name, "armv7") ||
		strings.Contains(name, "ppc64le") ||
		strings.Contains(name, "s390x") ||
		strings.Contains(name, "riscv64")
}

func loadOs() string {
	hostInfo, _ := host.Info()
	switch hostInfo.KernelArch {
	case "x86_64":
		return "amd64"
	case "armv7l":
		return "armv7"
	default:
		return hostInfo.KernelArch
	}
}

func loadSnapSize(records []model.Snapshot) ([]dto.SnapshotFile, error) {
	datas := make([]dto.SnapshotFile, len(records))
	clientMap := make(map[string]loadSizeHelper)
	var wg sync.WaitGroup
	for i := 0; i < len(records); i++ {
		item := dto.SnapshotFile{Name: records[i].Name, ID: records[i].ID}
		itemPath := fmt.Sprintf("system_snapshot/%s.tar.gz", item.Name)
		if _, ok := clientMap[records[i].DefaultDownload]; !ok {
			backup, err := backupRepo.Get(commonRepo.WithByType(records[i].DefaultDownload))
			if err != nil {
				global.LOG.Errorf("load backup model %s from db failed, err: %v", records[i].DefaultDownload, err)
				clientMap[records[i].DefaultDownload] = loadSizeHelper{}
				datas[i] = item
				continue
			}
			client, err := NewIBackupService().NewClient(&backup)
			if err != nil {
				global.LOG.Errorf("load backup client %s from db failed, err: %v", records[i].DefaultDownload, err)
				clientMap[records[i].DefaultDownload] = loadSizeHelper{}
				datas[i] = item
				continue
			}
			item.Size, _ = client.Size(path.Join(strings.TrimLeft(backup.BackupPath, "/"), itemPath))
			datas[i] = item
			clientMap[records[i].DefaultDownload] = loadSizeHelper{backupPath: strings.TrimLeft(backup.BackupPath, "/"), client: client, isOk: true}
			continue
		}
		// Copy the helper out of clientMap so the goroutine below never reads
		// the map, which this loop keeps writing on later iterations.
		helper := clientMap[records[i].DefaultDownload]
		datas[i] = item
		if helper.isOk {
			wg.Add(1)
			go func(index int, helper loadSizeHelper, itemPath string) {
				defer wg.Done()
				datas[index].Size, _ = helper.client.Size(path.Join(helper.backupPath, itemPath))
			}(i, helper, itemPath)
		}
	}
	wg.Wait()
	return datas, nil
}
