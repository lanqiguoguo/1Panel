package service

import (
	"context"
	"fmt"
	"os"
	"path"
	"strings"
	"sync"

	"github.com/1Panel-dev/1Panel/backend/app/dto"
	"github.com/1Panel-dev/1Panel/backend/app/model"
	"github.com/1Panel-dev/1Panel/backend/constant"
	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/1Panel-dev/1Panel/backend/utils/cmd"
	"github.com/1Panel-dev/1Panel/backend/utils/common"
	composeUtil "github.com/1Panel-dev/1Panel/backend/utils/compose"
	"github.com/1Panel-dev/1Panel/backend/utils/files"
	"github.com/1Panel-dev/1Panel/backend/utils/systemctl"
	"github.com/pkg/errors"
)

func (u *SnapshotService) HandleSnapshotRecover(snap model.Snapshot, isRecover bool, req dto.SnapshotRecover) {
	_ = global.Cron.Stop()
	defer func() {
		global.Cron.Start()
	}()

	snapFileDir := ""
	if isRecover {
		baseDir := path.Join(global.CONF.System.TmpDir, fmt.Sprintf("system/%s", snap.Name))
		if _, err := os.Stat(baseDir); err != nil && os.IsNotExist(err) {
			_ = os.MkdirAll(baseDir, os.ModePerm)
		}
		if req.IsNew || snap.InterruptStep == "Download" || req.ReDownload {
			if err := handleDownloadSnapshot(snap, baseDir); err != nil {
				updateRecoverStatus(snap.ID, isRecover, "Backup", constant.StatusFailed, err.Error())
				return
			}
			global.LOG.Debugf("download snapshot file to %s successful!", baseDir)
			req.IsNew = true
		}
		if req.IsNew || snap.InterruptStep == "Decompress" {
			if err := handleUnTar(fmt.Sprintf("%s/%s.tar.gz", baseDir, snap.Name), baseDir, req.Secret); err != nil {
				updateRecoverStatus(snap.ID, isRecover, "Decompress", constant.StatusFailed, fmt.Sprintf("decompress file failed, err: %v", err))
				return
			}
			global.LOG.Debug("decompress snapshot file successful!", baseDir)
			req.IsNew = true
		}
		if req.IsNew || snap.InterruptStep == "Backup" {
			if err := backupBeforeRecover(snap); err != nil {
				updateRecoverStatus(snap.ID, isRecover, "Backup", constant.StatusFailed, fmt.Sprintf("handle backup before recover failed, err: %v", err))
				return
			}
			global.LOG.Debug("handle backup before recover successful!")
			req.IsNew = true
		}
		snapFileDir = fmt.Sprintf("%s/%s", baseDir, snap.Name)
		if _, err := os.Stat(snapFileDir); err != nil {
			snapFileDir = baseDir
		}
	} else {
		snapFileDir = fmt.Sprintf("%s/1panel_original/original_%s", global.CONF.System.BaseDir, snap.Name)
		if _, err := os.Stat(snapFileDir); err != nil {
			updateRecoverStatus(snap.ID, isRecover, "", constant.StatusFailed, fmt.Sprintf("cannot find the backup file %s, please try to recover again.", snapFileDir))
			return
		}
	}
	if isRecover {
		// A snapshot downloaded from cloud storage (or placed in the local
		// backup dir) is untrusted: the storage account may be compromised or
		// the package replaced in transit. Before any recovery step runs, the
		// decompressed package must carry a parseable snapshot.json whose
		// restore-target paths stay inside the panel data/backup/tmp
		// directories — otherwise the untar below could overwrite arbitrary
		// host paths, including the panel database with its stored
		// credentials. Decompression itself is already member-validated
		// (handleSafeUnTar), so it can only write inside the scratch dir.
		jsonPath := fmt.Sprintf("%s/snapshot.json", snapFileDir)
		if _, err := os.Stat(jsonPath); err != nil {
			updateRecoverStatus(snap.ID, isRecover, "Readjson", constant.StatusFailed, "snapshot.json is missing from the snapshot package")
			return
		}
		jsonItem, err := u.readFromJson(jsonPath)
		if err != nil {
			updateRecoverStatus(snap.ID, isRecover, "Readjson", constant.StatusFailed, fmt.Sprintf("decompress file failed, err: %v", err))
			return
		}
		if err := validateSnapshotJsonPaths(jsonItem); err != nil {
			global.LOG.Errorf("reject recovering snapshot %s: %v", snap.Name, err)
			updateRecoverStatus(snap.ID, isRecover, "Readjson", constant.StatusFailed, fmt.Sprintf("snapshot package integrity check failed, err: %v", err))
			return
		}
	}
	snapJson, err := u.readFromJson(fmt.Sprintf("%s/snapshot.json", snapFileDir))
	if err != nil {
		updateRecoverStatus(snap.ID, isRecover, "Readjson", constant.StatusFailed, fmt.Sprintf("decompress file failed, err: %v", err))
		return
	}
	if snap.InterruptStep == "Readjson" {
		req.IsNew = true
	}
	if isRecover && (req.IsNew || snap.InterruptStep == "AppData") {
		if err := recoverAppData(snapFileDir); err != nil {
			updateRecoverStatus(snap.ID, isRecover, "DockerDir", constant.StatusFailed, fmt.Sprintf("handle recover app data failed, err: %v", err))
			return
		}
		global.LOG.Debug("recover app data from snapshot file successful!")
		req.IsNew = true
	}
	if req.IsNew || snap.InterruptStep == "DaemonJson" {
		fileOp := files.NewFileOp()
		if err := recoverDaemonJson(snapFileDir, "/etc/docker", fileOp); err != nil {
			updateRecoverStatus(snap.ID, isRecover, "DaemonJson", constant.StatusFailed, err.Error())
			return
		}
		global.LOG.Debug("recover daemon.json from snapshot file successful!")
		req.IsNew = true
	}

	h, err := systemctl.DefaultHandler("1panel")
	if err != nil {
		updateRecoverStatus(snap.ID, isRecover, "ServiceHandle", constant.StatusFailed, fmt.Sprintf("initialize service handle failed: %v", err))
		return
	}

	if req.IsNew || snap.InterruptStep == "1PanelBinary" {
		binDir := systemctl.BinaryPath
		if err := recoverPanel(path.Join(snapFileDir, "1panel/1panel"), binDir); err != nil {
			updateRecoverStatus(snap.ID, isRecover, "1PanelBinary", constant.StatusFailed, err.Error())
			return
		}
		global.LOG.Debug("recover 1panel binary from snapshot file successful!")
		req.IsNew = true
	}
	if req.IsNew || snap.InterruptStep == "1PctlBinary" {
		binDir := systemctl.BinaryPath
		if err := recoverPanel(path.Join(snapFileDir, "1panel/1pctl"), binDir); err != nil {
			updateRecoverStatus(snap.ID, isRecover, "1PctlBinary", constant.StatusFailed, err.Error())
			return
		}
		langDir := path.Join(binDir, "lang")
		if err := os.RemoveAll(langDir); err != nil {
			updateRecoverStatus(snap.ID, isRecover, "RemoveLang", constant.StatusFailed, fmt.Sprintf("remove lang dir failed: %v", err))
			return
		}
		if err := common.CopyDirs(path.Join(snapFileDir, "1panel/lang"), langDir); err != nil {
			updateRecoverStatus(snap.ID, isRecover, "CopyLang", constant.StatusFailed, fmt.Sprintf("copy lang files failed: %v", err))
			return
		}
		global.LOG.Debug("recover 1pctl from snapshot file successful!")
		req.IsNew = true
	}
	if req.IsNew || snap.InterruptStep == "1PanelService" {
		servicePath, err := h.GetServicePath()
		currentServiceName := h.GetServiceName()
		if err != nil {
			updateRecoverStatus(snap.ID, isRecover, "GetServicePath", constant.StatusFailed, fmt.Sprintf("get service path failed: %v", err))
			return
		}
		global.LOG.Debugf("current service path: %s", servicePath)
		if err := common.CopyFile(selectInitScript(path.Join(snapFileDir, "1panel/initscript"), currentServiceName), servicePath); err != nil {
			updateRecoverStatus(snap.ID, isRecover, "1PanelService", constant.StatusFailed, err.Error())
			return
		}
		global.LOG.Debug("recover 1panel service from snapshot file successful!")
		req.IsNew = true
	}

	if req.IsNew || snap.InterruptStep == "1PanelBackups" {
		// Atomically staged restore (snapshot_stage.go): the payload is fully
		// materialised and verified next to the target first, then swapped in
		// member by member. A failure leaves the backup dir untouched instead
		// of half-overwritten.
		if err := applyStagedPayload(path.Join(snapFileDir, "/1panel/1panel_backup.tar.gz"), snapJson.BackupDataDir, ""); err != nil {
			updateRecoverStatus(snap.ID, isRecover, "1PanelBackups", constant.StatusFailed, err.Error())
			return
		}
		global.LOG.Debug("recover 1panel backups from snapshot file successful!")
		req.IsNew = true
	}

	if req.IsNew || snap.InterruptStep == "1PanelData" {
		checkPointOfWal()
		// Atomic staged restore of the live data directory (snapshot_stage.go):
		// the payload is extracted and integrity-checked in a staging dir next
		// to <BaseDir>/1panel, swapped in member by member, and the panel DB
		// handle is reopened onto the restored file. On any failure the swap is
		// rolled back (or never started) and the running process keeps its
		// pre-recovery data directory — no mixed snapshot/leftover state.
		dataDir := path.Join(snapJson.BaseDir, "1panel")
		if err := applyStagedPanelData(path.Join(snapFileDir, "/1panel/1panel_data.tar.gz"), dataDir); err != nil {
			updateRecoverStatus(snap.ID, isRecover, "1PanelData", constant.StatusFailed, err.Error())
			return
		}
		global.LOG.Debug("recover 1panel data from snapshot file successful!")
		req.IsNew = true
	}
	// Reaching here means the data untar replaced the whole app_installs table
	// with the snapshot's rows (and the panel restarts into the recovered
	// database right after), so every in-flight port claim minted against the
	// previous database lost the install that justified it. Dropping them is
	// the same reasoning as forceReleaseAppPort but for all ports at once;
	// keeping them would make the panel reject new installs on the recovered
	// apps' ports until the restart. Only the success path runs this: on any
	// earlier failure the database was never replaced and live claims (and
	// their protection) still refer to the untouched app_installs.
	resetAppPortClaims()
	_ = rebuildAllAppInstall()
	restartCompose(path.Join(snapJson.BaseDir, "1panel/docker/compose"))

	// Persist the terminal state BEFORE the process restart below. This is the
	// only place that clears the recover/rollback status on the success path:
	// without it the row keeps its "Waiting" marker and the init hook
	// (handleSnapStatus) would stamp it as failed "interrupted due to the
	// restart" although the recovery succeeded. updateRecoverStatus also resets
	// the SystemStatus setting to Free, so a failing restart below can no
	// longer leave the panel locked in "Recovering" (GlobalLoading middleware
	// rejects every API while SystemStatus != Free).
	updateRecoverStatus(snap.ID, isRecover, "", constant.StatusSuccess, "")

	global.LOG.Info("recover successful")
	if !isRecover {
		oriPath := fmt.Sprintf("%s/1panel_original/original_%s", global.CONF.System.BaseDir, snap.Name)
		global.LOG.Debugf("remove the file %s after the operation is successful", oriPath)
		_ = os.RemoveAll(oriPath)
	} else {
		global.LOG.Debugf("remove the file %s after the operation is successful", path.Dir(snapFileDir))
		_ = os.RemoveAll(path.Dir(snapFileDir))
	}
	if h.ManagerName() == "systemd" {
		_, _ = cmd.Exec("systemctl daemon-reload")
	}
	if err := systemctl.Restart("1panel"); err != nil {
		global.LOG.Errorf("restart 1panel service failed: %v", err)
	}
}

func backupBeforeRecover(snap model.Snapshot) error {
	baseDir := fmt.Sprintf("%s/1panel_original/original_%s", global.CONF.System.BaseDir, snap.Name)
	var wg sync.WaitGroup
	var status model.SnapshotStatus
	itemHelper := snapHelper{SnapID: 0, Status: &status, Wg: &wg, FileOp: files.NewFileOp(), Ctx: context.Background()}

	jsonItem := SnapshotJson{
		BaseDir:       global.CONF.System.BaseDir,
		BackupDataDir: global.CONF.System.Backup,
		PanelDataDir:  path.Join(global.CONF.System.BaseDir, "1panel"),
	}
	_ = os.MkdirAll(path.Join(baseDir, "1panel"), os.ModePerm)
	_ = os.MkdirAll(path.Join(baseDir, "docker"), os.ModePerm)

	// The snapshot workers only persist their progress to the database (they no
	// longer write the shared in-memory status), so give them a dedicated
	// status row to report through and read it back afterwards. snap_id 0 is
	// never used by real snapshot records, keeping this out of the way.
	if err := snapshotRepo.CreateStatus(&status); err != nil {
		return fmt.Errorf("create backup status failed, err: %v", err)
	}
	defer func() {
		if err := snapshotRepo.DeleteStatus(status.SnapID); err != nil {
			global.LOG.Errorf("delete backup status failed, err: %v", err)
		}
	}()

	wg.Add(4)
	itemHelper.Wg = &wg
	go snapJson(itemHelper, jsonItem, baseDir)
	go snapPanel(itemHelper, path.Join(baseDir, "1panel"))
	go snapDaemonJson(itemHelper, path.Join(baseDir, "docker"))
	go snapBackup(itemHelper, global.CONF.System.Backup, path.Join(baseDir, "1panel"))
	wg.Wait()
	// app data is not part of the pre-recover backup; mark it done like the
	// original in-memory flow did so checkAllDone passes.
	if err := snapshotRepo.UpdateStatus(status.ID, map[string]interface{}{"app_data": constant.StatusDone}); err != nil {
		global.LOG.Errorf("update backup status app_data failed, err: %v", err)
	}

	statusItem, err := snapshotRepo.GetStatus(status.SnapID)
	if err != nil {
		return fmt.Errorf("load backup status failed, err: %v", err)
	}
	allDone, msg := checkAllDone(statusItem)
	if !allDone {
		return errors.New(msg)
	}
	snapPanelData(itemHelper, global.CONF.System.BaseDir, path.Join(baseDir, "1panel"))
	statusItem, err = snapshotRepo.GetStatus(status.SnapID)
	if err != nil {
		return fmt.Errorf("load backup status failed, err: %v", err)
	}
	if statusItem.PanelData != constant.StatusDone {
		return errors.New(statusItem.PanelData)
	}
	return nil
}

func handleDownloadSnapshot(snap model.Snapshot, targetDir string) error {
	backup, err := backupRepo.Get(commonRepo.WithByType(snap.DefaultDownload))
	if err != nil {
		return err
	}
	client, err := NewIBackupService().NewClient(&backup)
	if err != nil {
		return err
	}
	pathItem := backup.BackupPath
	if backup.BackupPath != "/" {
		pathItem = strings.TrimPrefix(backup.BackupPath, "/")
	}
	filePath := fmt.Sprintf("%s/%s.tar.gz", targetDir, snap.Name)
	_ = os.RemoveAll(filePath)
	ok, err := client.Download(path.Join(pathItem, fmt.Sprintf("system_snapshot/%s.tar.gz", snap.Name)), filePath)
	if err != nil || !ok {
		return fmt.Errorf("download file %s from %s failed, err: %v", snap.Name, backup.Type, err)
	}
	return nil
}

func recoverAppData(src string) error {
	if _, err := os.Stat(path.Join(src, "docker/docker_image.tar")); err != nil {
		global.LOG.Debug("no such docker images in snapshot")
		return nil
	}
	std, err := cmd.Execf("docker load < %s", path.Join(src, "docker/docker_image.tar"))
	if err != nil {
		return errors.New(std)
	}
	return err
}

// recoverDaemonJson restores the snapshot's docker daemon.json (when the
// snapshot carries one) and restarts docker so the daemon runs against the
// restored configuration. The copy and the restart share daemonJsonMu with
// every other daemon.json writer (see applyRegistriesChange for the full
// rationale): dockerd reads the whole file on restart, so a concurrent writer
// interleaving between our copy and our restart could get its change silently
// overwritten by the restored file — or have the restart pick up a config
// nobody meant to ship. waitForDockerActive keeps the recovery from moving on
// to app rebuilds while the daemon is still coming back.
//
// When the snapshot has no daemon.json but the host does, no copy happens yet
// docker is still restarted. That asymmetry is pre-existing behaviour, kept
// deliberately: after a full system restore the restart pins the daemon to
// whatever config is on disk at this point; skipping it would silently change
// recovery semantics, so it is documented here rather than "fixed" in passing.
func recoverDaemonJson(src, daemonJsonDir string, fileOp files.FileOp) error {
	daemonJsonPath := path.Join(daemonJsonDir, "daemon.json")
	_, errSrc := os.Stat(path.Join(src, "docker/daemon.json"))
	_, errPath := os.Stat(daemonJsonPath)
	if os.IsNotExist(errSrc) && os.IsNotExist(errPath) {
		global.LOG.Debug("the daemon.json file does not exist, nothing happens.")
		return nil
	}
	daemonJsonMu.Lock()
	defer daemonJsonMu.Unlock()
	if errSrc == nil {
		if err := fileOp.CopyFile(path.Join(src, "docker/daemon.json"), daemonJsonDir); err != nil {
			return fmt.Errorf("recover docker daemon.json failed, err: %v", err)
		}
	}

	if err := restartDockerFn(); err != nil {
		return err
	}
	return waitForDockerActiveFn()
}

func recoverPanel(src string, dst string) error {
	if _, err := os.Stat(src); err != nil {
		return fmt.Errorf("file is not found in %s, err: %v", src, err)
	}
	if err := common.CopyFile(src, dst); err != nil {
		return fmt.Errorf("cp file failed, err: %v", err)
	}
	return nil
}

func restartCompose(composePath string) {
	composes, err := composeRepo.ListRecord()
	if err != nil {
		return
	}
	for _, compose := range composes {
		pathItem := path.Join(composePath, compose.Name, "docker-compose.yml")
		if _, err := os.Stat(pathItem); err != nil {
			continue
		}
		upCmd := fmt.Sprintf("%s -f %s up -d", composeUtil.Command(), pathItem)
		stdout, err := cmd.Exec(upCmd)
		if err != nil {
			global.LOG.Debugf("%s failed, err: %v", upCmd, stdout)
		}
	}
	global.LOG.Debug("restart all compose successful!")
}
