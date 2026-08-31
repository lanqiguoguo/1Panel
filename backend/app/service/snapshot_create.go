package service

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/1Panel-dev/1Panel/backend/app/model"
	"github.com/1Panel-dev/1Panel/backend/buserr"
	"github.com/1Panel-dev/1Panel/backend/constant"
	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/1Panel-dev/1Panel/backend/utils/cmd"
	"github.com/1Panel-dev/1Panel/backend/utils/common"
	"github.com/1Panel-dev/1Panel/backend/utils/files"
	"github.com/1Panel-dev/1Panel/backend/utils/systemctl"
)

type snapHelper struct {
	SnapID uint
	Status *model.SnapshotStatus
	Ctx    context.Context
	FileOp files.FileOp
	Wg     *sync.WaitGroup
}

func snapJson(snap snapHelper, snapJson SnapshotJson, targetDir string) {
	defer snap.Wg.Done()
	if err := snapshotRepo.UpdateStatus(snap.Status.ID, map[string]interface{}{"panel_info": constant.Running}); err != nil {
		global.LOG.Errorf("update snapshot panel_info status to running failed, err: %v", err)
	}
	status := constant.StatusDone
	remarkInfo, _ := json.MarshalIndent(snapJson, "", "\t")
	if err := os.WriteFile(fmt.Sprintf("%s/snapshot.json", targetDir), remarkInfo, 0640); err != nil {
		status = err.Error()
	}
	if err := snapshotRepo.UpdateStatus(snap.Status.ID, map[string]interface{}{"panel_info": status}); err != nil {
		global.LOG.Errorf("update snapshot panel_info status failed, err: %v", err)
	}
}

func snapPanel(snap snapHelper, targetDir string) {
	defer snap.Wg.Done()
	if err := snapshotRepo.UpdateStatus(snap.Status.ID, map[string]interface{}{"panel": constant.Running}); err != nil {
		global.LOG.Errorf("update snapshot panel status to running failed, err: %v", err)
	}
	status := constant.StatusDone
	h, err := systemctl.DefaultHandler("1panel")

	if err != nil {
		status = fmt.Sprintf("initialize service handle failed: %v", err)
		if err := snapshotRepo.UpdateStatus(snap.Status.ID, map[string]interface{}{"panel": status}); err != nil {
			global.LOG.Errorf("update snapshot panel status failed, err: %v", err)
		}
		return
	}

	binDir := systemctl.BinaryPath
	servicePath, err := h.GetServicePath()
	if err != nil {
		status = fmt.Sprintf("get service path failed: %v", err)
		if err := snapshotRepo.UpdateStatus(snap.Status.ID, map[string]interface{}{"panel": status}); err != nil {
			global.LOG.Errorf("update snapshot panel status failed, err: %v", err)
		}
		return
	}

	if err := common.CopyFile(path.Join(binDir, "1panel"), path.Join(targetDir, "1panel")); err != nil {
		status = err.Error()
	}
	if err := common.CopyFile(path.Join(binDir, "1pctl"), targetDir); err != nil {
		status = err.Error()
	}
	if _, err := cmd.Execf("cp -r %s/lang %s", binDir, targetDir); err != nil {
		status = err.Error()
	}
	initScriptDir := path.Join(constant.DataDir, "initscript")
	if err := common.CopyFile(servicePath, initScriptDir); err != nil {
		status = err.Error()
	}
	global.LOG.Debugf("from %s copy init script to %s", initScriptDir, path.Join(targetDir, "initscript"))
	if err := common.CopyDirs(initScriptDir, path.Join(targetDir, "initscript")); err != nil { // copy init script to targetDir
		status = err.Error()
	}
	if err := snapshotRepo.UpdateStatus(snap.Status.ID, map[string]interface{}{"panel": status}); err != nil {
		global.LOG.Errorf("update snapshot panel status failed, err: %v", err)
	}
}

func snapDaemonJson(snap snapHelper, targetDir string) {
	defer snap.Wg.Done()
	status := constant.StatusDone
	if !snap.FileOp.Stat("/etc/docker/daemon.json") {
		if err := snapshotRepo.UpdateStatus(snap.Status.ID, map[string]interface{}{"daemon_json": status}); err != nil {
			global.LOG.Errorf("update snapshot daemon_json status failed, err: %v", err)
		}
		return
	}
	if err := snapshotRepo.UpdateStatus(snap.Status.ID, map[string]interface{}{"daemon_json": constant.Running}); err != nil {
		global.LOG.Errorf("update snapshot daemon_json status to running failed, err: %v", err)
	}
	if err := common.CopyFile("/etc/docker/daemon.json", targetDir); err != nil {
		status = err.Error()
	}
	if err := snapshotRepo.UpdateStatus(snap.Status.ID, map[string]interface{}{"daemon_json": status}); err != nil {
		global.LOG.Errorf("update snapshot daemon_json status failed, err: %v", err)
	}
}

func snapAppData(snap snapHelper, targetDir string) {
	defer snap.Wg.Done()
	if err := snapshotRepo.UpdateStatus(snap.Status.ID, map[string]interface{}{"app_data": constant.Running}); err != nil {
		global.LOG.Errorf("update snapshot app_data status to running failed, err: %v", err)
	}
	appInstalls, err := appInstallRepo.ListBy()
	if err != nil {
		if err := snapshotRepo.UpdateStatus(snap.Status.ID, map[string]interface{}{"app_data": err.Error()}); err != nil {
			global.LOG.Errorf("update snapshot app_data status failed, err: %v", err)
		}
		return
	}
	runtimes, err := runtimeRepo.List()
	if err != nil {
		if err := snapshotRepo.UpdateStatus(snap.Status.ID, map[string]interface{}{"app_data": err.Error()}); err != nil {
			global.LOG.Errorf("update snapshot app_data status failed, err: %v", err)
		}
		return
	}
	imageRegex := regexp.MustCompile(`image:\s*(.*)`)
	var imageSaveList []string
	existStr, _ := cmd.Exec("docker images | awk '{print $1\":\"$2}' | grep -v REPOSITORY:TAG")
	existImages := strings.Split(existStr, "\n")
	duplicateMap := make(map[string]bool)
	for _, app := range appInstalls {
		matches := imageRegex.FindAllStringSubmatch(app.DockerCompose, -1)
		for _, match := range matches {
			for _, existImage := range existImages {
				if match[1] == existImage && !duplicateMap[match[1]] {
					imageSaveList = append(imageSaveList, match[1])
					duplicateMap[match[1]] = true
				}
			}
		}
	}
	for _, runtime := range runtimes {
		for _, existImage := range existImages {
			if runtime.Image == existImage && !duplicateMap[runtime.Image] {
				imageSaveList = append(imageSaveList, runtime.Image)
				duplicateMap[runtime.Image] = true
			}
		}
	}

	if len(imageSaveList) != 0 {
		// The names come from docker-compose.yml content and are joined into a
		// bash -c command line below (docker save | gzip); only plain image
		// references may pass (see validateImageRefs for the rationale).
		if err := validateImageRefs(imageSaveList); err != nil {
			global.LOG.Errorf("skip docker save, %v", err)
			if err := snapshotRepo.UpdateStatus(snap.Status.ID, map[string]interface{}{"app_data": err.Error()}); err != nil {
				global.LOG.Errorf("update snapshot app_data status failed, err: %v", err)
			}
			return
		}
		global.LOG.Debugf("docker save %s | gzip -c > %s", strings.Join(imageSaveList, " "), path.Join(targetDir, "docker_image.tar"))
		std, err := cmd.Execf("docker save %s | gzip -c > %s", strings.Join(imageSaveList, " "), path.Join(targetDir, "docker_image.tar"))
		if err != nil {
			if err := snapshotRepo.UpdateStatus(snap.Status.ID, map[string]interface{}{"app_data": std}); err != nil {
				global.LOG.Errorf("update snapshot app_data status failed, err: %v", err)
			}
			return
		}
	}
	if err := snapshotRepo.UpdateStatus(snap.Status.ID, map[string]interface{}{"app_data": constant.StatusDone}); err != nil {
		global.LOG.Errorf("update snapshot app_data status failed, err: %v", err)
	}
}

func snapBackup(snap snapHelper, localDir, targetDir string) {
	defer snap.Wg.Done()
	if err := snapshotRepo.UpdateStatus(snap.Status.ID, map[string]interface{}{"backup_data": constant.Running}); err != nil {
		global.LOG.Errorf("update snapshot backup_data status to running failed, err: %v", err)
	}
	status := constant.StatusDone
	if err := handleSnapTar(localDir, targetDir, "1panel_backup.tar.gz", "./system;./system_snapshot;", ""); err != nil {
		status = err.Error()
	}
	if err := snapshotRepo.UpdateStatus(snap.Status.ID, map[string]interface{}{"backup_data": status}); err != nil {
		global.LOG.Errorf("update snapshot backup_data status failed, err: %v", err)
	}
}

func snapPanelData(snap snapHelper, localDir, targetDir string) {
	if err := snapshotRepo.UpdateStatus(snap.Status.ID, map[string]interface{}{"panel_data": constant.Running}); err != nil {
		global.LOG.Errorf("update snapshot panel_data status to running failed, err: %v", err)
	}
	status := constant.StatusDone
	dataDir := path.Join(global.CONF.System.BaseDir, "1panel")
	exclusionRules := "./tmp;./log;./cache;./db/1Panel.db-*;"
	if strings.Contains(localDir, dataDir) {
		exclusionRules += ("." + strings.ReplaceAll(localDir, dataDir, "") + ";")
	}
	ignoreVal, _ := settingRepo.Get(settingRepo.WithByKey("SnapshotIgnore"))
	rules := strings.Split(ignoreVal.Value, ",")
	for _, ignore := range rules {
		if len(ignore) == 0 || cmd.CheckIllegal(ignore) {
			continue
		}
		exclusionRules += ("." + strings.ReplaceAll(ignore, dataDir, "") + ";")
	}
	if err := snapshotRepo.Update(snap.SnapID, map[string]interface{}{"status": "OnSaveData"}); err != nil {
		global.LOG.Errorf("update snapshot status to OnSaveData failed, err: %v", err)
	}
	sysIP, _ := settingRepo.Get(settingRepo.WithByKey("SystemIP"))
	if err := settingRepo.Update("SystemIP", ""); err != nil {
		global.LOG.Errorf("temporarily clear SystemIP for snapshot backup failed, err: %v", err)
	}
	checkPointOfWal()
	if err := handleSnapTar(dataDir, targetDir, "1panel_data.tar.gz", exclusionRules, ""); err != nil {
		status = err.Error()
	}
	if err := snapshotRepo.Update(snap.SnapID, map[string]interface{}{"status": constant.StatusWaiting}); err != nil {
		global.LOG.Errorf("update snapshot status to waiting failed, err: %v", err)
	}

	if err := snapshotRepo.UpdateStatus(snap.Status.ID, map[string]interface{}{"panel_data": status}); err != nil {
		global.LOG.Errorf("update snapshot panel_data status failed, err: %v", err)
	}
	if err := settingRepo.Update("SystemIP", sysIP.Value); err != nil {
		global.LOG.Errorf("restore SystemIP after snapshot backup failed, err: %v", err)
	}
}

func snapCompress(snap snapHelper, rootDir string, secret string) {
	if err := snapshotRepo.UpdateStatus(snap.Status.ID, map[string]interface{}{"compress": constant.StatusRunning}); err != nil {
		global.LOG.Errorf("update snapshot compress status to running failed, err: %v", err)
	}
	tmpDir := path.Join(global.CONF.System.TmpDir, "system")
	fileName := fmt.Sprintf("%s.tar.gz", path.Base(rootDir))
	if err := handleSnapTar(rootDir, tmpDir, fileName, "", secret); err != nil {
		if err := snapshotRepo.UpdateStatus(snap.Status.ID, map[string]interface{}{"compress": err.Error()}); err != nil {
			global.LOG.Errorf("update snapshot compress status failed, err: %v", err)
		}
		return
	}

	stat, err := os.Stat(path.Join(tmpDir, fileName))
	if err != nil {
		if err := snapshotRepo.UpdateStatus(snap.Status.ID, map[string]interface{}{"compress": err.Error()}); err != nil {
			global.LOG.Errorf("update snapshot compress status failed, err: %v", err)
		}
		return
	}
	size := common.LoadSizeUnit2F(float64(stat.Size()))
	global.LOG.Debugf("compress successful! size of file: %s", size)
	if err := snapshotRepo.UpdateStatus(snap.Status.ID, map[string]interface{}{"compress": constant.StatusDone, "size": size}); err != nil {
		global.LOG.Errorf("update snapshot compress status failed, err: %v", err)
	}

	global.LOG.Debugf("remove snapshot file %s", rootDir)
	_ = os.RemoveAll(rootDir)
}

func snapUpload(snap snapHelper, accounts string, file string) {
	source := path.Join(global.CONF.System.TmpDir, "system", path.Base(file))
	if err := snapshotRepo.UpdateStatus(snap.Status.ID, map[string]interface{}{"upload": constant.StatusUploading}); err != nil {
		global.LOG.Errorf("update snapshot upload status to uploading failed, err: %v", err)
	}
	accountMap, err := loadClientMap(accounts)
	if err != nil {
		if err := snapshotRepo.UpdateStatus(snap.Status.ID, map[string]interface{}{"upload": err.Error()}); err != nil {
			global.LOG.Errorf("update snapshot upload status failed, err: %v", err)
		}
		return
	}
	targetAccounts := strings.Split(accounts, ",")
	for _, item := range targetAccounts {
		global.LOG.Debugf("start upload snapshot to %s, path: %s", item, path.Join(accountMap[item].backupPath, "system_snapshot", path.Base(file)))
		if _, err := accountMap[item].client.Upload(source, path.Join(accountMap[item].backupPath, "system_snapshot", path.Base(file))); err != nil {
			global.LOG.Debugf("upload to %s failed, err: %v", item, err)
			if err := snapshotRepo.UpdateStatus(snap.Status.ID, map[string]interface{}{"upload": err.Error()}); err != nil {
				global.LOG.Errorf("update snapshot upload status failed, err: %v", err)
			}
			return
		}
		global.LOG.Debugf("upload to %s successful", item)
	}
	if err := snapshotRepo.UpdateStatus(snap.Status.ID, map[string]interface{}{"upload": constant.StatusDone}); err != nil {
		global.LOG.Errorf("update snapshot upload status failed, err: %v", err)
	}

	global.LOG.Debugf("remove snapshot file %s", source)
	_ = os.Remove(source)
}

func handleSnapTar(sourceDir, targetDir, name, exclusionRules string, secret string) error {
	// Defense in depth, mirroring handleTar in cronjob_helper.go: every
	// user-influenced argument is validated before it is interpolated into the
	// bash -c archive command. Checking the secret here (not only in the
	// request entry points) also covers stored cronjob records whose secret is
	// replayed by snapshotCompress, and the check runs before any side effect
	// (the target dir is not even created for an illegal argument).
	if !files.ValidShellArgs(sourceDir, targetDir, name) || (secret != "" && !files.ValidShellArgs(secret)) {
		return buserr.New(constant.ErrCmdIllegal)
	}
	if _, err := os.Stat(targetDir); err != nil && os.IsNotExist(err) {
		if err = os.MkdirAll(targetDir, os.ModePerm); err != nil {
			return err
		}
	}

	exMap := make(map[string]struct{})
	exStr := ""
	excludes := strings.Split(exclusionRules, ";")
	for _, exclude := range excludes {
		if len(exclude) == 0 {
			continue
		}
		if _, ok := exMap[exclude]; ok {
			continue
		}
		exStr += " --exclude "
		exStr += exclude
		exMap[exclude] = struct{}{}
	}
	path := ""
	if strings.Contains(sourceDir, "/") {
		itemDir := strings.ReplaceAll(sourceDir[strings.LastIndex(sourceDir, "/"):], "/", "")
		aheadDir := sourceDir[:strings.LastIndex(sourceDir, "/")]
		if len(aheadDir) == 0 {
			aheadDir = "/"
		}
		path += fmt.Sprintf("-C %s %s", aheadDir, itemDir)
	} else {
		path = sourceDir
	}
	commands := ""
	if len(secret) != 0 {
		extraCmd := "| openssl enc -aes-256-cbc -salt -k '" + secret + "' -out"
		commands = fmt.Sprintf("tar --warning=no-file-changed --ignore-failed-read --exclude-from=<(find %s -type s -print) -zcf %s %s %s %s", sourceDir, " -"+exStr, path, extraCmd, targetDir+"/"+name)
		// The secret appears quoted in the command (-k '<secret>'); the old
		// ' %s ' pattern never matched that form, leaking the key into the
		// debug log. Mask both the quoted and the bare form.
		global.LOG.Debug(strings.ReplaceAll(strings.ReplaceAll(commands, "'"+secret+"'", "******"), secret, "******"))
	} else {
		commands = fmt.Sprintf("tar --warning=no-file-changed --ignore-failed-read --exclude-from=<(find %s -type s -printf '%%P\n' | sed 's|^|./|') -zcf %s %s -C %s .", sourceDir, targetDir+"/"+name, exStr, sourceDir)
		global.LOG.Debug(commands)
	}
	stdout, err := cmd.ExecWithTimeOut(commands, 30*time.Minute)
	if err != nil {
		if len(stdout) != 0 {
			global.LOG.Errorf("do handle tar failed, stdout: %s, err: %v", stdout, err)
			return fmt.Errorf("do handle tar failed, stdout: %s, err: %v", stdout, err)
		}
	}
	return nil
}

func checkPointOfWal() {
	if err := global.DB.Exec("PRAGMA wal_checkpoint(TRUNCATE);").Error; err != nil {
		global.LOG.Errorf("handle check point failed, err: %v", err)
	}
}
