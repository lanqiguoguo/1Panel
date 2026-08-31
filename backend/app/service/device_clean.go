package service

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/1Panel-dev/1Panel/backend/buserr"
	"github.com/1Panel-dev/1Panel/backend/constant"
	"github.com/1Panel-dev/1Panel/backend/utils/docker"
	"github.com/1Panel-dev/1Panel/backend/utils/systemctl"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"

	"github.com/1Panel-dev/1Panel/backend/app/dto"
	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/1Panel-dev/1Panel/backend/utils/common"
	fileUtils "github.com/1Panel-dev/1Panel/backend/utils/files"
	"github.com/google/uuid"
)

const (
	upgradePath      = "1panel/tmp/upgrade"
	snapshotTmpPath  = "1panel/tmp/system"
	rollbackPath     = "1panel/tmp"
	cachePath        = "1panel/cache"
	oldOriginalPath  = "original"
	oldAppBackupPath = "1panel/resource/apps_bak"
	oldDownloadPath  = "1panel/tmp/download"
	oldUpgradePath   = "1panel/tmp"
	tmpUploadPath    = "1panel/tmp/upload"
	uploadPath       = "1panel/uploads"
	downloadPath     = "1panel/download"
	logPath          = "1panel/log"
	dockerLogPath    = "1panel/tmp/docker_logs"
	taskPath         = "1panel/task"
)

func (u *DeviceService) Scan() dto.CleanData {
	var (
		SystemClean dto.CleanData
		treeData    []dto.CleanTree
	)
	fileOp := fileUtils.NewFileOp()

	originalPath := path.Join(global.CONF.System.BaseDir, "1panel_original")
	originalSize, _ := fileOp.GetDirSize(originalPath)
	treeData = append(treeData, dto.CleanTree{
		ID:          uuid.NewString(),
		Label:       "1panel_original",
		Size:        uint64(originalSize),
		IsCheck:     true,
		IsRecommend: true,
		Type:        "1panel_original",
		Children:    loadTreeWithDir(true, "1panel_original", originalPath, fileOp),
	})

	upgradePath := path.Join(global.CONF.System.BaseDir, upgradePath)
	upgradeSize, _ := fileOp.GetDirSize(upgradePath)
	treeData = append(treeData, dto.CleanTree{
		ID:          uuid.NewString(),
		Label:       "upgrade",
		Size:        uint64(upgradeSize),
		IsCheck:     false,
		IsRecommend: true,
		Type:        "upgrade",
		Children:    loadTreeWithDir(true, "upgrade", upgradePath, fileOp),
	})

	snapTree := loadSnapshotTree(fileOp)
	snapSize := uint64(0)
	for _, snap := range snapTree {
		snapSize += snap.Size
	}
	treeData = append(treeData, dto.CleanTree{
		ID:          uuid.NewString(),
		Label:       "snapshot",
		Size:        snapSize,
		IsCheck:     true,
		IsRecommend: true,
		Type:        "snapshot",
		Children:    snapTree,
	})

	rollBackTree := loadRollBackTree(fileOp)
	rollbackSize := uint64(0)
	for _, rollback := range rollBackTree {
		rollbackSize += rollback.Size
	}
	treeData = append(treeData, dto.CleanTree{
		ID:          uuid.NewString(),
		Label:       "rollback",
		Size:        rollbackSize,
		IsCheck:     true,
		IsRecommend: true,
		Type:        "rollback",
		Children:    rollBackTree,
	})

	cachePath := path.Join(global.CONF.System.BaseDir, cachePath)
	cacheSize, _ := fileOp.GetDirSize(cachePath)
	treeData = append(treeData, dto.CleanTree{
		ID:          uuid.NewString(),
		Label:       "cache",
		Size:        uint64(cacheSize),
		IsCheck:     false,
		IsRecommend: false,
		Type:        "cache",
	})

	unusedTree := loadUnusedFile(fileOp)
	unusedSize := uint64(0)
	for _, unused := range unusedTree {
		unusedSize += unused.Size
	}
	treeData = append(treeData, dto.CleanTree{
		ID:          uuid.NewString(),
		Label:       "unused",
		Size:        unusedSize,
		IsCheck:     true,
		IsRecommend: true,
		Type:        "unused",
		Children:    unusedTree,
	})
	SystemClean.SystemClean = treeData

	uploadTreeData := loadUploadTree(fileOp)
	SystemClean.UploadClean = append(SystemClean.UploadClean, uploadTreeData...)

	downloadTreeData := loadDownloadTree(fileOp)
	SystemClean.DownloadClean = append(SystemClean.DownloadClean, downloadTreeData...)

	logTree := loadLogTree(fileOp)
	SystemClean.SystemLogClean = append(SystemClean.SystemLogClean, logTree...)

	containerTree := loadContainerTree()
	SystemClean.ContainerClean = append(SystemClean.ContainerClean, containerTree...)

	return SystemClean
}

func (u *DeviceService) Clean(req []dto.Clean) error {
	size := uint64(0)
	restart := false
	// 统一校验所有清理项的 Name，任一非法则整体拒绝，防止路径穿越删除任意目录
	for _, item := range req {
		if err := checkCleanName(item.Name); err != nil {
			global.LOG.Errorf("clean item treeType %s has invalid name %q", item.TreeType, item.Name)
			return err
		}
	}
	for _, item := range req {
		size += item.Size
		switch item.TreeType {
		case "1panel_original":
			if err := dropFileOrDir(path.Join(global.CONF.System.BaseDir, "1panel_original", item.Name)); err != nil {
				return err
			}

		case "upgrade":
			if err := dropFileOrDir(path.Join(global.CONF.System.BaseDir, upgradePath, item.Name)); err != nil {
				return err
			}

		case "snapshot":
			if err := dropFileOrDir(path.Join(global.CONF.System.BaseDir, snapshotTmpPath, item.Name)); err != nil {
				return err
			}
			if err := dropFileOrDir(path.Join(global.CONF.System.Backup, "system", item.Name)); err != nil {
				return err
			}
		case "snapshot_tmp":
			if err := dropFileOrDir(path.Join(global.CONF.System.BaseDir, snapshotTmpPath, item.Name)); err != nil {
				return err
			}
		case "snapshot_local":
			if err := dropFileOrDir(path.Join(global.CONF.System.Backup, "system", item.Name)); err != nil {
				return err
			}

		case "rollback":
			if err := dropFileOrDir(path.Join(global.CONF.System.BaseDir, rollbackPath, "app")); err != nil {
				return err
			}
			if err := dropFileOrDir(path.Join(global.CONF.System.BaseDir, rollbackPath, "database")); err != nil {
				return err
			}
			if err := dropFileOrDir(path.Join(global.CONF.System.BaseDir, rollbackPath, "website")); err != nil {
				return err
			}
		case "rollback_app":
			if err := dropFileOrDir(path.Join(global.CONF.System.BaseDir, rollbackPath, "app", item.Name)); err != nil {
				return err
			}
		case "rollback_database":
			if err := dropFileOrDir(path.Join(global.CONF.System.BaseDir, rollbackPath, "database", item.Name)); err != nil {
				return err
			}
		case "rollback_website":
			if err := dropFileOrDir(path.Join(global.CONF.System.BaseDir, rollbackPath, "website", item.Name)); err != nil {
				return err
			}

		case "cache":
			if err := dropFileOrDir(path.Join(global.CONF.System.BaseDir, cachePath, item.Name)); err != nil {
				return err
			}
			restart = true

		case "unused":
			if err := dropFileOrDir(path.Join(global.CONF.System.BaseDir, oldOriginalPath)); err != nil {
				return err
			}
			if err := dropFileOrDir(path.Join(global.CONF.System.BaseDir, oldAppBackupPath)); err != nil {
				return err
			}
			if err := dropFileOrDir(path.Join(global.CONF.System.BaseDir, oldDownloadPath)); err != nil {
				return err
			}
			files, _ := os.ReadDir(path.Join(global.CONF.System.BaseDir, oldUpgradePath))
			if len(files) == 0 {
				continue
			}
			for _, file := range files {
				if strings.HasPrefix(file.Name(), "upgrade_") {
					if err := dropFileOrDir(path.Join(global.CONF.System.BaseDir, oldUpgradePath, file.Name())); err != nil {
						return err
					}
				}
			}
		case "old_original":
			if err := dropFileOrDir(path.Join(global.CONF.System.BaseDir, oldOriginalPath, item.Name)); err != nil {
				return err
			}
		case "old_apps_bak":
			if err := dropFileOrDir(path.Join(global.CONF.System.BaseDir, oldAppBackupPath, item.Name)); err != nil {
				return err
			}
		case "old_download":
			if err := dropFileOrDir(path.Join(global.CONF.System.BaseDir, oldDownloadPath, item.Name)); err != nil {
				return err
			}
		case "old_upgrade":
			if len(item.Name) == 0 {
				files, _ := os.ReadDir(path.Join(global.CONF.System.BaseDir, oldUpgradePath))
				if len(files) == 0 {
					continue
				}
				for _, file := range files {
					if strings.HasPrefix(file.Name(), "upgrade_") {
						if err := dropFileOrDir(path.Join(global.CONF.System.BaseDir, oldUpgradePath, file.Name())); err != nil {
							return err
						}
					}
				}
			} else {
				if err := dropFileOrDir(path.Join(global.CONF.System.BaseDir, oldUpgradePath, item.Name)); err != nil {
					return err
				}
			}

		case "upload":
			if err := dropFileOrDir(path.Join(global.CONF.System.BaseDir, uploadPath, item.Name)); err != nil {
				return err
			}
			if len(item.Name) == 0 {
				if err := dropFileOrDir(path.Join(global.CONF.System.BaseDir, tmpUploadPath)); err != nil {
					return err
				}
			}
		case "upload_tmp":
			if err := dropFileOrDir(path.Join(global.CONF.System.BaseDir, tmpUploadPath, item.Name)); err != nil {
				return err
			}
		case "upload_app":
			if err := dropFileOrDir(path.Join(global.CONF.System.BaseDir, uploadPath, "app", item.Name)); err != nil {
				return err
			}
		case "upload_database":
			if err := dropFileOrDir(path.Join(global.CONF.System.BaseDir, uploadPath, "database", item.Name)); err != nil {
				return err
			}
		case "upload_website":
			if err := dropFileOrDir(path.Join(global.CONF.System.BaseDir, uploadPath, "website", item.Name)); err != nil {
				return err
			}
		case "upload_directory":
			if err := dropFileOrDir(path.Join(global.CONF.System.BaseDir, uploadPath, "directory", item.Name)); err != nil {
				return err
			}
		case "download":
			if err := dropFileOrDir(path.Join(global.CONF.System.BaseDir, downloadPath, item.Name)); err != nil {
				return err
			}
		case "download_app":
			if err := dropFileOrDir(path.Join(global.CONF.System.BaseDir, downloadPath, "app", item.Name)); err != nil {
				return err
			}
		case "download_database":
			if err := dropFileOrDir(path.Join(global.CONF.System.BaseDir, downloadPath, "database", item.Name)); err != nil {
				return err
			}
		case "download_website":
			if err := dropFileOrDir(path.Join(global.CONF.System.BaseDir, downloadPath, "website", item.Name)); err != nil {
				return err
			}
		case "download_directory":
			if err := dropFileOrDir(path.Join(global.CONF.System.BaseDir, downloadPath, "directory", item.Name)); err != nil {
				return err
			}

		case "system_log":
			if len(item.Name) == 0 {
				files, _ := os.ReadDir(path.Join(global.CONF.System.BaseDir, logPath))
				if len(files) == 0 {
					continue
				}
				for _, file := range files {
					if file.Name() == "1Panel.log" || file.IsDir() {
						continue
					}
					if err := dropFileOrDir(path.Join(global.CONF.System.BaseDir, logPath, file.Name())); err != nil {
						return err
					}
				}
			} else {
				if err := dropFileOrDir(path.Join(global.CONF.System.BaseDir, logPath, item.Name)); err != nil {
					return err
				}
			}
		case "docker_log":
			if err := dropFileOrDir(path.Join(global.CONF.System.BaseDir, dockerLogPath, item.Name)); err != nil {
				return err
			}
		case "task_log":
			pathItem := path.Join(global.CONF.System.BaseDir, taskPath, item.Name)
			if err := dropFileOrDir(path.Join(global.CONF.System.BaseDir, taskPath, item.Name)); err != nil {
				return err
			}
			if len(item.Name) == 0 {
				files, _ := os.ReadDir(pathItem)
				if len(files) == 0 {
					continue
				}
				for _, file := range files {
					_ = cronjobRepo.DeleteRecord(cronjobRepo.WithByRecordFile(path.Join(pathItem, file.Name())))
				}
			} else {
				_ = cronjobRepo.DeleteRecord(cronjobRepo.WithByRecordFile(pathItem))
			}
		case "images":
			dropImages()
		case "containers":
			dropContainers()
		case "volumes":
			dropVolumes()
		case "build_cache":
			dropBuildCache()
		}
	}

	_ = settingRepo.Update("LastCleanTime", time.Now().Format(constant.DateTimeLayout))
	_ = settingRepo.Update("LastCleanSize", fmt.Sprintf("%v", size))
	_ = settingRepo.Update("LastCleanData", fmt.Sprintf("%v", len(req)))

	if restart {
		go func() {
			err := systemctl.Restart("1panel")
			if err != nil {
				global.LOG.Errorf("restart system port failed, err: %v", err)
			}
		}()
	}
	return nil
}

func (u *DeviceService) CleanForCronjob() (string, error) {
	logs := ""
	size := int64(0)
	fileCount := 0
	dropFileOrDirWithLog(path.Join(global.CONF.System.BaseDir, "1panel_original"), &logs, &size, &fileCount)

	upgradePath := path.Join(global.CONF.System.BaseDir, upgradePath)
	upgradeFiles, _ := os.ReadDir(upgradePath)
	if len(upgradeFiles) != 0 {
		sort.Slice(upgradeFiles, func(i, j int) bool {
			return upgradeFiles[i].Name() > upgradeFiles[j].Name()
		})
		for i := 0; i < len(upgradeFiles); i++ {
			if i != 0 {
				dropFileOrDirWithLog(path.Join(upgradePath, upgradeFiles[i].Name()), &logs, &size, &fileCount)
			}
		}
	}

	dropFileOrDirWithLog(path.Join(global.CONF.System.BaseDir, snapshotTmpPath), &logs, &size, &fileCount)
	dropFileOrDirWithLog(path.Join(global.CONF.System.Backup, "system"), &logs, &size, &fileCount)

	dropFileOrDirWithLog(path.Join(global.CONF.System.BaseDir, rollbackPath, "app"), &logs, &size, &fileCount)
	dropFileOrDirWithLog(path.Join(global.CONF.System.BaseDir, rollbackPath, "website"), &logs, &size, &fileCount)
	dropFileOrDirWithLog(path.Join(global.CONF.System.BaseDir, rollbackPath, "database"), &logs, &size, &fileCount)

	dropFileOrDirWithLog(path.Join(global.CONF.System.BaseDir, oldOriginalPath), &logs, &size, &fileCount)
	dropFileOrDirWithLog(path.Join(global.CONF.System.BaseDir, oldAppBackupPath), &logs, &size, &fileCount)
	dropFileOrDirWithLog(path.Join(global.CONF.System.BaseDir, oldDownloadPath), &logs, &size, &fileCount)
	oldUpgradePath := path.Join(global.CONF.System.BaseDir, oldUpgradePath)
	oldUpgradeFiles, _ := os.ReadDir(oldUpgradePath)
	if len(oldUpgradeFiles) != 0 {
		for i := 0; i < len(oldUpgradeFiles); i++ {
			dropFileOrDirWithLog(path.Join(oldUpgradePath, oldUpgradeFiles[i].Name()), &logs, &size, &fileCount)
		}
	}

	dropFileOrDirWithLog(path.Join(global.CONF.System.BaseDir, tmpUploadPath), &logs, &size, &fileCount)
	dropFileOrDirWithLog(path.Join(global.CONF.System.BaseDir, uploadPath), &logs, &size, &fileCount)
	dropFileOrDirWithLog(path.Join(global.CONF.System.BaseDir, downloadPath), &logs, &size, &fileCount)

	logPath := path.Join(global.CONF.System.BaseDir, logPath)
	logFiles, _ := os.ReadDir(logPath)
	if len(logFiles) != 0 {
		for i := 0; i < len(logFiles); i++ {
			if logFiles[i].Name() != "1Panel.log" {
				dropFileOrDirWithLog(path.Join(logPath, logFiles[i].Name()), &logs, &size, &fileCount)
			}
		}
	}
	timeNow := time.Now().Format(constant.DateTimeLayout)
	dropFileOrDirWithLog(path.Join(global.CONF.System.BaseDir, dockerLogPath), &logs, &size, &fileCount)
	logs += fmt.Sprintf("\n%s: total clean: %s, total count: %d", timeNow, common.LoadSizeUnit2F(float64(size)), fileCount)

	_ = settingRepo.Update("LastCleanTime", timeNow)
	_ = settingRepo.Update("LastCleanSize", fmt.Sprintf("%v", size))
	_ = settingRepo.Update("LastCleanData", fmt.Sprintf("%v", fileCount))

	return logs, nil
}

func loadSnapshotTree(fileOp fileUtils.FileOp) []dto.CleanTree {
	var treeData []dto.CleanTree
	path1 := path.Join(global.CONF.System.BaseDir, snapshotTmpPath)
	list1 := loadTreeWithAllFile(true, path1, "snapshot_tmp", path1, fileOp)
	if len(list1) != 0 {
		size, _ := fileOp.GetDirSize(path1)
		treeData = append(treeData, dto.CleanTree{ID: uuid.NewString(), Label: "snapshot_tmp", Size: uint64(size), Children: list1, Type: "snapshot_tmp", IsRecommend: true})
	}

	path2 := path.Join(global.CONF.System.Backup, "system")
	list2 := loadTreeWithAllFile(true, path2, "snapshot_local", path2, fileOp)
	if len(list2) != 0 {
		size, _ := fileOp.GetDirSize(path2)
		treeData = append(treeData, dto.CleanTree{ID: uuid.NewString(), Label: "snapshot_local", Size: uint64(size), Children: list2, Type: "snapshot_local", IsRecommend: true})
	}
	return treeData
}

func loadRollBackTree(fileOp fileUtils.FileOp) []dto.CleanTree {
	var treeData []dto.CleanTree
	path1 := path.Join(global.CONF.System.BaseDir, rollbackPath, "app")
	list1 := loadTreeWithAllFile(true, path1, "rollback_app", path1, fileOp)
	size1, _ := fileOp.GetDirSize(path1)
	treeData = append(treeData, dto.CleanTree{ID: uuid.NewString(), Label: "rollback_app", Size: uint64(size1), Children: list1, Type: "rollback_app", IsRecommend: true})

	path2 := path.Join(global.CONF.System.BaseDir, rollbackPath, "website")
	list2 := loadTreeWithAllFile(true, path2, "rollback_website", path2, fileOp)
	size2, _ := fileOp.GetDirSize(path2)
	treeData = append(treeData, dto.CleanTree{ID: uuid.NewString(), Label: "rollback_website", Size: uint64(size2), Children: list2, Type: "rollback_website", IsRecommend: true})

	path3 := path.Join(global.CONF.System.BaseDir, rollbackPath, "database")
	list3 := loadTreeWithAllFile(true, path3, "rollback_database", path3, fileOp)
	size3, _ := fileOp.GetDirSize(path3)
	treeData = append(treeData, dto.CleanTree{ID: uuid.NewString(), Label: "rollback_database", Size: uint64(size3), Children: list3, Type: "rollback_database", IsRecommend: true})

	return treeData
}

func loadUnusedFile(fileOp fileUtils.FileOp) []dto.CleanTree {
	var treeData []dto.CleanTree
	path1 := path.Join(global.CONF.System.BaseDir, oldOriginalPath)
	list1 := loadTreeWithAllFile(true, path1, "old_original", path1, fileOp)
	if len(list1) != 0 {
		size, _ := fileOp.GetDirSize(path1)
		treeData = append(treeData, dto.CleanTree{ID: uuid.NewString(), Label: "old_original", Size: uint64(size), Children: list1, Type: "old_original"})
	}

	path2 := path.Join(global.CONF.System.BaseDir, oldAppBackupPath)
	list2 := loadTreeWithAllFile(true, path2, "old_apps_bak", path2, fileOp)
	if len(list2) != 0 {
		size, _ := fileOp.GetDirSize(path2)
		treeData = append(treeData, dto.CleanTree{ID: uuid.NewString(), Label: "old_apps_bak", Size: uint64(size), Children: list2, Type: "old_apps_bak"})
	}

	path3 := path.Join(global.CONF.System.BaseDir, oldDownloadPath)
	list3 := loadTreeWithAllFile(true, path3, "old_download", path3, fileOp)
	if len(list3) != 0 {
		size, _ := fileOp.GetDirSize(path3)
		treeData = append(treeData, dto.CleanTree{ID: uuid.NewString(), Label: "old_download", Size: uint64(size), Children: list3, Type: "old_download"})
	}

	path4 := path.Join(global.CONF.System.BaseDir, oldUpgradePath)
	list4 := loadTreeWithDir(true, "old_upgrade", path4, fileOp)
	itemSize := uint64(0)
	for _, item := range list4 {
		itemSize += item.Size
	}
	if len(list4) != 0 {
		treeData = append(treeData, dto.CleanTree{ID: uuid.NewString(), Label: "old_upgrade", Size: itemSize, Children: list4, Type: "old_upgrade"})
	}
	return treeData
}

func loadUploadTree(fileOp fileUtils.FileOp) []dto.CleanTree {
	var treeData []dto.CleanTree

	path0 := path.Join(global.CONF.System.BaseDir, tmpUploadPath)
	list0 := loadTreeWithAllFile(true, path0, "upload_tmp", path0, fileOp)
	size0, _ := fileOp.GetDirSize(path0)
	treeData = append(treeData, dto.CleanTree{ID: uuid.NewString(), Label: "upload_tmp", Size: uint64(size0), Children: list0, Type: "upload_tmp", IsRecommend: true})

	path1 := path.Join(global.CONF.System.BaseDir, uploadPath, "app")
	list1 := loadTreeWithAllFile(true, path1, "upload_app", path1, fileOp)
	size1, _ := fileOp.GetDirSize(path1)
	treeData = append(treeData, dto.CleanTree{ID: uuid.NewString(), Label: "upload_app", Size: uint64(size1), Children: list1, Type: "upload_app", IsRecommend: true})

	path2 := path.Join(global.CONF.System.BaseDir, uploadPath, "website")
	list2 := loadTreeWithAllFile(true, path2, "upload_website", path2, fileOp)
	size2, _ := fileOp.GetDirSize(path2)
	treeData = append(treeData, dto.CleanTree{ID: uuid.NewString(), Label: "upload_website", Size: uint64(size2), Children: list2, Type: "upload_website", IsRecommend: true})

	path3 := path.Join(global.CONF.System.BaseDir, uploadPath, "database")
	list3 := loadTreeWithAllFile(true, path3, "upload_database", path3, fileOp)
	size3, _ := fileOp.GetDirSize(path3)
	treeData = append(treeData, dto.CleanTree{ID: uuid.NewString(), Label: "upload_database", Size: uint64(size3), Children: list3, Type: "upload_database", IsRecommend: true})

	path4 := path.Join(global.CONF.System.BaseDir, uploadPath, "directory")
	list4 := loadTreeWithAllFile(true, path4, "upload_directory", path4, fileOp)
	size4, _ := fileOp.GetDirSize(path4)
	treeData = append(treeData, dto.CleanTree{ID: uuid.NewString(), Label: "upload_directory", Size: uint64(size4), Children: list4, Type: "upload_directory", IsRecommend: true})

	path5 := path.Join(global.CONF.System.BaseDir, uploadPath)
	uploadTreeData := loadTreeWithAllFile(true, path5, "upload", path5, fileOp)
	treeData = append(treeData, uploadTreeData...)

	return treeData
}

func loadDownloadTree(fileOp fileUtils.FileOp) []dto.CleanTree {
	var treeData []dto.CleanTree
	path1 := path.Join(global.CONF.System.BaseDir, downloadPath, "app")
	list1 := loadTreeWithAllFile(true, path1, "download_app", path1, fileOp)
	size1, _ := fileOp.GetDirSize(path1)
	treeData = append(treeData, dto.CleanTree{ID: uuid.NewString(), Label: "download_app", Size: uint64(size1), Children: list1, Type: "download_app", IsRecommend: true})

	path2 := path.Join(global.CONF.System.BaseDir, downloadPath, "website")
	list2 := loadTreeWithAllFile(true, path2, "download_website", path2, fileOp)
	size2, _ := fileOp.GetDirSize(path2)
	treeData = append(treeData, dto.CleanTree{ID: uuid.NewString(), Label: "download_website", Size: uint64(size2), Children: list2, Type: "download_website", IsRecommend: true})

	path3 := path.Join(global.CONF.System.BaseDir, downloadPath, "database")
	list3 := loadTreeWithAllFile(true, path3, "download_database", path3, fileOp)
	size3, _ := fileOp.GetDirSize(path3)
	treeData = append(treeData, dto.CleanTree{ID: uuid.NewString(), Label: "download_database", Size: uint64(size3), Children: list3, Type: "download_database", IsRecommend: true})

	path4 := path.Join(global.CONF.System.BaseDir, downloadPath, "directory")
	list4 := loadTreeWithAllFile(true, path4, "download_directory", path4, fileOp)
	size4, _ := fileOp.GetDirSize(path4)
	treeData = append(treeData, dto.CleanTree{ID: uuid.NewString(), Label: "download_directory", Size: uint64(size4), Children: list4, Type: "download_directory", IsRecommend: true})

	path5 := path.Join(global.CONF.System.BaseDir, downloadPath)
	uploadTreeData := loadTreeWithAllFile(true, path5, "download", path5, fileOp)
	treeData = append(treeData, uploadTreeData...)

	return treeData
}

func loadLogTree(fileOp fileUtils.FileOp) []dto.CleanTree {
	var treeData []dto.CleanTree
	path1 := path.Join(global.CONF.System.BaseDir, logPath)
	list1 := loadTreeWithAllFile(true, path1, "system_log", path1, fileOp)
	size := uint64(0)
	for _, file := range list1 {
		size += file.Size
	}
	treeData = append(treeData, dto.CleanTree{ID: uuid.NewString(), Label: "system_log", Size: uint64(size), Children: list1, Type: "system_log", IsRecommend: true})

	path2 := path.Join(global.CONF.System.BaseDir, dockerLogPath)
	list2 := loadTreeWithAllFile(true, path2, "docker_log", path2, fileOp)
	size2, _ := fileOp.GetDirSize(path2)
	treeData = append(treeData, dto.CleanTree{ID: uuid.NewString(), Label: "docker_log", Size: uint64(size2), Children: list2, Type: "docker_log", IsRecommend: true})

	path3 := path.Join(global.CONF.System.BaseDir, taskPath)
	list3 := loadTreeWithAllFile(false, path3, "task_log", path3, fileOp)
	size3, _ := fileOp.GetDirSize(path3)
	treeData = append(treeData, dto.CleanTree{ID: uuid.NewString(), Label: "task_log", Size: uint64(size3), Children: list3, Type: "task_log"})
	return treeData
}

func loadContainerTree() []dto.CleanTree {
	var treeData []dto.CleanTree
	client, err := docker.NewDockerClient()
	if err != nil {
		return treeData
	}
	defer client.Close()
	diskUsage, err := client.DiskUsage(context.Background(), types.DiskUsageOptions{})
	if err != nil {
		return treeData
	}
	imageSize := uint64(0)
	for _, file := range diskUsage.Images {
		if file.Containers == 0 {
			imageSize += uint64(file.Size)
		}
	}
	treeData = append(treeData, dto.CleanTree{ID: uuid.NewString(), Label: "container_images", Size: imageSize, Children: nil, Type: "images", IsRecommend: true})

	containerSize := uint64(0)
	for _, file := range diskUsage.Containers {
		if file.State != "running" {
			containerSize += uint64(file.SizeRw)
		}
	}
	treeData = append(treeData, dto.CleanTree{ID: uuid.NewString(), Label: "container_containers", Size: containerSize, Children: nil, Type: "containers", IsRecommend: true})

	volumeSize := uint64(0)
	for _, file := range diskUsage.Volumes {
		if file.UsageData.RefCount <= 0 {
			volumeSize += uint64(file.UsageData.Size)
		}
	}
	treeData = append(treeData, dto.CleanTree{ID: uuid.NewString(), Label: "container_volumes", Size: volumeSize, Children: nil, Type: "volumes", IsRecommend: true})

	var buildCacheTotalSize int64
	for _, cache := range diskUsage.BuildCache {
		if cache.Type == "source.local" {
			buildCacheTotalSize += cache.Size
		}
	}
	treeData = append(treeData, dto.CleanTree{ID: uuid.NewString(), Label: "build_cache", Size: uint64(buildCacheTotalSize), Type: "build_cache", IsRecommend: true})
	return treeData
}

func loadTreeWithDir(isCheck bool, treeType, pathItem string, fileOp fileUtils.FileOp) []dto.CleanTree {
	var lists []dto.CleanTree
	files, err := os.ReadDir(pathItem)
	if err != nil {
		return lists
	}
	sort.Slice(files, func(i, j int) bool {
		return files[i].Name() > files[j].Name()
	})
	for _, file := range files {
		if (treeType == "old_upgrade" || treeType == "upgrade") && !strings.HasPrefix(file.Name(), "upgrade_2023") {
			continue
		}
		if file.IsDir() {
			size, err := fileOp.GetDirSize(path.Join(pathItem, file.Name()))
			if err != nil {
				continue
			}
			item := dto.CleanTree{
				ID:          uuid.NewString(),
				Label:       file.Name(),
				Type:        treeType,
				Size:        uint64(size),
				Name:        strings.TrimPrefix(file.Name(), "/"),
				IsCheck:     isCheck,
				IsRecommend: isCheck,
			}
			if treeType == "upgrade" && len(lists) == 0 {
				item.IsCheck = false
				item.IsRecommend = false
			}
			lists = append(lists, item)
		}
	}
	return lists
}

func loadTreeWithAllFile(isCheck bool, originalPath, treeType, pathItem string, fileOp fileUtils.FileOp) []dto.CleanTree {
	var lists []dto.CleanTree

	files, err := os.ReadDir(pathItem)
	if err != nil {
		return lists
	}
	for _, file := range files {
		if treeType == "system_log" && (file.Name() == "1Panel.log" || file.IsDir()) {
			continue
		}
		if (treeType == "upload" || treeType == "download") && file.IsDir() && (file.Name() == "app" || file.Name() == "database" || file.Name() == "website" || file.Name() == "directory") {
			continue
		}
		size := uint64(0)
		name := strings.TrimPrefix(path.Join(pathItem, file.Name()), originalPath+"/")
		if file.IsDir() {
			sizeItem, err := fileOp.GetDirSize(path.Join(pathItem, file.Name()))
			if err != nil {
				continue
			}
			size = uint64(sizeItem)
		} else {
			fileInfo, err := file.Info()
			if err != nil {
				continue
			}
			size = uint64(fileInfo.Size())
		}
		item := dto.CleanTree{
			ID:          uuid.NewString(),
			Label:       file.Name(),
			Type:        treeType,
			Size:        uint64(size),
			Name:        name,
			IsCheck:     isCheck,
			IsRecommend: isCheck,
		}
		if file.IsDir() {
			item.Children = loadTreeWithAllFile(isCheck, originalPath, treeType, path.Join(pathItem, file.Name()), fileOp)
		}
		lists = append(lists, item)
	}
	return lists
}

// checkCleanName 校验磁盘清理请求中的 item.Name 是否可安全拼接到各分类目录之下，防止路径穿越。
//
// 合法的 Name 只有两类：
//   - 空字符串：表示清理整个分类目录（前端勾选分类根节点时提交，多个 case 依赖 len(Name)==0 分支）；
//   - 相对路径形式的名称：Scan（loadTreeWithAllFile）对子级节点会生成形如 "子目录/文件名" 的相对路径，
//     且上传文件、任务名等可能包含中文、空格等字符，故不做字符白名单限制（utils/files.ValidNameComponent
//     的白名单会误伤这类合法名称；SanitizeFilename 则禁止 "/"，同样不适用）。
//
// 绝对路径、"."、".." 路径分量、反斜杠、空白名称以及 NUL 等控制字符一律拒绝。
func checkCleanName(name string) error {
	if name == "" {
		return nil
	}
	if strings.TrimSpace(name) == "" {
		return buserr.New(constant.ErrCmdIllegal)
	}
	if strings.HasPrefix(name, "/") || strings.Contains(name, "\\") {
		return buserr.New(constant.ErrCmdIllegal)
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return buserr.New(constant.ErrCmdIllegal)
		}
	}
	for _, comp := range strings.Split(name, "/") {
		if comp == "" || comp == "." || comp == ".." {
			return buserr.New(constant.ErrCmdIllegal)
		}
	}
	return nil
}

// isCleanTargetProtected 基于 file.go 的 isProtectedPath 判断清理目标是否禁止删除。
// 与文件管理器不同，磁盘清理的合法目标几乎都位于面板数据目录 <BaseDir>/1panel 之下
// （如 tmp/upgrade、log、uploads 等），因此仅放开面板数据目录之下（不含本体）的包含判定，
// 其余保护规则（根目录、系统关键目录、回收站目录）与 isProtectedPath 保持一致。
func isCleanTargetProtected(itemPath string) bool {
	if !isProtectedPath(itemPath) {
		return false
	}
	if baseDir := global.CONF.System.BaseDir; baseDir != "" {
		panelDataDir := path.Join(baseDir, "1panel")
		cleanedPath := filepath.Clean(itemPath)
		if cleanedPath == panelDataDir {
			return true
		}
		if strings.HasPrefix(cleanedPath, panelDataDir+"/") {
			return false
		}
	}
	return true
}

func dropFileOrDir(itemPath string) error {
	if isCleanTargetProtected(itemPath) {
		global.LOG.Errorf("drop file %s is a protected path, refuse to delete", itemPath)
		return buserr.New(constant.ErrPathNotDelete)
	}
	global.LOG.Debugf("drop file %s", itemPath)
	if err := os.RemoveAll(itemPath); err != nil {
		global.LOG.Errorf("drop file %s failed, err %v", itemPath, err)
		return err
	}
	return nil
}

func dropBuildCache() {
	client, err := docker.NewDockerClient()
	if err != nil {
		global.LOG.Errorf("do not get docker client")
	}
	defer client.Close()
	opts := types.BuildCachePruneOptions{}
	opts.All = true
	_, err = client.BuildCachePrune(context.Background(), opts)
	if err != nil {
		global.LOG.Errorf("drop build cache failed, err %v", err)
	}
}

func dropImages() {
	client, err := docker.NewDockerClient()
	if err != nil {
		global.LOG.Errorf("do not get docker client")
	}
	defer client.Close()
	pruneFilters := filters.NewArgs()
	pruneFilters.Add("dangling", "false")
	_, err = client.ImagesPrune(context.Background(), pruneFilters)
	if err != nil {
		global.LOG.Errorf("drop images failed, err %v", err)
	}
}

func dropContainers() {
	client, err := docker.NewDockerClient()
	if err != nil {
		global.LOG.Errorf("do not get docker client")
	}
	defer client.Close()
	pruneFilters := filters.NewArgs()
	_, err = client.ContainersPrune(context.Background(), pruneFilters)
	if err != nil {
		global.LOG.Errorf("drop containers failed, err %v", err)
	}
}

func dropVolumes() {
	client, err := docker.NewDockerClient()
	if err != nil {
		global.LOG.Errorf("do not get docker client")
	}
	defer client.Close()
	pruneFilters := filters.NewArgs()
	versions, err := client.ServerVersion(context.Background())
	if err != nil {
		global.LOG.Errorf("do not get docker api versions")
	}
	if common.ComparePanelVersion(versions.APIVersion, "1.42") {
		pruneFilters.Add("all", "true")
	}
	_, err = client.VolumesPrune(context.Background(), pruneFilters)
	if err != nil {
		global.LOG.Errorf("drop volumes failed, err %v", err)
	}
}

func dropFileOrDirWithLog(itemPath string, log *string, size *int64, count *int) {
	itemSize := int64(0)
	itemCount := 0
	scanFile(itemPath, &itemSize, &itemCount)
	*size += itemSize
	*count += itemCount
	if err := os.RemoveAll(itemPath); err != nil {
		global.LOG.Errorf("drop file %s failed, err %v", itemPath, err)
		*log += fmt.Sprintf("- drop file %s failed, err: %v \n\n", itemPath, err)
		return
	}
	*log += fmt.Sprintf("+ drop file %s successful!, size: %s, count: %d \n\n", itemPath, common.LoadSizeUnit2F(float64(itemSize)), itemCount)
}

func scanFile(pathItem string, size *int64, count *int) {
	files, _ := os.ReadDir(pathItem)
	for _, f := range files {
		if f.IsDir() {
			scanFile(path.Join(pathItem, f.Name()), size, count)
		} else {
			fileInfo, err := f.Info()
			if err != nil {
				continue
			}
			*count++
			*size += fileInfo.Size()
		}
	}
}
