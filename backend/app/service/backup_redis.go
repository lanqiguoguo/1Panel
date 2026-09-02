package service

import (
	"fmt"
	"os"
	"path"
	"strings"
	"time"

	"github.com/1Panel-dev/1Panel/backend/app/dto"
	"github.com/1Panel-dev/1Panel/backend/app/model"
	"github.com/1Panel-dev/1Panel/backend/app/repo"
	"github.com/1Panel-dev/1Panel/backend/buserr"
	"github.com/1Panel-dev/1Panel/backend/constant"
	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/1Panel-dev/1Panel/backend/utils/cmd"
	"github.com/1Panel-dev/1Panel/backend/utils/common"
	"github.com/1Panel-dev/1Panel/backend/utils/compose"
	"github.com/1Panel-dev/1Panel/backend/utils/files"
	"github.com/pkg/errors"
)

func (u *BackupService) RedisBackup(db dto.CommonBackup) error {
	localDir, err := loadLocalDir()
	if err != nil {
		return err
	}
	redisInfo, err := appInstallRepo.LoadBaseInfo("redis", db.Name)
	if err != nil {
		return err
	}
	appendonly, err := configGetStr(redisInfo.ContainerName, redisInfo.Password, "appendonly")
	if err != nil {
		return err
	}
	global.LOG.Infof("appendonly in redis conf is %s", appendonly)

	timeNow := time.Now().Format(constant.DateTimeSlimLayout) + common.RandStrAndNum(5)
	fileName := fmt.Sprintf("%s.rdb", timeNow)
	if appendonly == "yes" {
		if strings.HasPrefix(redisInfo.Version, "6.") {
			fileName = fmt.Sprintf("%s.aof", timeNow)
		} else {
			fileName = fmt.Sprintf("%s.tar.gz", timeNow)
		}
	}
	itemDir := fmt.Sprintf("database/redis/%s", redisInfo.Name)
	backupDir := path.Join(localDir, itemDir)
	if err := handleRedisBackup(redisInfo, backupDir, fileName, db.Secret); err != nil {
		return err
	}
	record := &model.BackupRecord{
		Type:       "redis",
		Name:       db.Name,
		Source:     "LOCAL",
		BackupType: "LOCAL",
		FileDir:    itemDir,
		FileName:   fileName,
	}
	if err := backupRepo.CreateRecord(record); err != nil {
		global.LOG.Errorf("save backup record failed, err: %v", err)
	}

	return nil
}

func (u *BackupService) RedisRecover(req dto.CommonRecover) error {
	redisInfo, err := appInstallRepo.LoadBaseInfo("redis", req.Name)
	if err != nil {
		return err
	}
	global.LOG.Infof("recover redis from backup file %s", req.File)
	if err := handleRedisRecover(redisInfo, req.File, false, req.Secret); err != nil {
		return err
	}
	return nil
}

func handleRedisBackup(redisInfo *repo.RootInfo, backupDir, fileName string, secret string) error {
	fileOp := files.NewFileOp()
	if !fileOp.Stat(backupDir) {
		// 0750, not os.ModePerm (0777): the rdb/aof dump holds the whole
		// redis dataset and must not be readable by other local users.
		if err := os.MkdirAll(backupDir, 0750); err != nil {
			return fmt.Errorf("mkdir %s failed, err: %v", backupDir, err)
		}
	}
	backupFile := path.Join(backupDir, fileName)

	// The password is handed to redis-cli through the REDISCLI_AUTH env var
	// via `docker exec --env-file` (redis >= 6), so it never appears in the
	// world-readable process argv of the docker exec command.
	envFile, err := cmd.WriteDockerEnvFile(global.CONF.System.TmpDir, map[string]string{"REDISCLI_AUTH": redisInfo.Password})
	if err != nil {
		return err
	}
	defer os.Remove(envFile)
	stdout, err := cmd.Execf("docker exec --env-file %s %s redis-cli --no-auth-warning save", envFile, redisInfo.ContainerName)
	if err != nil {
		return errors.New(string(stdout))
	}

	if strings.HasSuffix(fileName, ".tar.gz") {
		redisDataDir := fmt.Sprintf("%s/%s/%s/data/appendonlydir", constant.AppInstallDir, "redis", redisInfo.Name)
		if err := handleTar(redisDataDir, backupDir, fileName, "", secret); err != nil {
			// Never leave a half-archived dump behind on a failed path.
			_ = os.RemoveAll(backupFile)
			return err
		}
		return nil
	}
	if strings.HasSuffix(fileName, ".aof") {
		stdout1, err := cmd.Execf("docker cp %s:/data/appendonly.aof %s/%s", redisInfo.ContainerName, backupDir, fileName)
		if err != nil {
			_ = os.RemoveAll(backupFile)
			return errors.New(string(stdout1))
		}
		return nil
	}

	stdout1, err1 := cmd.Execf("docker cp %s:/data/dump.rdb %s/%s", redisInfo.ContainerName, backupDir, fileName)
	if err1 != nil {
		_ = os.RemoveAll(backupFile)
		return errors.New(string(stdout1))
	}
	return nil
}

func handleRedisRecover(redisInfo *repo.RootInfo, recoverFile string, isRollback bool, secret string) error {
	fileOp := files.NewFileOp()
	if !fileOp.Stat(recoverFile) {
		return buserr.WithName("ErrFileNotFound", recoverFile)
	}

	appendonly, err := configGetStr(redisInfo.ContainerName, redisInfo.Password, "appendonly")
	if err != nil {
		return err
	}

	if appendonly == "yes" {
		if strings.HasPrefix(redisInfo.Version, "6.") && !strings.HasSuffix(recoverFile, ".aof") {
			return buserr.New(constant.ErrTypeOfRedis)
		}
		if strings.HasPrefix(redisInfo.Version, "7.") && !strings.HasSuffix(recoverFile, ".tar.gz") {
			return buserr.New(constant.ErrTypeOfRedis)
		}
	} else {
		if !strings.HasSuffix(recoverFile, ".rdb") {
			return buserr.New(constant.ErrTypeOfRedis)
		}
	}

	global.LOG.Infof("appendonly in redis conf is %s", appendonly)
	isOk := false
	composeDir := fmt.Sprintf("%s/redis/%s", constant.AppInstallDir, redisInfo.Name)
	composeFile := composeDir + "/docker-compose.yml"

	var rollbackFile string
	if !isRollback {
		suffix := "rdb"
		if appendonly == "yes" {
			if strings.HasPrefix(redisInfo.Version, "6.") {
				suffix = "aof"
			} else {
				suffix = "tar.gz"
			}
		}
		// A random suffix (same style as regular backups) keeps two recovers
		// started in the same second from overwriting each other's rollback
		// file.
		rollbackFile = path.Join(global.CONF.System.TmpDir, "database/redis", dbRollbackFileName(redisInfo.Name, suffix))
		if err := handleRedisBackup(redisInfo, path.Dir(rollbackFile), path.Base(rollbackFile), secret); err != nil {
			return fmt.Errorf("backup database %s for rollback before recover failed, err: %v", redisInfo.Name, err)
		}
		defer func() {
			if !isOk {
				global.LOG.Info("recover failed, start to rollback now")
				if err := handleRedisRecover(redisInfo, rollbackFile, true, secret); err != nil {
					global.LOG.Errorf("rollback redis from %s failed, err: %v", rollbackFile, err)
					// Last-resort bring-up: the recovery failed while the
					// container may still be down (a rollback that itself
					// cannot run compose leaves it stopped). Try to start it
					// with whatever data is in place instead of leaving the
					// instance down until a human intervenes.
					if _, upErr := compose.Up(composeFile); upErr != nil {
						global.LOG.Errorf("restart redis %s after rollback failed, err: %v", redisInfo.Name, upErr)
					}
					return
				}
				global.LOG.Infof("rollback redis from %s successful", rollbackFile)
			}
			_ = os.RemoveAll(rollbackFile)
		}()
	}
	if _, err := compose.Down(composeFile); err != nil {
		// The container is down or was never fully stopped; the data dir was
		// not touched yet, so there is nothing to roll back. Bring the
		// instance back up (Up is idempotent on a running container) instead
		// of returning with the service down.
		if _, upErr := compose.Up(composeFile); upErr != nil {
			global.LOG.Errorf("restart redis %s after down failed, err: %v", redisInfo.Name, upErr)
		}
		return fmt.Errorf("stop redis %s before recover failed, err: %v", redisInfo.Name, err)
	}

	// Replace the data while the container is stopped. Any failure here must
	// not leave the instance down until the deferred rollback runs: try to
	// bring the container back up synchronously (it then serves the old data
	// file, or the partially replaced one, and the deferred rollback restores
	// the pre-recover snapshot as the final state).
	replaceErr := func() error {
		if appendonly == "yes" && strings.HasPrefix(redisInfo.Version, "7.") {
			redisDataDir := fmt.Sprintf("%s/%s/%s/data", constant.AppInstallDir, "redis", redisInfo.Name)
			if err := handleUnTar(recoverFile, redisDataDir, secret); err != nil {
				return err
			}
			return nil
		}
		itemName := "dump.rdb"
		if appendonly == "yes" && strings.HasPrefix(redisInfo.Version, "6.") {
			itemName = "appendonly.aof"
		}
		input, err := os.ReadFile(recoverFile)
		if err != nil {
			return err
		}
		// Write through a same-dir temp file + rename: a plain WriteFile
		// would truncate the live dump.rdb first and leave a half-written
		// file behind (and a redis that refuses to start on it) if the write
		// fails midway.
		tmpData := composeDir + "/data/" + itemName + ".recover.tmp"
		if err := os.WriteFile(tmpData, input, 0640); err != nil {
			_ = os.RemoveAll(tmpData)
			return err
		}
		if err := os.Rename(tmpData, composeDir+"/data/"+itemName); err != nil {
			_ = os.RemoveAll(tmpData)
			return err
		}
		return nil
	}()
	if replaceErr != nil {
		if _, upErr := compose.Up(composeFile); upErr != nil {
			global.LOG.Errorf("restart redis %s after data replace failed, err: %v", redisInfo.Name, upErr)
		}
		return replaceErr
	}
	if _, err := compose.Up(composeFile); err != nil {
		return err
	}
	isOk = true
	return nil
}
