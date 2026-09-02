package service

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/1Panel-dev/1Panel/backend/constant"

	"github.com/1Panel-dev/1Panel/backend/buserr"

	"github.com/1Panel-dev/1Panel/backend/app/dto"
	"github.com/1Panel-dev/1Panel/backend/app/model"
	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/1Panel-dev/1Panel/backend/utils/cmd"
	"github.com/1Panel-dev/1Panel/backend/utils/common"
	"github.com/1Panel-dev/1Panel/backend/utils/files"
	"github.com/1Panel-dev/1Panel/backend/utils/mysql/client"
)

func (u *BackupService) MysqlBackup(req dto.CommonBackup) error {
	localDir, err := loadLocalDir()
	if err != nil {
		return err
	}

	timeNow := time.Now().Format(constant.DateTimeSlimLayout)
	itemDir := fmt.Sprintf("database/%s/%s/%s", req.Type, req.Name, req.DetailName)
	targetDir := path.Join(localDir, itemDir)
	fileName := fmt.Sprintf("%s_%s.sql.gz", req.DetailName, timeNow+common.RandStrAndNum(5))

	if err := handleMysqlBackup(req.Name, req.Type, req.DetailName, targetDir, fileName); err != nil {
		return err
	}

	record := &model.BackupRecord{
		Type:       req.Type,
		Name:       req.Name,
		DetailName: req.DetailName,
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

func (u *BackupService) MysqlRecover(req dto.CommonRecover) error {
	if err := validateMysqlRecoverTarget(&req); err != nil {
		return err
	}
	if err := handleMysqlRecover(req, false); err != nil {
		return err
	}
	return nil
}

func (u *BackupService) MysqlRecoverByUpload(req dto.CommonRecover) error {
	file := req.File
	fileName := path.Base(req.File)
	if strings.HasSuffix(fileName, ".tar.gz") {
		fileNameItem := time.Now().Format(constant.DateTimeSlimLayout)
		dstDir := fmt.Sprintf("%s/%s", path.Dir(req.File), fileNameItem)
		if _, err := os.Stat(dstDir); err != nil && os.IsNotExist(err) {
			if err = os.MkdirAll(dstDir, os.ModePerm); err != nil {
				return fmt.Errorf("mkdir %s failed, err: %v", dstDir, err)
			}
		}
		if err := handleUnTar(req.File, dstDir, ""); err != nil {
			_ = os.RemoveAll(dstDir)
			return err
		}
		global.LOG.Infof("decompress file %s successful, now start to check test.sql is exist", req.File)
		hasTestSql := false
		_ = filepath.Walk(dstDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if !info.IsDir() && info.Name() == "test.sql" {
				hasTestSql = true
				file = path
				fileName = "test.sql"
			}
			return nil
		})
		if !hasTestSql {
			_ = os.RemoveAll(dstDir)
			return fmt.Errorf("no such file named test.sql in %s", fileName)
		}
		defer func() {
			_ = os.RemoveAll(dstDir)
		}()
	}

	req.File = path.Dir(file) + "/" + fileName
	if err := validateMysqlRecoverTarget(&req); err != nil {
		return err
	}
	if err := handleMysqlRecover(req, false); err != nil {
		return err
	}
	global.LOG.Info("recover from uploads successful!")
	return nil
}

// validateMysqlRecoverTarget validates the values that handleMysqlRecover
// turns into SQL identifiers (DROP/CREATE DATABASE `...`, mysqldump/mysql
// `-d <name>`): only panel-recorded database rows may be targeted. The name
// (db.Name) and the owning connection record (req.Name == db.MysqlName, see
// mysqlRepo.Get below) are both re-read from the DB inside handleMysqlRecover,
// so a crafted req that names a legal-but-not-deleted database row can only
// ever address that row's own database - never an arbitrary server database.
// req.File also gets a light sanity check (it must exist as a regular file;
// ReadFile/Recover would reject the rest).
func validateMysqlRecoverTarget(req *dto.CommonRecover) error {
	if req == nil || req.Name == "" || req.DetailName == "" {
		return buserr.New(constant.ErrCmdIllegal)
	}
	if !cmd.ValidDBName(req.DetailName) {
		return buserr.New(constant.ErrCmdIllegal)
	}
	dbInfo, err := mysqlRepo.Get(commonRepo.WithByName(req.DetailName), mysqlRepo.WithByMysqlName(req.Name))
	if err != nil {
		return err
	}
	if dbInfo.IsDelete {
		return constant.ErrRecordNotFound
	}
	if req.File == "" {
		return buserr.New(constant.ErrCmdIllegal)
	}
	fi, err := os.Stat(req.File)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return buserr.WithName("ErrFileNotFound", req.File)
	}
	return nil
}

func handleMysqlBackup(database, dbType, dbName, targetDir, fileName string) error {
	dbInfo, err := mysqlRepo.Get(commonRepo.WithByName(dbName), mysqlRepo.WithByMysqlName(database))
	if err != nil {
		return err
	}
	cli, version, err := LoadMysqlClientByFrom(database)
	if err != nil {
		return err
	}

	backupInfo := client.BackupInfo{
		Name:      dbName,
		Type:      dbType,
		Version:   version,
		Format:    dbInfo.Format,
		TargetDir: targetDir,
		FileName:  fileName,

		Timeout: 300,
	}
	if err := cli.Backup(backupInfo); err != nil {
		return err
	}
	return nil
}

func handleMysqlRecover(req dto.CommonRecover, isRollback bool) error {
	isOk := false
	var rollbackFile string
	fileOp := files.NewFileOp()
	if !fileOp.Stat(req.File) {
		return buserr.WithName("ErrFileNotFound", req.File)
	}
	dbInfo, err := mysqlRepo.Get(commonRepo.WithByName(req.DetailName), mysqlRepo.WithByMysqlName(req.Name))
	if err != nil {
		return err
	}
	cli, version, err := LoadMysqlClientByFrom(req.Name)
	if err != nil {
		return err
	}
	defer cli.Close()

	if !isRollback {
		// A random suffix (same style as regular backups) keeps two recovers
		// started in the same second from overwriting each other's rollback
		// file (the rollback snapshot of the second run would silently shadow
		// the first one's).
		rollbackFile = path.Join(global.CONF.System.TmpDir, fmt.Sprintf("database/%s/%s", req.Type, dbRollbackFileName(req.DetailName, "sql.gz")))
		if err := cli.Backup(client.BackupInfo{
			Name:      req.DetailName,
			Type:      req.Type,
			Version:   version,
			Format:    dbInfo.Format,
			TargetDir: path.Dir(rollbackFile),
			FileName:  path.Base(rollbackFile),

			Timeout: 300,
		}); err != nil {
			return fmt.Errorf("backup mysql db %s for rollback before recover failed, err: %v", req.DetailName, err)
		}
		defer func() {
			if !isOk {
				// The failed import may have left the database partially
				// overwritten (a plain mysql client import is not
				// transactional). Re-importing the pre-recover snapshot over
				// that state can itself fail (duplicate keys on re-created
				// rows, dropped objects, ...), so never report a silent
				// rollback: the target database may be incomplete afterwards.
				global.LOG.Info("recover failed, start to rollback now")
				if err := cli.Recover(client.RecoverInfo{
					Name:       req.DetailName,
					Type:       req.Type,
					Version:    version,
					Format:     dbInfo.Format,
					SourceFile: rollbackFile,

					Timeout: 300,
				}); err != nil {
					global.LOG.Errorf("rollback mysql db %s from %s failed, err: %v", req.DetailName, rollbackFile, err)
					global.LOG.Errorf("database %s may be left in a partial state after the failed recover and rollback", req.DetailName)
				} else {
					global.LOG.Infof("rollback mysql db %s from %s successful", req.DetailName, rollbackFile)
				}
			}
			_ = os.RemoveAll(rollbackFile)
		}()
	}

	if req.Type == constant.AppMariaDB || dbInfo.MysqlName != req.Name {
		// mariadb and any non-record path: keep the historical behavior of
		// importing on top of the live database (still guarded by the
		// validateMysqlRecoverTarget checks and the rollback above).
		if err := cli.Recover(client.RecoverInfo{
			Name:       req.DetailName,
			Type:       req.Type,
			Version:    version,
			Format:     dbInfo.Format,
			SourceFile: req.File,

			Timeout: 300,
		}); err != nil {
			global.LOG.Errorf("recover mysql db %s from %s failed, err: %v", req.DetailName, req.File, err)
			return err
		}
		isOk = true
		return nil
	}

	// Fast path used for local databases only (the remote client runs with
	// the remote server's root connection and is skipped above): the database
	// is a row created by the panel, so we can re-create it empty before the
	// import. A failed import then leaves an EMPTY database behind instead of
	// a half-imported one - the pre-recover snapshot is still available in
	// the rollback file, and re-importing it over an empty database is far
	// less likely to fail than over a partially imported one.
	dropAndCreateErr := func() error {
		if _, ok := cli.(*client.Local); !ok {
			return nil
		}
		dropSQL := fmt.Sprintf("drop database if exists `%s`", req.DetailName)
		if err := cli.ExecSQL(dropSQL, 300); err != nil {
			return err
		}
		createSQL := fmt.Sprintf("create database `%s` default character set %s collate %s", req.DetailName, dbInfo.Format, mysqlFormatCollation(dbInfo.Format))
		return cli.ExecSQL(createSQL, 300)
	}()
	if dropAndCreateErr != nil {
		global.LOG.Errorf("recreate database %s before recover failed, err: %v", req.DetailName, dropAndCreateErr)
		return dropAndCreateErr
	}
	if err := cli.Recover(client.RecoverInfo{
		Name:       req.DetailName,
		Type:       req.Type,
		Version:    version,
		Format:     dbInfo.Format,
		SourceFile: req.File,

		Timeout: 300,
	}); err != nil {
		global.LOG.Errorf("recover mysql db %s from %s failed, err: %v", req.DetailName, req.File, err)
		global.LOG.Errorf("database %s is left empty or partially imported; the pre-recover snapshot %s is kept for manual restore", req.DetailName, path.Base(rollbackFile))
		return err
	}
	isOk = true
	return nil
}

// mysqlFormatCollation maps a mysql database charset name to the collation
// used by the panel when creating databases (see mysql/client formatMap).
func mysqlFormatCollation(format string) string {
	switch format {
	case "utf8":
		return "utf8_general_ci"
	case "gbk":
		return "gbk_chinese_ci"
	case "big5":
		return "big5_chinese_ci"
	default:
		return "utf8mb4_general_ci"
	}
}
