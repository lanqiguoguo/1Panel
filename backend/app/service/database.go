package service

import (
	"context"
	"fmt"
	"path"

	"github.com/1Panel-dev/1Panel/backend/utils/postgresql"
	pgclient "github.com/1Panel-dev/1Panel/backend/utils/postgresql/client"
	redisclient "github.com/1Panel-dev/1Panel/backend/utils/redis"

	"github.com/1Panel-dev/1Panel/backend/app/dto"
	"github.com/1Panel-dev/1Panel/backend/buserr"
	"github.com/1Panel-dev/1Panel/backend/constant"
	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/1Panel-dev/1Panel/backend/utils/cmd"
	"github.com/1Panel-dev/1Panel/backend/utils/encrypt"
	"github.com/1Panel-dev/1Panel/backend/utils/mysql"
	"github.com/1Panel-dev/1Panel/backend/utils/mysql/client"
	"github.com/jinzhu/copier"
	"github.com/pkg/errors"
)

type DatabaseService struct{}

type IDatabaseService interface {
	Get(name string) (dto.DatabaseInfo, error)
	SearchWithPage(search dto.DatabaseSearch) (int64, interface{}, error)
	CheckDatabase(req dto.DatabaseCreate) bool
	Create(req dto.DatabaseCreate) error
	Update(req dto.DatabaseUpdate) error
	DeleteCheck(id uint) ([]string, error)
	Delete(req dto.DatabaseDelete) error
	List(dbType string) ([]dto.DatabaseOption, error)
	LoadItems(dbType string) ([]dto.DatabaseItem, error)
}

func NewIDatabaseService() IDatabaseService {
	return &DatabaseService{}
}

func (u *DatabaseService) SearchWithPage(search dto.DatabaseSearch) (int64, interface{}, error) {
	total, dbs, err := databaseRepo.Page(search.Page, search.PageSize,
		databaseRepo.WithTypeList(search.Type),
		commonRepo.WithLikeName(search.Info),
		commonRepo.WithOrderRuleBy(search.OrderBy, search.Order),
		databaseRepo.WithoutByFrom("local"),
	)
	var datas []dto.DatabaseInfo
	for _, db := range dbs {
		var item dto.DatabaseInfo
		if err := copier.Copy(&item, &db); err != nil {
			return 0, nil, errors.WithMessage(constant.ErrStructTransform, err.Error())
		}
		datas = append(datas, item)
	}
	return total, datas, err
}

func (u *DatabaseService) Get(name string) (dto.DatabaseInfo, error) {
	var data dto.DatabaseInfo
	remote, err := databaseRepo.Get(commonRepo.WithByName(name))
	if err != nil {
		return data, err
	}
	if err := copier.Copy(&data, &remote); err != nil {
		return data, errors.WithMessage(constant.ErrStructTransform, err.Error())
	}
	return data, nil
}

func (u *DatabaseService) List(dbType string) ([]dto.DatabaseOption, error) {
	dbs, err := databaseRepo.GetList(databaseRepo.WithTypeList(dbType))
	if err != nil {
		return nil, err
	}
	var datas []dto.DatabaseOption
	for _, db := range dbs {
		var item dto.DatabaseOption
		if err := copier.Copy(&item, &db); err != nil {
			return nil, errors.WithMessage(constant.ErrStructTransform, err.Error())
		}
		item.Database = db.Name
		datas = append(datas, item)
	}
	return datas, err
}

func (u *DatabaseService) LoadItems(dbType string) ([]dto.DatabaseItem, error) {
	dbs, err := databaseRepo.GetList(databaseRepo.WithTypeList(dbType))
	var datas []dto.DatabaseItem
	for _, db := range dbs {
		if dbType == "postgresql" {
			items, _ := postgresqlRepo.List(postgresqlRepo.WithByPostgresqlName(db.Name))
			for _, item := range items {
				var dItem dto.DatabaseItem
				if err := copier.Copy(&dItem, &item); err != nil {
					continue
				}
				dItem.Database = db.Name
				datas = append(datas, dItem)
			}
		} else {
			items, _ := mysqlRepo.List(mysqlRepo.WithByMysqlName(db.Name))
			for _, item := range items {
				var dItem dto.DatabaseItem
				if err := copier.Copy(&dItem, &item); err != nil {
					continue
				}
				dItem.Database = db.Name
				datas = append(datas, dItem)
			}
		}
	}
	return datas, err
}

func (u *DatabaseService) CheckDatabase(req dto.DatabaseCreate) bool {
	switch req.Type {
	case constant.AppPostgresql:
		_, err := postgresql.NewPostgresqlClient(pgclient.DBInfo{
			From:     "remote",
			Address:  req.Address,
			Port:     req.Port,
			Username: req.Username,
			Password: req.Password,
			Timeout:  6,
		})
		return err == nil
	case constant.AppRedis:
		_, err := redisclient.NewRedisClient(redisclient.DBInfo{
			Address:  req.Address,
			Port:     req.Port,
			Password: req.Password,
		})
		return err == nil
	case "mysql", "mariadb":
		_, err := mysql.NewMysqlClient(client.DBInfo{
			From:     "remote",
			Address:  req.Address,
			Port:     req.Port,
			Username: req.Username,
			Password: req.Password,

			SSL:        req.SSL,
			RootCert:   req.RootCert,
			ClientKey:  req.ClientKey,
			ClientCert: req.ClientCert,
			SkipVerify: req.SkipVerify,
			Timeout:    6,
		})
		return err == nil
	}

	return false
}

// validateRemoteDatabaseConn whitelists the remote connection fields that are
// later interpolated unquoted into the host `bash -c` backup/restore command
// built by the remote mysql/postgresql clients (utils/*/client/remote.go).
// It applies only to remote-type connections (From=="remote" / Update, which
// always targets a remote record); local app connections are untouched.
func validateRemoteDatabaseConn(address, username string) error {
	if !cmd.ValidDBHost(address) {
		return fmt.Errorf("invalid remote database address: %q", address)
	}
	if !cmd.ValidDBUser(username) {
		return fmt.Errorf("invalid remote database username: %q", username)
	}
	return nil
}

// validRemoteSyncedDB reports whether a database reported by a remote server
// (mysql SyncDB / pg SyncDB, consumed by the LoadFromRemote services) may be
// synced into the local record table. The name and charset are attacker
// controlled when the remote server is malicious or compromised, and they are
// later interpolated unquoted into the host `bash -c` backup/restore command,
// so anything outside the whitelist must be skipped. The synced pg rows carry
// no charset, which the callers pass as an empty string.
func validRemoteSyncedDB(name, format string) bool {
	if !cmd.ValidDBName(name) {
		return false
	}
	return format == "" || cmd.ValidDBCharset(format)
}

func (u *DatabaseService) Create(req dto.DatabaseCreate) error {
	db, _ := databaseRepo.Get(commonRepo.WithByName(req.Name))
	if db.ID != 0 {
		if db.From == "local" {
			return buserr.New(constant.ErrLocalExist)
		}
		return constant.ErrRecordExist
	}
	if req.From != "local" {
		if err := validateRemoteDatabaseConn(req.Address, req.Username); err != nil {
			return err
		}
	}
	switch req.Type {
	case constant.AppPostgresql:
		if _, err := postgresql.NewPostgresqlClient(pgclient.DBInfo{
			From:     "remote",
			Address:  req.Address,
			Port:     req.Port,
			Username: req.Username,
			Password: req.Password,
			Timeout:  6,
		}); err != nil {
			return err
		}
	case constant.AppRedis:
		if _, err := redisclient.NewRedisClient(redisclient.DBInfo{
			Address:  req.Address,
			Port:     req.Port,
			Password: req.Password,
		}); err != nil {
			return err
		}
	case "mysql", "mariadb":
		if _, err := mysql.NewMysqlClient(client.DBInfo{
			From:     "remote",
			Address:  req.Address,
			Port:     req.Port,
			Username: req.Username,
			Password: req.Password,

			SSL:        req.SSL,
			RootCert:   req.RootCert,
			ClientKey:  req.ClientKey,
			ClientCert: req.ClientCert,
			SkipVerify: req.SkipVerify,
			Timeout:    6,
		}); err != nil {
			return err
		}
	default:
		return errors.New("database type not supported")
	}

	if err := copier.Copy(&db, &req); err != nil {
		return errors.WithMessage(constant.ErrStructTransform, err.Error())
	}
	if err := databaseRepo.Create(context.Background(), &db); err != nil {
		return err
	}
	return nil
}

func (u *DatabaseService) DeleteCheck(id uint) ([]string, error) {
	var appInUsed []string
	apps, _ := appInstallResourceRepo.GetBy(databaseRepo.WithByFrom("remote"), appInstallResourceRepo.WithLinkId(id))
	for _, app := range apps {
		appInstall, _ := appInstallRepo.GetFirst(commonRepo.WithByID(app.AppInstallId))
		if appInstall.ID != 0 {
			appInUsed = append(appInUsed, appInstall.Name)
		}
	}

	return appInUsed, nil
}

func (u *DatabaseService) Delete(req dto.DatabaseDelete) error {
	db, _ := databaseRepo.Get(commonRepo.WithByID(req.ID))
	if db.ID == 0 {
		return constant.ErrRecordNotFound
	}

	if req.DeleteBackup {
		uploadRoot := path.Join(global.CONF.System.BaseDir, "1panel/uploads/database")
		uploadDir := path.Join(uploadRoot, db.Type, db.Name)
		removeDatabaseBackupDirs(uploadDir, uploadRoot, "upload", db.Name)
		localDir, err := loadLocalDir()
		if err != nil && !req.ForceDelete {
			return err
		}
		backupRoot := path.Join(localDir, "database")
		backupDir := path.Join(backupRoot, db.Type, db.Name)
		removeDatabaseBackupDirs(backupDir, backupRoot, "backup", db.Name)
		_ = backupRepo.DeleteRecord(context.Background(), commonRepo.WithByType(db.Type), commonRepo.WithByName(db.Name))
		global.LOG.Infof("delete database %s-%s backups successful", db.Type, db.Name)
	}

	if err := databaseRepo.Delete(context.Background(), commonRepo.WithByID(req.ID)); err != nil && !req.ForceDelete {
		return err
	}
	if db.From != "local" {
		if db.Type == "mysql" || db.Type == "mariadb" {
			if err := mysqlRepo.Delete(context.Background(), mysqlRepo.WithByMysqlName(db.Name)); err != nil && !req.ForceDelete {
				return err
			}
		} else {
			if err := postgresqlRepo.Delete(context.Background(), postgresqlRepo.WithByPostgresqlName(db.Name)); err != nil && !req.ForceDelete {
				return err
			}
		}
	}
	return nil
}

func (u *DatabaseService) Update(req dto.DatabaseUpdate) error {
	// Update always targets a remote connection record (local apps are edited
	// elsewhere), so the same whitelist as Create applies.
	if err := validateRemoteDatabaseConn(req.Address, req.Username); err != nil {
		return err
	}
	switch req.Type {
	case constant.AppPostgresql:
		if _, err := postgresql.NewPostgresqlClient(pgclient.DBInfo{
			From:     "remote",
			Address:  req.Address,
			Port:     req.Port,
			Username: req.Username,
			Password: req.Password,
			Timeout:  300,
		}); err != nil {
			return err
		}
	case constant.AppRedis:
		if _, err := redisclient.NewRedisClient(redisclient.DBInfo{
			Address:  req.Address,
			Port:     req.Port,
			Password: req.Password,
		}); err != nil {
			return err
		}
	case "mysql", "mariadb":
		if _, err := mysql.NewMysqlClient(client.DBInfo{
			From:     "remote",
			Address:  req.Address,
			Port:     req.Port,
			Username: req.Username,
			Password: req.Password,

			SSL:        req.SSL,
			RootCert:   req.RootCert,
			ClientKey:  req.ClientKey,
			ClientCert: req.ClientCert,
			SkipVerify: req.SkipVerify,
			Timeout:    300,
		}); err != nil {
			return err
		}
	default:
		return errors.New("database type not supported")
	}

	pass, err := encrypt.StringEncrypt(req.Password)
	if err != nil {
		return fmt.Errorf("decrypt database password failed, err: %v", err)
	}

	upMap := make(map[string]interface{})
	upMap["type"] = req.Type
	upMap["version"] = req.Version
	upMap["address"] = req.Address
	upMap["port"] = req.Port
	upMap["username"] = req.Username
	upMap["password"] = pass
	upMap["description"] = req.Description
	upMap["ssl"] = req.SSL
	upMap["client_key"] = req.ClientKey
	upMap["client_cert"] = req.ClientCert
	upMap["root_cert"] = req.RootCert
	upMap["skip_verify"] = req.SkipVerify
	return databaseRepo.Update(req.ID, upMap)
}
