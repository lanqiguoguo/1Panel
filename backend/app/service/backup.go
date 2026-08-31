package service

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/1Panel-dev/1Panel/backend/app/dto"
	"github.com/1Panel-dev/1Panel/backend/app/model"
	"github.com/1Panel-dev/1Panel/backend/buserr"
	"github.com/1Panel-dev/1Panel/backend/constant"
	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/1Panel-dev/1Panel/backend/utils/cloud_storage"
	"github.com/1Panel-dev/1Panel/backend/utils/cloud_storage/client"
	fileUtils "github.com/1Panel-dev/1Panel/backend/utils/files"
	"github.com/jinzhu/copier"
	"github.com/pkg/errors"
	"gorm.io/gorm"
)

type BackupService struct{}

type IBackupService interface {
	List() ([]dto.BackupInfo, error)
	SearchRecordsWithPage(search dto.RecordSearch) (int64, []dto.BackupRecords, error)
	LoadSize(req dto.RecordSearch) ([]dto.BackupFile, error)
	SearchRecordsByCronjobWithPage(search dto.RecordSearchByCronjob) (int64, []dto.BackupRecords, error)
	LoadSizeByCronjob(req dto.RecordSearchByCronjob) ([]dto.BackupFile, error)
	LoadOneDriveInfo() (dto.OneDriveInfo, error)
	DownloadRecord(info dto.DownloadRecord) (string, error)
	Create(backupDto dto.BackupOperate) error
	GetBuckets(backupDto dto.ForBuckets) ([]interface{}, error)
	Update(ireq dto.BackupOperate) error
	Delete(id uint) error
	DeleteRecordByName(backupType, name, detailName string, withDeleteFile bool) error
	BatchDeleteRecord(ids []uint) error
	NewClient(backup *model.BackupAccount) (cloud_storage.CloudStorageClient, error)
	ListAppRecords(name, detailName, fileName string) ([]model.BackupRecord, error)

	ListFiles(req dto.BackupSearchFile) []string

	MysqlBackup(db dto.CommonBackup) error
	PostgresqlBackup(db dto.CommonBackup) error
	MysqlRecover(db dto.CommonRecover) error
	PostgresqlRecover(db dto.CommonRecover) error
	MysqlRecoverByUpload(req dto.CommonRecover) error
	PostgresqlRecoverByUpload(req dto.CommonRecover) error

	RedisBackup(db dto.CommonBackup) error
	RedisRecover(db dto.CommonRecover) error

	WebsiteBackup(db dto.CommonBackup) error
	WebsiteRecover(req dto.CommonRecover) error

	AppBackup(db dto.CommonBackup) (*model.BackupRecord, error)
	AppRecover(req dto.CommonRecover) error

	Run()
}

func NewIBackupService() IBackupService {
	return &BackupService{}
}

func (u *BackupService) List() ([]dto.BackupInfo, error) {
	ops, err := backupRepo.List(commonRepo.WithOrderBy("created_at desc"))
	var dtobas []dto.BackupInfo
	dtobas = append(dtobas, u.loadByType("LOCAL", ops))
	dtobas = append(dtobas, u.loadByType("OSS", ops))
	dtobas = append(dtobas, u.loadByType("S3", ops))
	dtobas = append(dtobas, u.loadByType("SFTP", ops))
	dtobas = append(dtobas, u.loadByType("MINIO", ops))
	dtobas = append(dtobas, u.loadByType("COS", ops))
	dtobas = append(dtobas, u.loadByType("KODO", ops))
	dtobas = append(dtobas, u.loadByType("OneDrive", ops))
	dtobas = append(dtobas, u.loadByType("WebDAV", ops))
	return dtobas, err
}

func (u *BackupService) SearchRecordsWithPage(search dto.RecordSearch) (int64, []dto.BackupRecords, error) {
	total, records, err := backupRepo.PageRecord(
		search.Page, search.PageSize,
		commonRepo.WithOrderBy("created_at desc"),
		commonRepo.WithByName(search.Name),
		commonRepo.WithByType(search.Type),
		backupRepo.WithByDetailName(search.DetailName),
	)
	if err != nil {
		return 0, nil, err
	}

	var list []dto.BackupRecords
	for _, item := range records {
		var itemRecord dto.BackupRecords
		if err := copier.Copy(&itemRecord, &item); err != nil {
			continue
		}
		list = append(list, itemRecord)
	}
	return total, list, err
}

func (u *BackupService) LoadSize(req dto.RecordSearch) ([]dto.BackupFile, error) {
	_, records, err := backupRepo.PageRecord(
		req.Page, req.PageSize,
		commonRepo.WithOrderBy("created_at desc"),
		commonRepo.WithByName(req.Name),
		commonRepo.WithByType(req.Type),
		backupRepo.WithByDetailName(req.DetailName),
	)
	if err != nil {
		return nil, err
	}
	return u.loadRecordSize(records)
}

func (u *BackupService) ListAppRecords(name, detailName, fileName string) ([]model.BackupRecord, error) {
	records, err := backupRepo.ListRecord(
		commonRepo.WithOrderBy("created_at asc"),
		commonRepo.WithByName(name),
		commonRepo.WithByType("app"),
		backupRepo.WithFileNameStartWith(fileName),
		backupRepo.WithByDetailName(detailName),
	)
	if err != nil {
		return nil, err
	}
	return records, err
}

func (u *BackupService) SearchRecordsByCronjobWithPage(search dto.RecordSearchByCronjob) (int64, []dto.BackupRecords, error) {
	total, records, err := backupRepo.PageRecord(
		search.Page, search.PageSize,
		commonRepo.WithOrderBy("created_at desc"),
		backupRepo.WithByCronID(search.CronjobID),
	)
	if err != nil {
		return 0, nil, err
	}

	var list []dto.BackupRecords
	for _, item := range records {
		var itemRecord dto.BackupRecords
		if err := copier.Copy(&itemRecord, &item); err != nil {
			continue
		}
		list = append(list, itemRecord)
	}
	return total, list, err
}

func (u *BackupService) LoadSizeByCronjob(req dto.RecordSearchByCronjob) ([]dto.BackupFile, error) {
	_, records, err := backupRepo.PageRecord(
		req.Page, req.PageSize,
		commonRepo.WithOrderBy("created_at desc"),
		backupRepo.WithByCronID(req.CronjobID),
	)
	if err != nil {
		return nil, err
	}
	return u.loadRecordSize(records)
}

type loadSizeHelper struct {
	isOk       bool
	backupPath string
	client     cloud_storage.CloudStorageClient
}

func (u *BackupService) LoadOneDriveInfo() (dto.OneDriveInfo, error) {
	var data dto.OneDriveInfo
	data.RedirectUri = constant.OneDriveRedirectURI
	clientID, err := settingRepo.Get(settingRepo.WithByKey("OneDriveID"))
	if err != nil {
		return data, err
	}
	idItem, err := base64.StdEncoding.DecodeString(clientID.Value)
	if err != nil {
		return data, err
	}
	data.ClientID = string(idItem)
	clientSecret, err := settingRepo.Get(settingRepo.WithByKey("OneDriveSc"))
	if err != nil {
		return data, err
	}
	if _, err := base64.StdEncoding.DecodeString(clientSecret.Value); err != nil {
		return data, err
	}
	// Never echo the Azure OAuth client secret back to the frontend (D-1).
	// The secret is only read internally from the OneDriveSc setting (see
	// init/hook) or from the account vars when the OAuth flow runs; the edit
	// form treats an empty value as "keep the stored secret".
	data.ClientSecret = ""

	return data, err
}

func (u *BackupService) DownloadRecord(info dto.DownloadRecord) (string, error) {
	fileDir, err := sanitizeBackupDir(info.FileDir)
	if err != nil {
		return "", err
	}
	fileName, err := fileUtils.SanitizeFilename(info.FileName)
	if err != nil {
		return "", err
	}
	info.FileDir = fileDir
	info.FileName = fileName

	if info.Source == "LOCAL" {
		localDir, err := loadLocalDir()
		if err != nil {
			return "", err
		}
		return path.Join(localDir, info.FileDir, info.FileName), nil
	}
	backup, _ := backupRepo.Get(commonRepo.WithByType(info.Source))
	if backup.ID == 0 {
		return "", constant.ErrRecordNotFound
	}
	varMap := make(map[string]interface{})
	if err := json.Unmarshal([]byte(backup.Vars), &varMap); err != nil {
		return "", err
	}
	varMap["bucket"] = backup.Bucket
	switch backup.Type {
	case constant.Sftp, constant.WebDAV:
		varMap["username"] = backup.AccessKey
		varMap["password"] = backup.Credential
	case constant.OSS, constant.S3, constant.MinIo, constant.Cos, constant.Kodo:
		varMap["accessKey"] = backup.AccessKey
		varMap["secretKey"] = backup.Credential
	case constant.OneDrive:
		varMap["accessToken"] = backup.Credential
	}
	backClient, err := cloud_storage.NewCloudStorageClient(backup.Type, varMap)
	if err != nil {
		return "", fmt.Errorf("new cloud storage client failed, err: %v", err)
	}
	targetPath := fmt.Sprintf("%s/download/%s/%s", constant.DataDir, info.FileDir, info.FileName)
	if _, err := os.Stat(path.Dir(targetPath)); err != nil && os.IsNotExist(err) {
		if err = os.MkdirAll(path.Dir(targetPath), os.ModePerm); err != nil {
			global.LOG.Errorf("mkdir %s failed, err: %v", path.Dir(targetPath), err)
		}
	}
	srcPath := fmt.Sprintf("%s/%s", info.FileDir, info.FileName)
	if len(backup.BackupPath) != 0 {
		srcPath = path.Join(strings.TrimPrefix(backup.BackupPath, "/"), srcPath)
	}
	if exist, _ := backClient.Exist(srcPath); exist {
		isOK, err := backClient.Download(srcPath, targetPath)
		if !isOK {
			return "", fmt.Errorf("cloud storage download failed, err: %v", err)
		}
	}
	return targetPath, nil
}

// sanitizeBackupDir validates a backup record's relative directory path and
// returns it unchanged on success. Backup FileDir values are relative paths
// that may span multiple levels (e.g. "system/mysql", "app/wordpress"),
// so unlike SanitizeFilename it permits "/" as a separator while rejecting
// anything that could escape the backup root: empty names, "." and "..",
// absolute paths, Windows drive prefixes, backslashes, and path segments
// that are empty, "." or "..".
func sanitizeBackupDir(s string) (string, error) {
	if s == "" || s == "." || s == ".." {
		return "", buserr.New(constant.ErrCmdIllegal)
	}
	if strings.HasPrefix(s, "/") {
		return "", buserr.New(constant.ErrCmdIllegal)
	}
	if strings.Contains(s, "\\") {
		return "", buserr.New(constant.ErrCmdIllegal)
	}
	// Windows drive prefix, e.g. "C:" or "c:".
	if len(s) >= 2 && isASCIIAlpha(s[0]) && s[1] == ':' {
		return "", buserr.New(constant.ErrCmdIllegal)
	}
	for _, seg := range strings.Split(s, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return "", buserr.New(constant.ErrCmdIllegal)
		}
	}
	return s, nil
}

func isASCIIAlpha(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

func (u *BackupService) Create(req dto.BackupOperate) error {
	backup, _ := backupRepo.Get(commonRepo.WithByType(req.Type))
	if backup.ID != 0 {
		return constant.ErrRecordExist
	}
	if err := copier.Copy(&backup, &req); err != nil {
		return errors.WithMessage(constant.ErrStructTransform, err.Error())
	}

	if req.Type == constant.OneDrive {
		if err := u.loadAccessToken(&backup); err != nil {
			return err
		}
	}
	if req.Type != "LOCAL" {
		if _, err := u.checkBackupConn(&backup); err != nil {
			return buserr.WithMap("ErrBackupCheck", map[string]interface{}{"err": err.Error()}, err)
		}
	}
	if backup.Type == constant.OneDrive {
		StartRefreshOneDriveToken()
	}
	if err := backupRepo.Create(&backup); err != nil {
		return err
	}
	return nil
}

func (u *BackupService) GetBuckets(backupDto dto.ForBuckets) ([]interface{}, error) {
	varMap := make(map[string]interface{})
	if err := json.Unmarshal([]byte(backupDto.Vars), &varMap); err != nil {
		return nil, err
	}
	switch backupDto.Type {
	case constant.Sftp, constant.WebDAV:
		varMap["username"] = backupDto.AccessKey
		varMap["password"] = backupDto.Credential
	case constant.OSS, constant.S3, constant.MinIo, constant.Cos, constant.Kodo:
		varMap["accessKey"] = backupDto.AccessKey
		varMap["secretKey"] = backupDto.Credential
	}
	client, err := cloud_storage.NewCloudStorageClient(backupDto.Type, varMap)
	if err != nil {
		return nil, err
	}
	return client.ListBuckets()
}

func (u *BackupService) Delete(id uint) error {
	backup, _ := backupRepo.Get(commonRepo.WithByID(id))
	if backup.ID == 0 {
		return constant.ErrRecordNotFound
	}
	if backup.Type == constant.OneDrive {
		global.Cron.Remove(global.OneDriveCronID)
		// Reset the id so a later Create of another OneDrive account cannot
		// double-register the refresh job: StartRefreshOneDriveToken skips
		// when the id is already set, and Remove(0) is a safe no-op.
		global.OneDriveCronID = 0
	}
	cronjobs, _ := cronjobRepo.List(cronjobRepo.WithByDefaultDownload(backup.Type))
	if len(cronjobs) != 0 {
		return buserr.New(constant.ErrBackupInUsed)
	}
	return backupRepo.Delete(commonRepo.WithByID(id))
}

func (u *BackupService) DeleteRecordByName(backupType, name, detailName string, withDeleteFile bool) error {
	if !withDeleteFile {
		return backupRepo.DeleteRecord(context.Background(), commonRepo.WithByType(backupType), commonRepo.WithByName(name), backupRepo.WithByDetailName(detailName))
	}

	records, err := backupRepo.ListRecord(commonRepo.WithByType(backupType), commonRepo.WithByName(name), backupRepo.WithByDetailName(detailName))
	if err != nil {
		return err
	}

	for _, record := range records {
		backupAccount, err := backupRepo.Get(commonRepo.WithByType(record.Source))
		if err != nil {
			global.LOG.Errorf("load backup account %s info from db failed, err: %v", record.Source, err)
			continue
		}
		client, err := u.NewClient(&backupAccount)
		if err != nil {
			global.LOG.Errorf("new client for backup account %s failed, err: %v", record.Source, err)
			continue
		}
		if _, err = client.Delete(path.Join(record.FileDir, record.FileName)); err != nil {
			global.LOG.Errorf("remove file %s from %s failed, err: %v", path.Join(record.FileDir, record.FileName), record.Source, err)
		}
		_ = backupRepo.DeleteRecord(context.Background(), commonRepo.WithByID(record.ID))
	}
	return nil
}

func (u *BackupService) BatchDeleteRecord(ids []uint) error {
	records, err := backupRepo.ListRecord(commonRepo.WithIdsIn(ids))
	if err != nil {
		return err
	}
	for _, record := range records {
		backupAccount, err := backupRepo.Get(commonRepo.WithByType(record.Source))
		if err != nil {
			global.LOG.Errorf("load backup account %s info from db failed, err: %v", record.Source, err)
			continue
		}
		client, err := u.NewClient(&backupAccount)
		if err != nil {
			global.LOG.Errorf("new client for backup account %s failed, err: %v", record.Source, err)
			continue
		}
		if _, err = client.Delete(path.Join(record.FileDir, record.FileName)); err != nil {
			global.LOG.Errorf("remove file %s from %s failed, err: %v", path.Join(record.FileDir, record.FileName), record.Source, err)
		}
	}
	return backupRepo.DeleteRecord(context.Background(), commonRepo.WithIdsIn(ids))
}

func (u *BackupService) Update(req dto.BackupOperate) error {
	backup, err := backupRepo.Get(commonRepo.WithByID(req.ID))
	if err != nil {
		return constant.ErrRecordNotFound
	}
	varMap := make(map[string]interface{})
	if err := json.Unmarshal([]byte(req.Vars), &varMap); err != nil {
		return err
	}

	oldVars := backup.Vars
	oldDir, err := loadLocalDir()
	if err != nil {
		return err
	}

	// Keep semantics: the frontend echoes masked credentials ("******" for
	// secret var fields) and sends an empty credential/accessKey when the
	// user left the secret fields untouched. In both cases the stored value
	// must survive the update. A masked/empty value only takes effect when
	// nothing is stored yet (create path enforces required fields, so an
	// empty credential here always means "keep").
	if isMaskedCredential(req.Credential) {
		req.Credential = backup.Credential
	}
	if isMaskedCredential(req.AccessKey) {
		req.AccessKey = backup.AccessKey
	}
	if req.Vars == "" || isMaskedCredential(req.Vars) {
		req.Vars = backup.Vars
	} else {
		if req.Vars, err = mergeMaskedVars(backup.Vars, req.Vars); err != nil {
			return err
		}
	}

	upMap := make(map[string]interface{})
	upMap["bucket"] = req.Bucket
	upMap["access_key"] = req.AccessKey
	upMap["credential"] = req.Credential
	upMap["backup_path"] = req.BackupPath
	upMap["vars"] = req.Vars
	backup.Bucket = req.Bucket
	backup.Vars = req.Vars
	backup.Credential = req.Credential
	backup.AccessKey = req.AccessKey
	backup.BackupPath = req.BackupPath

	if req.Type == constant.OneDrive {
		if err := u.loadAccessToken(&backup); err != nil {
			return err
		}
		upMap["credential"] = backup.Credential
		upMap["vars"] = backup.Vars
	}
	if backup.Type != "LOCAL" {
		isOk, err := u.checkBackupConn(&backup)
		if err != nil || !isOk {
			return buserr.WithMap("ErrBackupCheck", map[string]interface{}{"err": err.Error()}, err)
		}
	}

	if err := backupRepo.Update(req.ID, upMap); err != nil {
		return err
	}
	if backup.Type == "LOCAL" {
		if dir, ok := varMap["dir"]; ok {
			if dirStr, isStr := dir.(string); isStr {
				if strings.HasSuffix(dirStr, "/") && dirStr != "/" {
					dirStr = dirStr[:strings.LastIndex(dirStr, "/")]
				}
				if err := changeLocalBackup(oldDir, dirStr); err != nil {
					_ = backupRepo.Update(req.ID, map[string]interface{}{"vars": oldVars})
					return fmt.Errorf("copy dir from %s to %s failed, err: %v", oldDir, dirStr, err)
				}
				global.CONF.System.Backup = dirStr
			}
		}
	}
	return nil
}

func (u *BackupService) ListFiles(req dto.BackupSearchFile) []string {
	var datas []string
	backup, err := backupRepo.Get(backupRepo.WithByType(req.Type))
	if err != nil {
		return datas
	}
	client, err := u.NewClient(&backup)
	if err != nil {
		return datas
	}
	prefix := "system_snapshot"
	if len(backup.BackupPath) != 0 {
		prefix = path.Join(strings.TrimPrefix(backup.BackupPath, "/"), prefix)
	}
	files, err := client.ListObjects(prefix)
	if err != nil {
		global.LOG.Debugf("load files from %s failed, err: %v", req.Type, err)
		return datas
	}
	for _, file := range files {
		if len(file) != 0 {
			datas = append(datas, path.Base(file))
		}
	}
	return datas
}

func (u *BackupService) NewClient(backup *model.BackupAccount) (cloud_storage.CloudStorageClient, error) {
	varMap := make(map[string]interface{})
	if err := json.Unmarshal([]byte(backup.Vars), &varMap); err != nil {
		return nil, err
	}
	varMap["bucket"] = backup.Bucket
	switch backup.Type {
	case constant.Sftp, constant.WebDAV:
		varMap["username"] = backup.AccessKey
		varMap["password"] = backup.Credential
	case constant.OSS, constant.S3, constant.MinIo, constant.Cos, constant.Kodo:
		varMap["accessKey"] = backup.AccessKey
		varMap["secretKey"] = backup.Credential
	}

	backClient, err := cloud_storage.NewCloudStorageClient(backup.Type, varMap)
	if err != nil {
		return nil, err
	}

	return backClient, nil
}

// backupMaskValue is the placeholder returned in place of real credentials on
// every read path that echoes backup account data back to the frontend. The
// edit forms treat this exact value (or an empty value) as "keep the stored
// secret" and the update path skips writing it back.
const backupMaskValue = "******"

// backupSecretVars holds the var keys whose values are secrets and must be
// masked whenever account vars are echoed to the frontend. Access keys and
// usernames are not secrets and are intentionally not listed.
var backupSecretVars = map[string]struct{}{
	"password":      {},
	"secretKey":     {},
	"secret":        {},
	"client_secret": {},
	"refresh_token": {},
	"credential":    {},
}

// isMaskedCredential reports whether a credential value received from the
// frontend is a placeholder (masked echo or empty) that must not overwrite a
// stored secret.
func isMaskedCredential(v string) bool {
	return v == "" || v == backupMaskValue
}

// maskBackupVars returns a copy of the account vars JSON with every secret
// value replaced by the mask placeholder. Non-secret fields (accessKey,
// bucket, endpoint, region, refresh_time/status, ...) are passed through
// unchanged so the frontend list can still display account state.
//
// Vars that cannot be parsed (e.g. a malformed historical row) fail closed:
// they are masked wholesale as an empty vars object, since echoing the raw
// value could leak plaintext credentials. The frontend parses the vars JSON
// and renders an empty object as an account without credentials.
func maskBackupVars(vars string) string {
	var varMap map[string]interface{}
	if err := json.Unmarshal([]byte(vars), &varMap); err != nil {
		return "{}"
	}
	for key := range varMap {
		if _, ok := backupSecretVars[key]; ok {
			varMap[key] = backupMaskValue
		}
	}
	itemVars, err := json.Marshal(varMap)
	if err != nil {
		return "{}"
	}
	return string(itemVars)
}

// mergeMaskedVars overlays a vars map submitted from the frontend on top of
// the stored vars, keeping the stored value for every field the form left at
// the mask placeholder (or empty). Non-masked fields take the submitted
// value. This gives the edit forms "keep the stored secret" semantics while
// still allowing every other field to be changed in one request.
func mergeMaskedVars(storedVars, reqVars string) (string, error) {
	storedMap := make(map[string]interface{})
	if err := json.Unmarshal([]byte(storedVars), &storedMap); err != nil {
		return "", fmt.Errorf("unmarshal stored vars failed, err: %v", err)
	}
	reqMap := make(map[string]interface{})
	if err := json.Unmarshal([]byte(reqVars), &reqMap); err != nil {
		return "", fmt.Errorf("unmarshal request vars failed, err: %v", err)
	}
	for key, value := range reqMap {
		if _, ok := backupSecretVars[key]; ok {
			strValue, isStr := value.(string)
			if (isStr && isMaskedCredential(strValue)) || (!isStr && value == nil) {
				// Masked/empty secret: keep whatever is stored (storedMap
				// still holds the old value), skip the overwrite.
				continue
			}
		}
		storedMap[key] = value
	}
	itemVars, err := json.Marshal(storedMap)
	if err != nil {
		return "", fmt.Errorf("json marshal vars failed, err: %v", err)
	}
	return string(itemVars), nil
}

func (u *BackupService) loadByType(accountType string, accounts []model.BackupAccount) dto.BackupInfo {
	for _, account := range accounts {
		if account.Type == accountType {
			var item dto.BackupInfo
			if err := copier.Copy(&item, &account); err != nil {
				global.LOG.Errorf("copy backup account to dto backup info failed, err: %v", err)
			}
			item.Vars = maskBackupVars(item.Vars)
			return item
		}
	}
	return dto.BackupInfo{Type: accountType}
}

func (u *BackupService) loadAccessToken(backup *model.BackupAccount) error {
	varMap := make(map[string]interface{})
	if err := json.Unmarshal([]byte(backup.Vars), &varMap); err != nil {
		return fmt.Errorf("unmarshal backup vars failed, err: %v", err)
	}
	refreshToken, err := client.RefreshToken("authorization_code", "refreshToken", varMap)
	if err != nil {
		return err
	}
	delete(varMap, "code")
	varMap["refresh_status"] = constant.StatusSuccess
	varMap["refresh_time"] = time.Now().Format(constant.DateTimeLayout)
	varMap["refresh_token"] = refreshToken
	itemVars, err := json.Marshal(varMap)
	if err != nil {
		return fmt.Errorf("json marshal var map failed, err: %v", err)
	}
	backup.Vars = string(itemVars)
	return nil
}

func (u *BackupService) loadRecordSize(records []model.BackupRecord) ([]dto.BackupFile, error) {
	data := make([]dto.BackupFile, len(records))
	clientMap := make(map[string]loadSizeHelper)
	var wg sync.WaitGroup
	for i := 0; i < len(records); i++ {
		data[i].ID = records[i].ID
		data[i].Name = records[i].FileName
		itemPath := path.Join(records[i].FileDir, records[i].FileName)
		if _, ok := clientMap[records[i].Source]; !ok {
			backup, err := backupRepo.Get(commonRepo.WithByType(records[i].Source))
			if err != nil {
				global.LOG.Errorf("load backup model %s from db failed, err: %v", records[i].Source, err)
				clientMap[records[i].Source] = loadSizeHelper{}
				continue
			}
			client, err := u.NewClient(&backup)
			if err != nil {
				global.LOG.Errorf("load backup client %s from db failed, err: %v", records[i].Source, err)
				clientMap[records[i].Source] = loadSizeHelper{}
				continue
			}
			data[i].Size, _ = client.Size(path.Join(strings.TrimLeft(backup.BackupPath, "/"), itemPath))
			clientMap[records[i].Source] = loadSizeHelper{backupPath: strings.TrimLeft(backup.BackupPath, "/"), client: client, isOk: true}
			continue
		}
		// Copy the helper out of clientMap so the goroutine below never reads
		// the map, which this loop keeps writing on later iterations.
		helper := clientMap[records[i].Source]
		if helper.isOk {
			wg.Add(1)
			go func(index int, helper loadSizeHelper, itemPath string) {
				defer wg.Done()
				data[index].Size, _ = helper.client.Size(path.Join(helper.backupPath, itemPath))
			}(i, helper, itemPath)
		}
	}
	wg.Wait()
	return data, nil
}

func loadLocalDir() (string, error) {
	backup, err := backupRepo.Get(commonRepo.WithByType("LOCAL"))
	if err != nil {
		return "", err
	}
	varMap := make(map[string]interface{})
	if err := json.Unmarshal([]byte(backup.Vars), &varMap); err != nil {
		return "", err
	}
	if _, ok := varMap["dir"]; !ok {
		return "", errors.New("load local backup dir failed")
	}
	baseDir, ok := varMap["dir"].(string)
	if ok {
		if _, err := os.Stat(baseDir); err != nil && os.IsNotExist(err) {
			if err = os.MkdirAll(baseDir, os.ModePerm); err != nil {
				return "", fmt.Errorf("mkdir %s failed, err: %v", baseDir, err)
			}
		}
		return baseDir, nil
	}
	return "", fmt.Errorf("error type dir: %T", varMap["dir"])
}

func copyDir(src, dst string) error {
	srcInfo, err := os.Stat(src)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(dst, srcInfo.Mode()); err != nil {
		return err
	}
	files, err := os.ReadDir(src)
	if err != nil {
		return err
	}

	fileOP := fileUtils.NewFileOp()
	for _, file := range files {
		srcPath := fmt.Sprintf("%s/%s", src, file.Name())
		dstPath := fmt.Sprintf("%s/%s", dst, file.Name())
		if file.IsDir() {
			if err = copyDir(srcPath, dstPath); err != nil {
				global.LOG.Errorf("copy dir %s to %s failed, err: %v", srcPath, dstPath, err)
			}
		} else {
			if err := fileOP.CopyFile(srcPath, dst); err != nil {
				global.LOG.Errorf("copy file %s to %s failed, err: %v", srcPath, dstPath, err)
			}
		}
	}

	return nil
}

func (u *BackupService) checkBackupConn(backup *model.BackupAccount) (bool, error) {
	client, err := u.NewClient(backup)
	if err != nil {
		return false, err
	}
	fileItem := path.Join(global.CONF.System.TmpDir, "test", "1panel")
	if _, err := os.Stat(path.Dir(fileItem)); err != nil && os.IsNotExist(err) {
		if err = os.MkdirAll(path.Dir(fileItem), os.ModePerm); err != nil {
			return false, err
		}
	}
	file, err := os.OpenFile(fileItem, os.O_WRONLY|os.O_CREATE, 0666)
	if err != nil {
		return false, err
	}
	defer file.Close()
	write := bufio.NewWriter(file)
	_, _ = write.WriteString("1Panel 备份账号测试文件。\n")
	_, _ = write.WriteString("1Panel 備份賬號測試文件。\n")
	_, _ = write.WriteString("1Panel Backs up account test files.\n")
	_, _ = write.WriteString("1Panelアカウントのテストファイルをバックアップします。\n")
	write.Flush()

	targetPath := strings.TrimPrefix(path.Join(backup.BackupPath, "test/1panel"), "/")
	return client.Upload(fileItem, targetPath)
}

func StartRefreshOneDriveToken() {
	if global.OneDriveCronID != 0 {
		// Already registered (startup + account creation both call this);
		// re-adding would leak a duplicate cron job.
		return
	}
	service := NewIBackupService()
	oneDriveCronID, err := global.Cron.AddJob("0 3 */31 * *", service)
	if err != nil {
		global.LOG.Errorf("can not add OneDrive corn job: %s", err.Error())
		return
	}
	global.OneDriveCronID = oneDriveCronID
}

func (u *BackupService) Run() {
	var backupItem model.BackupAccount
	if err := global.DB.Where("`type` = ?", "OneDrive").First(&backupItem).Error; err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		global.LOG.Errorf("load OneDrive backup account from db failed, err: %v", err)
		return
	}
	if backupItem.ID == 0 {
		return
	}
	global.LOG.Info("start to refresh token of OneDrive ...")
	varMap := make(map[string]interface{})
	if err := json.Unmarshal([]byte(backupItem.Vars), &varMap); err != nil {
		global.LOG.Errorf("Failed to refresh OneDrive token, please retry, err: %v", err)
		return
	}
	refreshToken, err := client.RefreshToken("refresh_token", "refreshToken", varMap)
	varMap["refresh_status"] = constant.StatusSuccess
	varMap["refresh_time"] = time.Now().Format(constant.DateTimeLayout)
	if err != nil {
		varMap["refresh_status"] = constant.StatusFailed
		varMap["refresh_msg"] = err.Error()
		global.LOG.Errorf("Failed to refresh OneDrive token, please retry, err: %v", err)
		return
	}
	varMap["refresh_token"] = refreshToken

	varsItem, _ := json.Marshal(varMap)
	if err := global.DB.Model(&model.BackupAccount{}).
		Where("id = ?", backupItem.ID).
		Updates(map[string]interface{}{
			"vars": varsItem,
		}).Error; err != nil {
		global.LOG.Errorf("update OneDrive refresh token to db failed, err: %v", err)
		return
	}
	global.LOG.Info("Successfully refreshed OneDrive token.")
}

func changeLocalBackup(oldPath, newPath string) error {
	fileOp := fileUtils.NewFileOp()
	if fileOp.Stat(path.Join(oldPath, "app")) {
		if err := fileOp.CopyDir(path.Join(oldPath, "app"), newPath); err != nil {
			return err
		}
	}
	if fileOp.Stat(path.Join(oldPath, "database")) {
		if err := fileOp.CopyDir(path.Join(oldPath, "database"), newPath); err != nil {
			return err
		}
	}
	if fileOp.Stat(path.Join(oldPath, "directory")) {
		if err := fileOp.CopyDir(path.Join(oldPath, "directory"), newPath); err != nil {
			return err
		}
	}
	if fileOp.Stat(path.Join(oldPath, "system_snapshot")) {
		if err := fileOp.CopyDir(path.Join(oldPath, "system_snapshot"), newPath); err != nil {
			return err
		}
	}
	if fileOp.Stat(path.Join(oldPath, "website")) {
		if err := fileOp.CopyDir(path.Join(oldPath, "website"), newPath); err != nil {
			return err
		}
	}
	if fileOp.Stat(path.Join(oldPath, "log")) {
		if err := fileOp.CopyDir(path.Join(oldPath, "log"), newPath); err != nil {
			return err
		}
	}
	_ = fileOp.RmRf(path.Join(oldPath, "app"))
	_ = fileOp.RmRf(path.Join(oldPath, "database"))
	_ = fileOp.RmRf(path.Join(oldPath, "directory"))
	_ = fileOp.RmRf(path.Join(oldPath, "system_snapshot"))
	_ = fileOp.RmRf(path.Join(oldPath, "website"))
	_ = fileOp.RmRf(path.Join(oldPath, "log"))
	return nil
}
