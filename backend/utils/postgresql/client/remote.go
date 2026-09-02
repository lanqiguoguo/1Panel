package client

import (
	"bufio"
	"context"
	"database/sql"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/1Panel-dev/1Panel/backend/app/model"
	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/1Panel-dev/1Panel/backend/utils/cmd"
	"github.com/docker/docker/api/types/image"
	"github.com/pkg/errors"

	"github.com/1Panel-dev/1Panel/backend/buserr"
	"github.com/1Panel-dev/1Panel/backend/constant"
	"github.com/1Panel-dev/1Panel/backend/utils/docker"
	_ "github.com/jackc/pgx/v5/stdlib"
)

type Remote struct {
	Client   *sql.DB
	From     string
	Database string
	User     string
	Password string
	Address  string
	Port     uint
}

func NewRemote(db Remote) *Remote {
	return &db
}
func (r *Remote) Create(info CreateInfo) error {
	createSql := fmt.Sprintf("CREATE DATABASE \"%s\"", info.Name)
	if err := r.ExecSQL(createSql, info.Timeout); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "already exists") {
			return buserr.New(constant.ErrDatabaseIsExist)
		}
		return err
	}
	if err := r.CreateUser(info, true); err != nil {
		return err
	}
	return nil
}

func (r *Remote) CreateUser(info CreateInfo, withDeleteDB bool) error {
	createSql := fmt.Sprintf("CREATE USER \"%s\" WITH PASSWORD '%s'", info.Username, info.Password)
	if err := r.ExecSQL(createSql, info.Timeout); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "already exists") {
			return buserr.New(constant.ErrUserIsExist)
		}
		if withDeleteDB {
			_ = r.Delete(DeleteInfo{
				Name:        info.Name,
				Username:    info.Username,
				ForceDelete: true,
				Timeout:     300})
		}
		return err
	}
	if info.SuperUser {
		if err := r.ChangePrivileges(Privileges{SuperUser: true, Username: info.Username, Timeout: info.Timeout}); err != nil {
			if withDeleteDB {
				_ = r.Delete(DeleteInfo{
					Name:        info.Name,
					Username:    info.Username,
					ForceDelete: true,
					Timeout:     300})
			}
			return err
		}
	}
	grantSql := fmt.Sprintf("GRANT ALL PRIVILEGES ON DATABASE \"%s\" TO \"%s\"", info.Name, info.Username)
	if err := r.ExecSQL(grantSql, info.Timeout); err != nil {
		if withDeleteDB {
			_ = r.Delete(DeleteInfo{
				Name:        info.Name,
				Username:    info.Username,
				ForceDelete: true,
				Timeout:     300})
		}
		return err
	}

	return nil
}

func (r *Remote) Delete(info DeleteInfo) error {
	if len(info.Name) != 0 {
		dropSql := fmt.Sprintf("DROP DATABASE \"%s\"", info.Name)
		if err := r.ExecSQL(dropSql, info.Timeout); err != nil && !info.ForceDelete {
			return err
		}
	}
	dropSql := fmt.Sprintf("DROP USER \"%s\"", info.Username)
	if err := r.ExecSQL(dropSql, info.Timeout); err != nil && !info.ForceDelete {
		if strings.Contains(strings.ToLower(err.Error()), "depend on it") {
			return buserr.WithDetail(constant.ErrInUsed, info.Username, nil)
		}
		return err
	}
	return nil
}

func (r *Remote) ChangePrivileges(info Privileges) error {
	super := "SUPERUSER"
	if !info.SuperUser {
		super = "NOSUPERUSER"
	}
	return r.ExecSQL(fmt.Sprintf("ALTER USER \"%s\" WITH %s", info.Username, super), info.Timeout)
}

func (r *Remote) ChangePassword(info PasswordChangeInfo) error {
	return r.ExecSQL(fmt.Sprintf("ALTER USER \"%s\" WITH ENCRYPTED PASSWORD '%s'", info.Username, info.Password), info.Timeout)
}

func (r *Remote) Backup(info BackupInfo) error {
	if err := validateRemoteFields(r.Address, r.User, info.Name); err != nil {
		return err
	}
	imageTag, err := loadImageTag()
	if err != nil {
		return err
	}
	fileNameItem := info.TargetDir + "/" + strings.TrimSuffix(info.FileName, ".gz")
	finalPath := info.TargetDir + "/" + info.FileName
	// 0600/0750 (see backupOutFile): the pg dump of a remote database is
	// streamed by pg_dump and must not be world-readable at any moment.
	if _, _, err := backupOutFile(info.TargetDir, strings.TrimSuffix(info.FileName, ".gz")); err != nil {
		return err
	}
	// The password reaches pg_dump via PGPASSWORD loaded from a 0600 env file
	// (cmd.WriteDockerEnvFile) through `docker run --env-file`: it crosses the
	// docker daemon socket only, so the host bash cmdline no longer contains
	// it (see remoteBackupCommand).
	envFile, err := cmd.WriteDockerEnvFile(global.CONF.System.TmpDir, map[string]string{"PGPASSWORD": r.Password})
	if err != nil {
		return err
	}
	defer os.Remove(envFile)
	// The bash redirect in remoteBackupCommand truncates the pre-created file
	// without resetting its 0600 mode. Never leave a partial dump behind on a
	// failed path.
	ok := false
	defer func() {
		if !ok {
			_ = os.RemoveAll(fileNameItem)
			_ = os.RemoveAll(finalPath)
		}
	}()
	backupCommand := exec.Command("bash", "-c",
		remoteBackupCommand(envFile, imageTag, r.Address, r.Port, r.User, info.Name, fileNameItem))
	out, err := backupCommand.CombinedOutput()
	if err != nil {
		return fmt.Errorf("dump database %s failed, err: %v", info.Name, string(out))
	}
	b := make([]byte, 5)
	n := []byte{80, 71, 68, 77, 80}
	handle, err := os.OpenFile(fileNameItem, os.O_RDONLY, 0)
	if err != nil {
		return fmt.Errorf("backup file not found,err:%v", err)
	}
	defer handle.Close()
	_, _ = handle.Read(b)
	if string(b) != string(n) {
		errBytes, _ := os.ReadFile(fileNameItem)
		return fmt.Errorf("backup failed,err:%s", string(errBytes))
	}

	gzipCmd := exec.Command("gzip", fileNameItem)
	stdout, err := gzipCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("gzip file %s failed, stdout: %v, err: %v", strings.TrimSuffix(info.FileName, ".gz"), string(stdout), err)
	}
	ok = true
	return nil
}

func (r *Remote) Recover(info RecoverInfo) error {
	if err := validateRemoteFields(r.Address, r.User, info.Name); err != nil {
		return err
	}
	imageTag, err := loadImageTag()
	if err != nil {
		return err
	}
	fileName := info.SourceFile
	if strings.HasSuffix(info.SourceFile, ".sql.gz") {
		fileName = strings.TrimSuffix(info.SourceFile, ".gz")
		gzipCmd := exec.Command("gunzip", info.SourceFile)
		stdout, err := gzipCmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("gunzip file %s failed, stdout: %v, err: %v", info.SourceFile, string(stdout), err)
		}
		defer func() {
			gzipCmd := exec.Command("gzip", fileName)
			_, _ = gzipCmd.CombinedOutput()
		}()
	}
	// See Backup: the password travels via PGPASSWORD from the 0600 env file
	// only, never through the host bash cmdline (see remoteRecoverCommand).
	envFile, err := cmd.WriteDockerEnvFile(global.CONF.System.TmpDir, map[string]string{"PGPASSWORD": r.Password})
	if err != nil {
		return err
	}
	defer os.Remove(envFile)
	recoverCommand := exec.Command("bash", "-c",
		remoteRecoverCommand(envFile, imageTag, r.Address, r.Port, r.User, info.Name, info.Username, fileName))
	pipe, _ := recoverCommand.StdoutPipe()
	stderrPipe, _ := recoverCommand.StderrPipe()
	defer pipe.Close()
	defer stderrPipe.Close()
	if err := recoverCommand.Start(); err != nil {
		return err
	}
	reader := bufio.NewReader(pipe)
	for {
		readString, err := reader.ReadString('\n')
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			all, _ := io.ReadAll(stderrPipe)
			global.LOG.Errorf("[Postgresql] DB:[%s] Recover Error: %s", info.Name, string(all))
			return err
		}
		global.LOG.Infof("[Postgresql] DB:[%s] Restoring: %s", info.Name, readString)
	}

	return nil
}

// validateRemoteFields whitelists every remote-controlled value that the
// backup/restore `docker run ... bash -c` commands interpolate into the
// single-quoted pg_dump/pg_restore invocation: r.Address and r.User come from
// the (user-supplied) remote connection record and info.Name may be re-synced
// from a malicious remote server (LoadFromRemote), so all three are rejected
// unless they fall inside the whitelist - before any docker image lookup,
// file access or command construction happens. The password is intentionally
// not covered here: it travels only via PGPASSWORD from the 0600 env file
// (cmd.WriteDockerEnvFile, see remoteBackupCommand/remoteRecoverCommand).
func validateRemoteFields(address, user, name string) error {
	if !cmd.ValidDBHost(address) {
		return fmt.Errorf("invalid remote database address: %q", address)
	}
	if !cmd.ValidDBUser(user) {
		return fmt.Errorf("invalid remote database user: %q", user)
	}
	if !cmd.ValidDBName(name) {
		return fmt.Errorf("invalid remote database name: %q", name)
	}
	return nil
}

func (r *Remote) SyncDB() ([]SyncDBInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
	defer cancel()

	var datas []SyncDBInfo
	rows, err := r.Client.Query("SELECT datname FROM pg_database;")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var dbName string
		if err := rows.Scan(&dbName); err != nil {
			continue
		}
		if len(dbName) == 0 || dbName == "postgres" || dbName == "template1" || dbName == "template0" || dbName == r.User {
			continue
		}
		datas = append(datas, SyncDBInfo{Name: dbName, From: r.From, PostgresqlName: r.Database})
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return nil, buserr.New(constant.ErrExecTimeOut)
	}
	return datas, nil
}

func (r *Remote) Close() {
	_ = r.Client.Close()
}

func (r *Remote) ExecSQL(command string, timeout uint) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	if _, err := r.Client.ExecContext(ctx, command); err != nil {
		return err
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return buserr.New(constant.ErrExecTimeOut)
	}

	return nil
}

// remoteBackupCommand builds the `docker run ... bash -c 'pg_dump ...'` shell
// command used by Remote Backup. The database password must never be
// interpolated into the returned string: `docker run -e PGPASSWORD=<password>`
// would expose the credential in the host bash argv (world-readable under
// /proc/<pid>/cmdline, 0444), from where every local user could read it.
// Instead the password is loaded from the 0600 env file
// (cmd.WriteDockerEnvFile) via `--env-file` into PGPASSWORD, which libpq and
// pg_dump honor natively. The redirect target is shellquoted so it stays a
// single argv word of the host bash process.
func remoteBackupCommand(envFile, imageTag, host string, port uint, user, database, outFile string) string {
	return fmt.Sprintf("docker run --rm --net=host -i --env-file %q %s /bin/bash -c 'pg_dump -h %s -p %d --no-owner -Fc -U %s %s' > %s",
		envFile, imageTag, host, port, user, database, shellquote(outFile))
}

// remoteRecoverCommand is the pg_restore sibling of remoteBackupCommand: same
// env-file handling (the password only travels via PGPASSWORD from the 0600
// env file, never through the command line), same shape as the pre-fix
// invocation. fileName is shellquoted like the backup redirect target.
func remoteRecoverCommand(envFile, imageTag, host string, port uint, user, database, role, fileName string) string {
	return fmt.Sprintf("docker run --rm --net=host -i --env-file %q %s /bin/bash -c 'pg_restore -h %s -p %d --verbose --clean --no-privileges --no-owner -Fc -U %s -d %s --role=%s' < %s",
		envFile, imageTag, host, port, user, database, role, shellquote(fileName))
}

// shellquote wraps a value in single quotes so it can be interpolated safely
// into the host `bash -c` command line: single quotes are closed, escaped
// and reopened, which makes the value opaque to the outer shell.
func shellquote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func loadImageTag() (string, error) {
	var (
		app        model.App
		appDetails []model.AppDetail
		versions   []string
	)
	if err := global.DB.Where("key = ?", "postgresql").First(&app).Error; err != nil {
		versions = []string{"postgres:16.1-alpine", "postgres:16.0-alpine"}
	} else {
		if err := global.DB.Where("app_id = ?", app.ID).Find(&appDetails).Error; err != nil {
			versions = []string{"postgres:16.1-alpine", "postgres:16.0-alpine"}
		} else {
			for _, item := range appDetails {
				versions = append(versions, "postgres:"+item.Version)
			}
		}
	}

	client, err := docker.NewDockerClient()
	if err != nil {
		return "", err
	}
	defer client.Close()
	images, err := client.ImageList(context.Background(), image.ListOptions{})
	if err != nil {
		return "", err
	}

	itemTag := ""
	for _, item := range versions {
		for _, image := range images {
			for _, tag := range image.RepoTags {
				if tag == item {
					itemTag = tag
					break
				}
			}
			if len(itemTag) != 0 {
				break
			}
		}
		if len(itemTag) != 0 {
			break
		}
	}
	if len(itemTag) != 0 {
		return itemTag, nil
	}

	sort.Strings(versions)
	if len(versions) != 0 {
		itemTag = versions[len(versions)-1]
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if _, err := client.ImagePull(ctx, itemTag, image.PullOptions{}); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return itemTag, buserr.New(constant.ErrPgImagePull)
		}
		global.LOG.Errorf("image %s pull failed, err: %v", itemTag, err)
		return itemTag, fmt.Errorf("image %s pull failed, err: %v", itemTag, err)
	}

	return itemTag, nil
}
