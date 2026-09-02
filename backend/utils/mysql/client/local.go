package client

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"strings"
	"time"

	"github.com/1Panel-dev/1Panel/backend/buserr"
	"github.com/1Panel-dev/1Panel/backend/constant"
	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/1Panel-dev/1Panel/backend/utils/cmd"
	"github.com/1Panel-dev/1Panel/backend/utils/files"
)

type Local struct {
	Type          string
	PrefixCommand []string
	Database      string
	Password      string
	ContainerName string
}

func NewLocal(command []string, dbType, containerName, password, database string) *Local {
	return &Local{Type: dbType, PrefixCommand: command, ContainerName: containerName, Password: password, Database: database}
}

func (r *Local) Create(info CreateInfo) error {
	createSql := fmt.Sprintf("create database `%s` default character set %s collate %s", info.Name, info.Format, formatMap[info.Format])
	if err := r.ExecSQL(createSql, info.Timeout); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "error 1007") {
			return buserr.New(constant.ErrDatabaseIsExist)
		}
		return err
	}

	if err := r.CreateUser(info, true); err != nil {
		_ = r.ExecSQL(fmt.Sprintf("drop database if exists `%s`", info.Name), info.Timeout)
		return err
	}

	return nil
}

func (r *Local) CreateUser(info CreateInfo, withDeleteDB bool) error {
	var userlist []string
	if strings.Contains(info.Permission, ",") {
		ips := strings.Split(info.Permission, ",")
		for _, ip := range ips {
			if len(ip) != 0 {
				userlist = append(userlist, fmt.Sprintf("'%s'@'%s'", info.Username, ip))
			}
		}
	} else {
		userlist = append(userlist, fmt.Sprintf("'%s'@'%s'", info.Username, info.Permission))
	}

	for _, user := range userlist {
		if err := r.ExecSQL(fmt.Sprintf("create user %s identified by '%s';", user, info.Password), info.Timeout); err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "error 1396") {
				return buserr.New(constant.ErrUserIsExist)
			}
			if withDeleteDB {
				_ = r.Delete(DeleteInfo{
					Name:        info.Name,
					Version:     info.Version,
					Username:    info.Username,
					Permission:  info.Permission,
					ForceDelete: true,
					Timeout:     300})
			}
			return err
		}
		grantStr := fmt.Sprintf("grant all privileges on `%s`.* to %s", info.Name, user)
		if info.Name == "*" {
			grantStr = fmt.Sprintf("grant all privileges on *.* to %s", user)
		}
		if strings.HasPrefix(info.Version, "5.7") || strings.HasPrefix(info.Version, "5.6") {
			grantStr = fmt.Sprintf("%s identified by '%s' with grant option;", grantStr, info.Password)
		} else {
			grantStr = grantStr + " with grant option;"
		}
		if err := r.ExecSQL(grantStr, info.Timeout); err != nil {
			if withDeleteDB {
				_ = r.Delete(DeleteInfo{
					Name:        info.Name,
					Version:     info.Version,
					Username:    info.Username,
					Permission:  info.Permission,
					ForceDelete: true,
					Timeout:     300})
			}
			return err
		}
	}
	return nil
}

func (r *Local) Delete(info DeleteInfo) error {
	var userlist []string
	if strings.Contains(info.Permission, ",") {
		ips := strings.Split(info.Permission, ",")
		for _, ip := range ips {
			if len(ip) != 0 {
				userlist = append(userlist, fmt.Sprintf("'%s'@'%s'", info.Username, ip))
			}
		}
	} else {
		userlist = append(userlist, fmt.Sprintf("'%s'@'%s'", info.Username, info.Permission))
	}

	for _, user := range userlist {
		if strings.HasPrefix(info.Version, "5.6") {
			if err := r.ExecSQL(fmt.Sprintf("drop user %s", user), info.Timeout); err != nil && !info.ForceDelete {
				return err
			}
		} else {
			if err := r.ExecSQL(fmt.Sprintf("drop user if exists %s", user), info.Timeout); err != nil && !info.ForceDelete {
				return err
			}
		}
	}
	if len(info.Name) != 0 {
		if err := r.ExecSQL(fmt.Sprintf("drop database if exists `%s`", info.Name), info.Timeout); err != nil && !info.ForceDelete {
			return err
		}
	}
	if !info.ForceDelete {
		global.LOG.Info("execute delete database sql successful, now start to drop uploads and records")
	}

	return nil
}

func (r *Local) ChangePassword(info PasswordChangeInfo) error {
	if info.Username != "root" {
		var userlist []string
		if strings.Contains(info.Permission, ",") {
			ips := strings.Split(info.Permission, ",")
			for _, ip := range ips {
				if len(ip) != 0 {
					userlist = append(userlist, fmt.Sprintf("'%s'@'%s'", info.Username, ip))
				}
			}
		} else {
			userlist = append(userlist, fmt.Sprintf("'%s'@'%s'", info.Username, info.Permission))
		}

		for _, user := range userlist {
			passwordChangeSql := fmt.Sprintf("set password for %s = password('%s')", user, info.Password)
			if !strings.HasPrefix(info.Version, "5.7") && !strings.HasPrefix(info.Version, "5.6") {
				passwordChangeSql = fmt.Sprintf("ALTER USER %s IDENTIFIED BY '%s';", user, info.Password)
			}
			if err := r.ExecSQL(passwordChangeSql, info.Timeout); err != nil {
				return err
			}
		}
		return nil
	}

	hosts, err := r.ExecSQLForRows("select host from mysql.user where user='root';", info.Timeout)
	if err != nil {
		return err
	}
	for _, host := range hosts {
		if host == "%" || host == "localhost" {
			passwordRootChangeCMD := fmt.Sprintf("set password for 'root'@'%s' = password('%s')", host, info.Password)
			if !strings.HasPrefix(info.Version, "5.7") && !strings.HasPrefix(info.Version, "5.6") {
				passwordRootChangeCMD = fmt.Sprintf("alter user 'root'@'%s' identified by '%s';", host, info.Password)
			}
			if err := r.ExecSQL(passwordRootChangeCMD, info.Timeout); err != nil {
				return err
			}
		}
	}

	return nil
}

func (r *Local) ChangeAccess(info AccessChangeInfo) error {
	if info.Username == "root" {
		info.OldPermission = "%"
		info.Name = "*"
		info.Password = r.Password
	}
	if info.Permission != info.OldPermission {
		if err := r.Delete(DeleteInfo{
			Version:     info.Version,
			Username:    info.Username,
			Permission:  info.OldPermission,
			ForceDelete: true,
			Timeout:     300}); err != nil {
			return err
		}
		if info.Username == "root" {
			return nil
		}
	}
	if err := r.CreateUser(CreateInfo{
		Name:       info.Name,
		Version:    info.Version,
		Username:   info.Username,
		Password:   info.Password,
		Permission: info.Permission,
		Timeout:    info.Timeout,
	}, false); err != nil {
		return err
	}
	if err := r.ExecSQL("flush privileges", 300); err != nil {
		return err
	}
	return nil
}

func (r *Local) Backup(info BackupInfo) error {
	outPath, outfile, err := backupOutFile(info.TargetDir, info.FileName)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		outfile.Close()
		// Never leave a partial dump behind on a failed path: it would sit in
		// the backup dir with 0600 as a confusing half file and would be
		// offered as a valid backup by later directory listings.
		if !ok {
			_ = os.Remove(outPath)
		}
	}()
	dumpCmd := "mysqldump"
	if r.Type == constant.AppMariaDB {
		dumpCmd = "mariadb-dump"
	}
	global.LOG.Infof("start to %s | gzip > %s.gzip", dumpCmd, info.TargetDir+"/"+info.FileName)
	envFile, err := cmd.WriteDockerEnvFile(global.CONF.System.TmpDir, map[string]string{"MYSQL_PWD": r.Password})
	if err != nil {
		return err
	}
	defer os.Remove(envFile)
	// MYSQL_PWD reaches the container through `docker exec --env-file` (read
	// by the docker CLI over the daemon socket), so the password never
	// appears in the docker exec argv that is world-readable under /proc.
	cmdItem := exec.Command("docker", "exec", "--env-file", envFile, r.ContainerName, dumpCmd, "--routines", "-uroot", "--default-character-set="+info.Format, info.Name)
	var stderr bytes.Buffer
	cmdItem.Stderr = &stderr

	gzipCmd := exec.Command("gzip", "-cf")
	gzipCmd.Stdin, _ = cmdItem.StdoutPipe()
	gzipCmd.Stdout = outfile
	if err := gzipCmd.Start(); err != nil {
		return fmt.Errorf("start gzip failed, err: %v", err)
	}

	if err := cmdItem.Run(); err != nil {
		return fmt.Errorf("handle backup database failed, err: %v", stderr.String())
	}
	if err := gzipCmd.Wait(); err != nil {
		return fmt.Errorf("compress backup database failed, err: %v", err)
	}
	ok = true
	return nil
}

// backupOutFile prepares the output file of a dump: it creates targetDir
// (0750, not os.ModePerm 0777 - the dumped SQL embeds the whole database
// content and must not be readable or replaceable by other local users) and
// then the file itself with 0600. A world-readable mode would expose partial
// (still sensitive) data while the dump is streamed into the file. The
// caller must remove the returned path when the backup fails.
func backupOutFile(targetDir, fileName string) (string, *os.File, error) {
	// The dump file name must be a plain base name: a caller-supplied
	// traversal would otherwise redirect the dump (or its cleanup) outside
	// the intended backup directory.
	if fileName == "" || fileName == "." || fileName == ".." || strings.ContainsAny(fileName, `/\`) {
		return "", nil, fmt.Errorf("invalid backup file name %q", fileName)
	}
	fileOp := files.NewFileOp()
	if !fileOp.Stat(targetDir) {
		if err := os.MkdirAll(targetDir, 0750); err != nil {
			return "", nil, fmt.Errorf("mkdir %s failed, err: %v", targetDir, err)
		}
	}
	outPath := path.Join(targetDir, fileName)
	outfile, err := os.OpenFile(outPath, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return "", nil, fmt.Errorf("open file %s failed, err: %v", outPath, err)
	}
	return outPath, outfile, nil
}

func (r *Local) Recover(info RecoverInfo) error {
	fi, _ := os.Open(info.SourceFile)
	defer fi.Close()
	envFile, err := cmd.WriteDockerEnvFile(global.CONF.System.TmpDir, map[string]string{"MYSQL_PWD": r.Password})
	if err != nil {
		return err
	}
	defer os.Remove(envFile)
	// See Backup: the password travels via `docker exec --env-file` only, so
	// it never shows up in the world-readable process argv.
	cmdItem := exec.Command("docker", "exec", "-i", "--env-file", envFile, r.ContainerName, r.Type, "-uroot", "--default-character-set="+info.Format, info.Name)
	if strings.HasSuffix(info.SourceFile, ".gz") {
		gzipFile, err := os.Open(info.SourceFile)
		if err != nil {
			return err
		}
		defer gzipFile.Close()
		gzipReader, err := gzip.NewReader(gzipFile)
		if err != nil {
			return err
		}
		defer gzipReader.Close()
		cmdItem.Stdin = gzipReader
	} else {
		cmdItem.Stdin = fi
	}
	stdout, err := cmdItem.CombinedOutput()
	stdStr := strings.ReplaceAll(string(stdout), "mysql: [Warning] Using a password on the command line interface can be insecure.\n", "")
	if err != nil || strings.HasPrefix(string(stdStr), "ERROR ") {
		return errors.New(stdStr)
	}

	return nil
}

func (r *Local) SyncDB(version string) ([]SyncDBInfo, error) {
	var datas []SyncDBInfo
	lines, err := r.ExecSQLForRows("SELECT SCHEMA_NAME, DEFAULT_CHARACTER_SET_NAME FROM information_schema.SCHEMATA", 300)
	if err != nil {
		return datas, err
	}
	for _, line := range lines {
		parts := strings.Fields(line)
		if len(parts) != 2 {
			continue
		}
		if parts[0] == "SCHEMA_NAME" || parts[0] == "information_schema" || parts[0] == "mysql" || parts[0] == "performance_schema" || parts[0] == "sys" || parts[0] == "__recycle_bin__" || parts[0] == "recycle_bin" {
			continue
		}
		dataItem := SyncDBInfo{
			Name:      parts[0],
			From:      "local",
			MysqlName: r.Database,
			Format:    parts[1],
		}
		userLines, err := r.ExecSQLForRows(fmt.Sprintf("select user,host from mysql.db where db = '%s'", parts[0]), 300)
		if err != nil {
			global.LOG.Debugf("sync user of db %s failed, err: %v", parts[0], err)
			dataItem.Permission = "%"
			datas = append(datas, dataItem)
			continue
		}

		var permissionItem []string
		isLocal := true
		i := 0
		for _, userline := range userLines {
			userparts := strings.Fields(userline)
			if len(userparts) != 2 {
				continue
			}
			if userparts[0] == "root" {
				continue
			}
			if i == 0 {
				dataItem.Username = userparts[0]
			}
			dataItem.Username = userparts[0]
			if dataItem.Username == userparts[0] && userparts[1] == "%" {
				isLocal = false
				dataItem.Permission = "%"
			} else if dataItem.Username == userparts[0] && userparts[1] != "localhost" {
				isLocal = false
				permissionItem = append(permissionItem, userparts[1])
			}
		}
		if len(dataItem.Username) == 0 {
			dataItem.Permission = "%"
		} else {
			if isLocal {
				dataItem.Permission = "localhost"
			}
			if len(dataItem.Permission) == 0 {
				dataItem.Permission = strings.Join(permissionItem, ",")
			}
		}
		datas = append(datas, dataItem)
	}
	return datas, nil
}

func (r *Local) Close() {}

func (r *Local) ExecSQL(command string, timeout uint) error {
	itemCommand := r.PrefixCommand[:]
	itemCommand = append(itemCommand, command)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()
	cmdItem, cleanup, err := r.execWithEnvFile(ctx, itemCommand)
	if err != nil {
		return err
	}
	defer cleanup()
	stdout, err := cmdItem.CombinedOutput()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return buserr.New(constant.ErrExecTimeOut)
	}
	stdStr := strings.ReplaceAll(string(stdout), "mysql: [Warning] Using a password on the command line interface can be insecure.\n", "")
	if err != nil || strings.HasPrefix(string(stdStr), "ERROR ") {
		return errors.New(stdStr)
	}
	return nil
}

func (r *Local) ExecSQLForRows(command string, timeout uint) ([]string, error) {
	itemCommand := r.PrefixCommand[:]
	itemCommand = append(itemCommand, command)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()
	cmdItem, cleanup, err := r.execWithEnvFile(ctx, itemCommand)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	stdout, err := cmdItem.CombinedOutput()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return nil, buserr.New(constant.ErrExecTimeOut)
	}
	stdStr := strings.ReplaceAll(string(stdout), "mysql: [Warning] Using a password on the command line interface can be insecure.\n", "")
	if err != nil || strings.HasPrefix(string(stdStr), "ERROR ") {
		return nil, errors.New(stdStr)
	}
	return strings.Split(stdStr, "\n"), nil
}

// execWithEnvFile builds the docker exec command for the given args, handing
// the database password to the container through `--env-file` (MYSQL_PWD) so
// it never appears in the world-readable process argv. The returned cleanup
// removes the env file; the caller must invoke it after the command finishes.
func (r *Local) execWithEnvFile(ctx context.Context, itemCommand []string) (*exec.Cmd, func(), error) {
	if len(itemCommand) == 0 {
		return nil, nil, errors.New("empty docker exec command")
	}
	envFile, err := cmd.WriteDockerEnvFile(global.CONF.System.TmpDir, map[string]string{"MYSQL_PWD": r.Password})
	if err != nil {
		return nil, nil, err
	}
	fullArgs := make([]string, 0, len(itemCommand)+2)
	fullArgs = append(fullArgs, "exec", "--env-file", envFile)
	fullArgs = append(fullArgs, itemCommand[1:]...)
	cmdItem := exec.CommandContext(ctx, "docker", fullArgs...)
	return cmdItem, func() { _ = os.Remove(envFile) }, nil
}
