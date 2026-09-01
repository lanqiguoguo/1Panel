package client

import (
	"strings"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/constant"
	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/sirupsen/logrus"
)

// TestRemoteBackupRecoverRejectsIllegalFields is the regression test for the
// shell injection in remote Backup/Recover: host, user, charset and database
// name used to be interpolated unquoted into the host `bash -c` command, so a
// malicious remote server could return a database name like `x'; curl evil; 'y`
// (synced by LoadFromRemote) and achieve command execution on the panel host.
// The validation must fire before any connection, file or docker command is
// built, and a legal field set must still reach remoteRunCommand unchanged.
func TestRemoteBackupRecoverRejectsIllegalFields(t *testing.T) {
	r := NewRemote(Remote{
		Type:     constant.AppMysql,
		Address:  "10.0.0.5",
		Port:     3306,
		User:     "root",
		Password: "S3cr3t-P@ss",
	})

	malicious := []struct {
		name   string
		mutate func(info *BackupInfo)
	}{
		{"database-name", func(i *BackupInfo) { i.Name = "x'; curl evil; 'y" }},
		{"database-name-dollar", func(i *BackupInfo) { i.Name = "my$(id)db" }},
		{"database-name-backtick", func(i *BackupInfo) { i.Name = "my`id`db" }},
		{"database-name-space", func(i *BackupInfo) { i.Name = "my db" }},
		{"database-name-empty", func(i *BackupInfo) { i.Name = "" }},
		{"charset", func(i *BackupInfo) { i.Format = "utf8'; id; '" }},
		{"charset-space", func(i *BackupInfo) { i.Format = "utf8 mb4" }},
	}
	for _, tc := range malicious {
		info := BackupInfo{
			Name:      "panel_db",
			Type:      constant.AppMysql,
			Version:   "8.0",
			Format:    "utf8mb4",
			TargetDir: t.TempDir(),
			FileName:  "dump.sql.gz",
		}
		tc.mutate(&info)
		if err := r.Backup(info); err == nil {
			t.Errorf("Backup with %s = nil error, want rejection", tc.name)
		} else if !strings.Contains(err.Error(), "invalid") {
			t.Errorf("Backup with %s: unexpected error %v, want a validation error", tc.name, err)
		}
	}

	recoverInfo := RecoverInfo{
		Name:       "x'; id; 'y",
		Type:       constant.AppMysql,
		Version:    "8.0",
		Format:     "utf8mb4",
		SourceFile: "/nonexistent/dump.sql",
	}
	if err := r.Recover(recoverInfo); err == nil {
		t.Error("Recover with malicious database name = nil error, want rejection")
	}
	// The recover rejection must happen before the source file is even opened:
	// /nonexistent/dump.sql would surface an os error otherwise.
	if err := r.Recover(recoverInfo); err != nil && strings.Contains(err.Error(), "no such file") {
		t.Errorf("Recover validated fields too late: %v", err)
	}
}

// TestRemoteBackupAcceptsLegalFields pins the happy path: legal host/user/
// charset/name combinations must pass validation and proceed to the docker
// stage (which fails here because the temp target dir/name exercise the file
// layer, not the validation). We assert the error is NOT the validation one.
func TestRemoteBackupAcceptsLegalFields(t *testing.T) {
	// Backup() logs via global.LOG once past validation; a discard logger is
	// enough here because docker is not expected to actually run.
	origLog := global.LOG
	global.LOG = logrus.New()
	t.Cleanup(func() { global.LOG = origLog })

	r := NewRemote(Remote{
		Type:     constant.AppMysql,
		Address:  "db.example.com",
		Port:     3306,
		User:     "panel.user",
		Password: "S3cr3t-P@ss",
	})
	info := BackupInfo{
		Name:      "my-db.v2",
		Type:      constant.AppMysql,
		Version:   "8.0",
		Format:    "utf8mb4",
		TargetDir: t.TempDir(),
		FileName:  "dump.sql.gz",
	}
	err := r.Backup(info)
	if err != nil && strings.Contains(err.Error(), "invalid") {
		t.Fatalf("legal fields rejected: %v", err)
	}

	// IPv6 hosts keep working (bracketed form produced by mysql.NewMysqlClient).
	r6 := NewRemote(Remote{
		Type:     constant.AppMysql,
		Address:  "[2001:db8::1]",
		Port:     3306,
		User:     "root",
		Password: "S3cr3t-P@ss",
	})
	err = r6.Backup(info)
	if err != nil && strings.Contains(err.Error(), "invalid") {
		t.Fatalf("bracketed IPv6 host rejected: %v", err)
	}

	// Remote-side validation of a legal recover request must fire before the
	// source file is opened; with a nonexistent file the error must therefore
	// NOT be a validation error.
	err = r.Recover(RecoverInfo{
		Name:       "my-db.v2",
		Type:       constant.AppMysql,
		Version:    "8.0",
		Format:     "utf8mb4",
		SourceFile: "/nonexistent/dump.sql",
	})
	if err != nil && strings.Contains(err.Error(), "invalid") {
		t.Fatalf("legal recover fields rejected: %v", err)
	}
}

// TestRemoteValidateRemoteFields covers the guard function directly for the
// connection-record fields (host/user), which the Backup/Recover cases above
// can only exercise through the info fields.
func TestRemoteValidateRemoteFields(t *testing.T) {
	if err := validateRemoteFields("10.0.0.5", "root", "utf8mb4", "mydb"); err != nil {
		t.Errorf("legal fields rejected: %v", err)
	}
	for _, host := range []string{"", "10.0.0.1; id", "host $(id)", "host name"} {
		if err := validateRemoteFields(host, "root", "utf8mb4", "mydb"); err == nil {
			t.Errorf("host %q accepted, want rejection", host)
		}
	}
	for _, user := range []string{"", "root'; id; '", "root@%"} {
		if err := validateRemoteFields("10.0.0.5", user, "utf8mb4", "mydb"); err == nil {
			t.Errorf("user %q accepted, want rejection", user)
		}
	}
	for _, charset := range []string{"", "utf8; id", "utf8 mb4"} {
		if err := validateRemoteFields("10.0.0.5", "root", charset, "mydb"); err == nil {
			t.Errorf("charset %q accepted, want rejection", charset)
		}
	}
	for _, name := range []string{"", "x'; id; 'y", "$(id)", "`id`", "my db"} {
		if err := validateRemoteFields("10.0.0.5", "root", "utf8mb4", name); err == nil {
			t.Errorf("database name %q accepted, want rejection", name)
		}
	}
}
