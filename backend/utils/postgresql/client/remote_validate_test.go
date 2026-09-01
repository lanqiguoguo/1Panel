package client

import (
	"strings"
	"testing"
)

// TestRemoteBackupRecoverRejectsIllegalFields is the regression test for the
// shell injection in remote Backup/Recover: r.Address, r.User and info.Name
// used to be interpolated unquoted into the host `bash -c` pg_dump/pg_restore
// command, so a malicious remote server could return a database name like
// `x'; curl evil; 'y` (synced by LoadFromRemote) and reach the panel host.
// The validation must fire before the docker image lookup / file access.
func TestRemoteBackupRecoverRejectsIllegalFields(t *testing.T) {
	r := NewRemote(Remote{
		Address:  "10.0.0.5",
		Port:     5432,
		User:     "postgres",
		Password: "S3cr3t-P@ss",
	})

	maliciousNames := []string{
		"x'; curl evil; 'y",
		"my$(id)db",
		"my`id`db",
		"my db",
		"",
		"db;rm -rf/",
	}
	for _, name := range maliciousNames {
		if err := r.Backup(BackupInfo{Name: name}); err == nil {
			t.Errorf("Backup with name %q = nil error, want rejection", name)
		} else if !strings.Contains(err.Error(), "invalid") {
			t.Errorf("Backup with name %q: unexpected error %v, want a validation error", name, err)
		}
		if err := r.Recover(RecoverInfo{Name: name, SourceFile: "/nonexistent/dump.sql"}); err == nil {
			t.Errorf("Recover with name %q = nil error, want rejection", name)
		}
	}

	// The recover rejection must happen before the source file is even opened:
	// /nonexistent/dump.sql would surface an os error otherwise.
	if err := r.Recover(RecoverInfo{Name: "x'; id; 'y", SourceFile: "/nonexistent/dump.sql"}); err != nil &&
		strings.Contains(err.Error(), "no such file") {
		t.Errorf("Recover validated fields too late: %v", err)
	}
}

// TestRemoteValidateRemoteFields covers the guard function directly for the
// connection-record fields (address/user), which the Backup/Recover cases
// above can only exercise through info.Name.
func TestRemoteValidateRemoteFields(t *testing.T) {
	if err := validateRemoteFields("db.example.com", "postgres", "mydb"); err != nil {
		t.Errorf("legal fields rejected: %v", err)
	}
	if err := validateRemoteFields("[2001:db8::1]", "postgres", "my-db.v2"); err != nil {
		t.Errorf("bracketed IPv6 rejected: %v", err)
	}
	for _, address := range []string{"", "10.0.0.1; id", "host $(id)", "host name", "host|pipe"} {
		if err := validateRemoteFields(address, "postgres", "mydb"); err == nil {
			t.Errorf("address %q accepted, want rejection", address)
		}
	}
	for _, user := range []string{"", "postgres'; id; '", "postgres $(id)"} {
		if err := validateRemoteFields("10.0.0.5", user, "mydb"); err == nil {
			t.Errorf("user %q accepted, want rejection", user)
		}
	}
	for _, name := range []string{"", "x'; id; 'y", "`id`", "my db"} {
		if err := validateRemoteFields("10.0.0.5", "postgres", name); err == nil {
			t.Errorf("database name %q accepted, want rejection", name)
		}
	}
}

// TestRemoteShellquotePinning keeps the existing single-quote escaping of the
// PGPASSWORD value intact: it is the only reason a password containing shell
// metacharacters stays inert inside the bash -c string.
func TestRemoteShellquotePinning(t *testing.T) {
	if got := shellquote("pa'ss"); got != `'pa'\''ss'` {
		t.Errorf("shellquote(pa'ss) = %q, want 'pa'\\''ss'", got)
	}
	if got := shellquote("plain"); got != `'plain'` {
		t.Errorf("shellquote(plain) = %q, want 'plain'", got)
	}
}
