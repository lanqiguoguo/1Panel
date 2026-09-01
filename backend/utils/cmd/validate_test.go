package cmd

import "testing"

// TestValidDBFields pins the whitelists used to guard the remote database
// backup/restore command construction (utils/mysql/client/remote.go and
// utils/postgresql/client/remote.go): every value interpolated into the host
// `bash -c` string must be free of shell metacharacters and whitespace, so a
// malicious remote server cannot smuggle commands through synced database
// names or a tampered connection record.
func TestValidDBFields(t *testing.T) {
	validNames := []string{
		"mydb",
		"my-db",
		"my_db",
		"my-db.v2",
		"MyDB01",
		"панель", // unicode letters stay legal (MySQL allows them unquoted)
		"01db",
	}
	for _, s := range validNames {
		if !ValidDBName(s) {
			t.Errorf("ValidDBName(%q) = false, want true", s)
		}
	}

	// "*" is the mysql grant-all wildcard used by ChangeAccess/CreateUser;
	// it must NOT pass the backup/restore whitelist because it is not a real
	// database name for the shell command.
	illegalNames := []string{
		"",
		"x'; id; 'y",
		"$(id)",
		"`id`",
		"my db",      // whitespace would split the shell word
		"my\tdb",     // tab splits like a space
		"my\ndb",     // newline = a second shell line
		"db;rm -rf/", // classic metacharacter
		"a|b",
		"a&b",
		"a>b",
		"a<b",
		`a"b`,
		"a'b",
		"..",
		".",
	}
	for _, s := range illegalNames {
		if ValidDBName(s) {
			t.Errorf("ValidDBName(%q) = true, want false", s)
		}
	}

	validUsers := []string{"root", "panel_user", "panel.user", "panel-user", "User01"}
	for _, s := range validUsers {
		if !ValidDBUser(s) {
			t.Errorf("ValidDBUser(%q) = false, want true", s)
		}
	}
	illegalUsers := []string{
		"",
		"root'; id; '",
		"root@%",
		"user name",
		"user$(id)",
		"user`id`",
		"user\n",
	}
	for _, s := range illegalUsers {
		if ValidDBUser(s) {
			t.Errorf("ValidDBUser(%q) = true, want false", s)
		}
	}

	validCharsets := []string{"utf8mb4", "utf8", "gbk", "big5", "utf8mb4_0900_ai_ci"}
	for _, s := range validCharsets {
		if !ValidDBCharset(s) {
			t.Errorf("ValidDBCharset(%q) = false, want true", s)
		}
	}
	illegalCharsets := []string{"", "utf8; id", "utf8 x", "$(id)", "utf8'quote"}
	for _, s := range illegalCharsets {
		if ValidDBCharset(s) {
			t.Errorf("ValidDBCharset(%q) = true, want false", s)
		}
	}

	validHosts := []string{
		"10.0.0.1",
		"db.example.com",
		"mysql-remote",
		"localhost",
		"db.example.com:3306",
		"::1",                    // bare IPv6
		"fe80::1%eth0",           // IPv6 zone index
		"[2001:db8::1]",          // pre-bracketed IPv6 (mysql.NewMysqlClient)
		"[2001:db8::1]:3306",
		"db.example.com:3306%eth0", // zone suffix after port
	}
	for _, s := range validHosts {
		if !ValidDBHost(s) {
			t.Errorf("ValidDBHost(%q) = false, want true", s)
		}
	}
	illegalHosts := []string{
		"",
		"10.0.0.1; id",
		"host $(id)",
		"host`id`",
		"host name",
		"10.0.0.1 -oProxyCommand=evil",
		"10.0.0.1\n",
		"host'quote",
		"host\"quote",
		"host|pipe",
		"host&bg",
	}
	for _, s := range illegalHosts {
		if ValidDBHost(s) {
			t.Errorf("ValidDBHost(%q) = true, want false", s)
		}
	}
}

// TestValidDBHostBracketsPinning documents that bracketed IPv6 keeps passing
// even though the address stored in the database record is unbracketed: the
// brackets are added by mysql.NewMysqlClient before the client ever sees it.
func TestValidDBHostBracketsPinning(t *testing.T) {
	// The stored form must be legal...
	if !ValidDBHost("2001:db8::1") {
		t.Fatalf("ValidDBHost(bare IPv6) = false, want true")
	}
	// ...and so must the bracketed form the client actually receives.
	if !ValidDBHost("[2001:db8::1]") {
		t.Fatalf("ValidDBHost(bracketed IPv6) = false, want true")
	}
}
