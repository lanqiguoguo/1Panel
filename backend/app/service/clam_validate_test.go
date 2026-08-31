package service

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/app/dto"
	"github.com/1Panel-dev/1Panel/backend/app/model"
	"github.com/1Panel-dev/1Panel/backend/buserr"
	"github.com/1Panel-dev/1Panel/backend/constant"
	"github.com/1Panel-dev/1Panel/backend/global"

	"github.com/glebarez/sqlite"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

// isClamErr reports whether err is the buserr business error the clam
// validators raise for the given constant (mirrors isErrCmdIllegal in
// cronjob_validate_test.go).
func isClamErr(t *testing.T, err error, want string) bool {
	t.Helper()
	var bizErr buserr.BusinessError
	return errors.As(err, &bizErr) && bizErr.Msg == want
}

func TestValidClamName(t *testing.T) {
	valid := []string{
		"my-scan",
		"Scan_01",
		"a",
		"x-y_z09",
		// 64 chars: the model.Clam name column cap the whitelist enforces
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	invalid := []string{
		"",         // empty
		"x$(id)",   // command substitution
		"../..",    // traversal
		"..",       // traversal
		"a/b",      // path separator
		`a\b`,      // path separator
		"a b",      // space (bash word-splitting in unquoted Execf)
		"a;b",      // shell metacharacter
		"a|b",      // shell metacharacter
		"a&b",      // shell metacharacter
		"a`id`b",   // shell metacharacter
		"a'b",      // shell metacharacter
		"a\"b",     // shell metacharacter
		"名前",       // outside the whitelist charset
		"_leading", // starts with an underscore like the frontend rule
		"-leading", // starts with a dash (would read as a clamdscan flag)
		"a\tb",     // invisible separator
		"a\nb",     // invisible separator
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1", // 65 chars > column cap
	}

	for _, s := range valid {
		if !validClamName(s) {
			t.Errorf("validClamName(%q) = false, want true", s)
		}
	}
	for _, s := range invalid {
		if validClamName(s) {
			t.Errorf("validClamName(%q) = true, want false", s)
		}
	}
}

func TestValidClamRecordName(t *testing.T) {
	// Records are created by HandleOnce as DataDir/clamav/<name>/<DateTimeSlimLayout>,
	// i.e. a plain 14-digit timestamp.
	valid := []string{"20260102030405", "19991231235959"}
	invalid := []string{
		"",
		"../../../etc/shadow", // the probed traversal payload
		"../..",
		"2026010203040",   // 13 digits
		"202601020304055", // 15 digits
		"2026010203040a",
		"a/b",
		".",
		"..",
		"-1",
		"20260102030405 ",
	}
	for _, s := range valid {
		if !validClamRecordName(s) {
			t.Errorf("validClamRecordName(%q) = false, want true", s)
		}
	}
	for _, s := range invalid {
		if validClamRecordName(s) {
			t.Errorf("validClamRecordName(%q) = true, want false", s)
		}
	}
}

func TestValidClamScanDir(t *testing.T) {
	valid := []string{
		"/tmp/quarantine",
		"/opt/1panel_infected",
		"/data/quarantine-01",
	}
	invalid := []string{
		"",               // empty (rejected: used unquoted in --move=/--copy=)
		"x$(id)",         // command substitution
		"/tmp/x;id",      // shell metacharacter
		"/tmp/a b",       // space: bash word-splits the unquoted --move=
		"/tmp/a\\b",      // backslash: bash escape in unquoted interpolation
		"../etc",         // relative: resolves against clamdscan cwd
		"etc/quarantine", // relative
		"/tmp/../../etc", // absolute, but the cleaned target escapes the intent
		"/tmp\nx",        // newline
	}
	for _, s := range valid {
		if !validClamScanDir(s) {
			t.Errorf("validClamScanDir(%q) = false, want true", s)
		}
	}
	for _, s := range invalid {
		if validClamScanDir(s) {
			t.Errorf("validClamScanDir(%q) = true, want false", s)
		}
	}
}

func TestValidClamTail(t *testing.T) {
	valid := []string{"0", "10", "100", "999999999"}
	invalid := []string{
		"",
		"-1 /etc/passwd",
		"+1;id",
		"10 5",
		"1e3",
		"0x10",
		"9999999990", // 10 digits > cap
	}
	for _, s := range valid {
		if !validClamTail(s) {
			t.Errorf("validClamTail(%q) = false, want true", s)
		}
	}
	for _, s := range invalid {
		if validClamTail(s) {
			t.Errorf("validClamTail(%q) = true, want false", s)
		}
	}
}

// TestValidateClamParams covers the shared Create/Update gate: malicious
// names, paths and infected dirs must be rejected, and legitimate values
// (including the empty InfectedDir the none/remove strategies use) must pass.
func TestValidateClamParams(t *testing.T) {
	cases := []struct {
		name         string
		reqName      string
		scanPath     string
		strategy     string
		infectedDir  string
		wantErrConst string // "" means success
	}{
		{"legal none strategy", "my-scan", "/tmp/www", "none", "", ""},
		{"legal remove strategy", "my-scan", "/tmp/www", "remove", "", ""},
		{"legal move strategy", "my-scan", "/tmp/www", "move", "/tmp/quarantine", ""},
		{"legacy empty strategy", "my-scan", "/tmp/www", "", "", ""},
		{"malicious name substitution", "x$(id)", "/tmp/www", "none", "", constant.ErrCmdIllegal},
		{"malicious name traversal", "../..", "/tmp/www", "none", "", constant.ErrCmdIllegal},
		{"malicious name with space/semicolon", "a b;c", "/tmp/www", "none", "", constant.ErrCmdIllegal},
		{"malicious name backtick", "`id`", "/tmp/www", "none", "", constant.ErrCmdIllegal},
		{"malicious name empty", "", "/tmp/www", "none", "", constant.ErrCmdIllegal},
		{"malicious path substitution", "my-scan", "/tmp/$(id)", "none", "", constant.ErrCmdIllegal},
		{"malicious path semicolon", "my-scan", "/tmp/a;b", "none", "", constant.ErrCmdIllegal},
		{"malicious path space", "my-scan", "/tmp/a b", "none", "", constant.ErrCmdIllegal},
		{"malicious path empty", "my-scan", "", "none", "", constant.ErrCmdIllegal},
		{"malicious infected dir relative", "my-scan", "/tmp/www", "move", "../etc", constant.ErrCmdIllegal},
		{"malicious infected dir substitution", "my-scan", "/tmp/www", "copy", "/tmp/$(id)", constant.ErrCmdIllegal},
		{"malicious infected dir empty", "my-scan", "/tmp/www", "move", "", constant.ErrCmdIllegal},
		{"unknown strategy", "my-scan", "/tmp/www", "wipe", "", constant.ErrTypeInvalidParams},
	}
	for _, tc := range cases {
		err := validateClamParams(tc.reqName, tc.scanPath, tc.strategy, tc.infectedDir)
		if tc.wantErrConst == "" {
			if err != nil {
				t.Errorf("%s: validateClamParams(%q,%q,%q,%q) = %v, want nil", tc.name, tc.reqName, tc.scanPath, tc.strategy, tc.infectedDir, err)
			}
			continue
		}
		if !isClamErr(t, err, tc.wantErrConst) {
			t.Errorf("%s: validateClamParams(%q,%q,%q,%q) = %v, want %s", tc.name, tc.reqName, tc.scanPath, tc.strategy, tc.infectedDir, err, tc.wantErrConst)
		}
	}
}

// setupClamTestDB wires an in-memory sqlite with the Clam table so the
// service methods can read rows back through clamRepo.
func setupClamTestDB(t *testing.T) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open in-memory sqlite failed: %v", err)
	}
	if err := db.AutoMigrate(&model.Clam{}); err != nil {
		t.Fatalf("migrate %T failed: %v", &model.Clam{}, err)
	}
	global.DB = db
	if global.LOG == nil {
		global.LOG = logrus.New()
	}
}

// TestCreateUpdateMaliciousParams runs the service-boundary gate end to end:
// neither Create nor Update may persist a row whose name/path/infected dir
// carries shell or traversal payloads.
func TestCreateUpdateMaliciousParams(t *testing.T) {
	setupClamTestDB(t)
	svc := NewIClamService()

	malicious := []dto.ClamCreate{
		{Name: "x$(id)", Path: "/tmp/www", InfectedStrategy: "none"},
		{Name: "../..", Path: "/tmp/www", InfectedStrategy: "none"},
		{Name: "a b;c", Path: "/tmp/www", InfectedStrategy: "none"},
		{Name: "ok-name", Path: "/tmp/www", InfectedStrategy: "move", InfectedDir: "../etc"},
		{Name: "ok-name", Path: "/tmp/www", InfectedStrategy: "copy", InfectedDir: "/tmp/$(id)"},
		{Name: "ok-name", Path: "/tmp/;id", InfectedStrategy: "none"},
	}
	for i, req := range malicious {
		if err := svc.Create(req); err == nil {
			t.Errorf("Create case %d (%s): expected error, got nil", i, req.Name)
		}
		upd := dto.ClamUpdate{ID: 1, Name: req.Name, Path: req.Path, InfectedStrategy: req.InfectedStrategy, InfectedDir: req.InfectedDir}
		if err := svc.Update(upd); err == nil {
			t.Errorf("Update case %d (%s): expected error, got nil", i, req.Name)
		}
	}

	// Legitimate values must pass the gate (row existence checked first for
	// Update, so Create actually persists here).
	legal := dto.ClamCreate{Name: "my-scan", Path: "/tmp/www", InfectedStrategy: "move", InfectedDir: "/tmp/quarantine"}
	if err := svc.Create(legal); err != nil {
		t.Fatalf("Create legal: unexpected error: %v", err)
	}
	if err := svc.Update(dto.ClamUpdate{ID: 1, Name: "my-scan", Path: "/tmp/www2", InfectedStrategy: "none"}); err != nil {
		t.Fatalf("Update legal: unexpected error: %v", err)
	}
}

// TestLoadRecordLogTraversal reproduces the probed /etc/shadow read: a
// traversal pair must be refused before any path is joined, and a legal
// record must still be readable.
func TestLoadRecordLogTraversal(t *testing.T) {
	dataDir := t.TempDir()
	oldDataDir := global.CONF.System.DataDir
	global.CONF.System.DataDir = dataDir
	defer func() { global.CONF.System.DataDir = oldDataDir }()

	recordDir := filepath.Join(dataDir, "clamav", "my-scan")
	if err := os.MkdirAll(recordDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	secret := filepath.Join(dataDir, "secret.txt")
	if err := os.WriteFile(secret, []byte("SECRET"), 0644); err != nil {
		t.Fatalf("write secret: %v", err)
	}
	logFile := filepath.Join(recordDir, "20260102030405")
	if err := os.WriteFile(logFile, []byte("LOG CONTENT"), 0644); err != nil {
		t.Fatalf("write log: %v", err)
	}

	svc := NewIClamService()

	// the probed payload: traversal pair must be refused
	for _, req := range []dto.ClamLogReq{
		{Tail: "100", ClamName: "../..", RecordName: "../../../etc/shadow"},
		{Tail: "100", ClamName: "my-scan", RecordName: "../../../etc/shadow"},
		{Tail: "100", ClamName: "../..", RecordName: "20260102030405"},
		{Tail: "100", ClamName: "a/b", RecordName: "20260102030405"},
		{Tail: "-1 /etc/passwd", ClamName: "my-scan", RecordName: "20260102030405"},
		{Tail: "100;id", ClamName: "my-scan", RecordName: "20260102030405"},
		{Tail: "", ClamName: "my-scan", RecordName: "20260102030405"},
	} {
		content, err := svc.LoadRecordLog(req)
		if err == nil {
			t.Errorf("LoadRecordLog(%+v): expected error, got content %q", req, content)
		}
		if content == "SECRET" {
			t.Errorf("LoadRecordLog(%+v): leaked the traversal target", req)
		}
	}

	// legal request keeps working
	content, err := svc.LoadRecordLog(dto.ClamLogReq{Tail: "100", ClamName: "my-scan", RecordName: "20260102030405"})
	if err != nil {
		t.Fatalf("LoadRecordLog legal: unexpected error: %v", err)
	}
	if content != "LOG CONTENT" {
		t.Fatalf("LoadRecordLog legal: got %q, want %q", content, "LOG CONTENT")
	}
	content, err = svc.LoadRecordLog(dto.ClamLogReq{Tail: "0", ClamName: "my-scan", RecordName: "20260102030405"})
	if err != nil {
		t.Fatalf("LoadRecordLog legal tail 0: unexpected error: %v", err)
	}
	if content != "LOG CONTENT" {
		t.Fatalf("LoadRecordLog legal tail 0: got %q, want %q", content, "LOG CONTENT")
	}
}
