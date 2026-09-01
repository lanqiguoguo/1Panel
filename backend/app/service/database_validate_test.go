package service

import (
	"context"
	"strings"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/app/dto"
	"github.com/1Panel-dev/1Panel/backend/app/model"
	"github.com/1Panel-dev/1Panel/backend/constant"
	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/1Panel-dev/1Panel/backend/utils/mysql/client"
	"github.com/glebarez/sqlite"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

// TestValidRemoteSyncedDB pins the pollution-source gate of LoadFromRemote
// (database_mysql.go / database_postgresql.go): a malicious or compromised
// remote server can report database names like `x'; id; 'y` through SyncDB,
// which the backup/restore path later interpolates unquoted into the host
// `bash -c` command. Such rows must be skipped during the sync (without
// aborting the whole batch), while ordinary names keep syncing.
func TestValidRemoteSyncedDB(t *testing.T) {
	legal := []struct {
		name   string
		format string
	}{
		{"mydb", "utf8mb4"},
		{"my-db.v2", "utf8"},
		{"panel_01", "gbk"},
		{"панель", "utf8mb4"}, // unicode letters stay legal
		{"pgdb", ""},          // pg SyncDB rows carry no charset
	}
	for _, tc := range legal {
		if !validRemoteSyncedDB(tc.name, tc.format) {
			t.Errorf("validRemoteSyncedDB(%q, %q) = false, want true", tc.name, tc.format)
		}
	}

	illegal := []struct {
		name   string
		format string
	}{
		{"x'; id; 'y", "utf8mb4"},          // shell injection name
		{"my$(id)db", "utf8mb4"},           // command substitution
		{"my`id`db", "utf8mb4"},            // backtick substitution
		{"my db", "utf8mb4"},               // whitespace splits the shell word
		{"", "utf8mb4"},                    // empty name
		{"mydb", "utf8'; id; '"},           // malicious charset
		{"mydb", "utf8 mb4"},               // charset with whitespace
		{"mydb", "utf8mb4_x; drop table"},  // charset with metacharacter
	}
	for _, tc := range illegal {
		if validRemoteSyncedDB(tc.name, tc.format) {
			t.Errorf("validRemoteSyncedDB(%q, %q) = true, want false", tc.name, tc.format)
		}
	}
}

// setupLoadFromRemoteFilterTest prepares an in-memory sqlite DB with the
// database/databases_mysql/databases_postgresql tables so the sync-filter
// behaviour can be exercised through the real repo layer.
func setupLoadFromRemoteFilterTest(t *testing.T) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open in-memory sqlite failed: %v", err)
	}
	if err := db.AutoMigrate(&model.Database{}, &model.DatabaseMysql{}, &model.DatabasePostgresql{}); err != nil {
		t.Fatalf("migrate database models failed: %v", err)
	}
	global.DB = db

	origLog := global.LOG
	global.LOG = logrus.New()
	t.Cleanup(func() { global.LOG = origLog })
}

// TestLoadFromRemoteSkipFilterKeepsLegalRows drives the sync filter through
// the mysql repo layer: with a pre-existing legal record, a SyncDB batch
// containing a legal new db, the same db again and two malicious rows must
// produce exactly one new record (the legal one) - the malicious rows are
// skipped by the LoadFromRemote loop, not persisted.
func TestLoadFromRemoteSkipFilterKeepsLegalRows(t *testing.T) {
	setupLoadFromRemoteFilterTest(t)

	if err := global.DB.Create(&model.DatabaseMysql{
		Name: "existing", From: "remote", MysqlName: "remote-db",
		Format: "utf8mb4", Username: "u", Password: "", Permission: "%",
	}).Error; err != nil {
		t.Fatalf("seed existing row failed: %v", err)
	}

	datas := []client.SyncDBInfo{
		{Name: "legal_db", From: "remote", MysqlName: "remote-db", Format: "utf8mb4"},
		{Name: "existing", From: "remote", MysqlName: "remote-db", Format: "utf8mb4"},
		{Name: "x'; id; 'y", From: "remote", MysqlName: "remote-db", Format: "utf8mb4"},
		{Name: "legal_charset_ok", From: "remote", MysqlName: "remote-db", Format: "utf8'; id; '"},
	}

	// Replay the LoadFromRemote filter loop over the seeded table. The real
	// method cannot be called offline (LoadMysqlClientByFrom needs a live
	// remote server), so the filter and the hasOld dedup are exercised exactly
	// as written there.
	existingRows, err := mysqlRepo.List(mysqlRepo.WithByMysqlName("remote-db"))
	if err != nil {
		t.Fatalf("list existing rows failed: %v", err)
	}
	for _, data := range datas {
		if !validRemoteSyncedDB(data.Name, data.Format) {
			continue
		}
		hasOld := false
		for i := 0; i < len(existingRows); i++ {
			if strings.EqualFold(existingRows[i].Name, data.Name) && strings.EqualFold(existingRows[i].MysqlName, data.MysqlName) {
				hasOld = true
				break
			}
		}
		if hasOld {
			continue
		}
		var createItem model.DatabaseMysql
		createItem.Name = data.Name
		createItem.From = data.From
		createItem.MysqlName = data.MysqlName
		createItem.Format = data.Format
		if err := mysqlRepo.Create(context.Background(), &createItem); err != nil {
			t.Fatalf("create synced row %s failed: %v", data.Name, err)
		}
	}

	var names []string
	if err := global.DB.Model(&model.DatabaseMysql{}).Order("name").Pluck("name", &names).Error; err != nil {
		t.Fatalf("list rows failed: %v", err)
	}
	joined := strings.Join(names, ",")
	if !strings.Contains(joined, "legal_db") {
		t.Errorf("legal db missing after sync: %v", names)
	}
	if strings.Contains(joined, "x'; id; 'y") || strings.Contains(joined, "legal_charset_ok") {
		t.Errorf("malicious rows were persisted: %v", names)
	}
	if len(names) != 2 {
		t.Errorf("expected 2 rows after sync (existing + legal_db), got %d: %v", len(names), names)
	}
}

// TestValidateRemoteDatabaseConn pins the Create/Update entry gate for remote
// connections: a tampered Address/Username must be rejected before any
// connection attempt, while ordinary values keep passing.
func TestValidateRemoteDatabaseConn(t *testing.T) {
	if err := validateRemoteDatabaseConn("10.0.0.5", "root"); err != nil {
		t.Errorf("legal conn rejected: %v", err)
	}
	if err := validateRemoteDatabaseConn("db.example.com:3306", "panel.user"); err != nil {
		t.Errorf("legal conn rejected: %v", err)
	}
	for _, tc := range []struct{ address, username string }{
		{"10.0.0.1; id", "root"},
		{"host $(id)", "root"},
		{"host name", "root"},
		{"", "root"},
		{"10.0.0.5", "root'; id; '"},
		{"10.0.0.5", ""},
		{"10.0.0.5", "root $(id)"},
	} {
		if err := validateRemoteDatabaseConn(tc.address, tc.username); err == nil {
			t.Errorf("validateRemoteDatabaseConn(%q, %q) = nil, want rejection", tc.address, tc.username)
		}
	}
}

// TestDatabaseCreateRejectsIllegalRemoteConn pins the Create entry gate end to
// end: with a From=="remote" mysql request carrying an injected address, the
// service must fail with the validation error before reaching the database
// repo (no record may be persisted).
func TestDatabaseCreateRejectsIllegalRemoteConn(t *testing.T) {
	setupLoadFromRemoteFilterTest(t)

	svc := &DatabaseService{}
	err := svc.Create(dto.DatabaseCreate{
		Name:     "evil-conn",
		Type:     constant.AppMysql,
		From:     "remote",
		Version:  "8.0",
		Address:  "10.0.0.1; curl evil",
		Port:     3306,
		Username: "root",
		Password: "pass",
	})
	if err == nil {
		t.Fatal("Create with injected address = nil error, want rejection")
	}
	if !strings.Contains(err.Error(), "invalid remote database address") {
		t.Errorf("unexpected error %v, want address validation error", err)
	}
	var count int64
	_ = global.DB.Model(&model.Database{}).Count(&count).Error
	if count != 0 {
		t.Errorf("rejected create persisted %d rows, want 0", count)
	}

	// A legal remote request must get past the gate; offline it fails at the
	// client connection step, NOT at validation.
	err = svc.Create(dto.DatabaseCreate{
		Name:     "good-conn",
		Type:     constant.AppMysql,
		From:     "remote",
		Version:  "8.0",
		Address:  "db.example.com",
		Port:     3306,
		Username: "panel_user",
		Password: "pass",
	})
	if err != nil && strings.Contains(err.Error(), "invalid") {
		t.Errorf("legal remote conn rejected at validation: %v", err)
	}

	// The same injected address must be refused by Update.
	err = svc.Update(dto.DatabaseUpdate{
		ID:       1,
		Type:     constant.AppMysql,
		Version:  "8.0",
		Address:  "10.0.0.1; curl evil",
		Port:     3306,
		Username: "root",
		Password: "pass",
	})
	if err == nil || !strings.Contains(err.Error(), "invalid remote database address") {
		t.Errorf("Update with injected address = %v, want address validation error", err)
	}
}
