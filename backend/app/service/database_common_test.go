package service

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/app/dto"
	"github.com/1Panel-dev/1Panel/backend/global"
)

func TestSanitizeDBInstanceName(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		wantErr bool
	}{
		// legal single-segment instance names
		{name: "mysql instance", in: "mysql-abc123", wantErr: false},
		{name: "redis instance", in: "redis-xyz", wantErr: false},
		{name: "single char", in: "a", wantErr: false},
		{name: "dot inside name", in: "my.sql", wantErr: false},
		{name: "leading dash", in: "-abc", wantErr: false},
		{name: "alphanumeric", in: "abc123", wantErr: false},

		// illegal
		{name: "empty", in: "", wantErr: true},
		{name: "dot", in: ".", wantErr: true},
		{name: "dotdot", in: "..", wantErr: true},
		{name: "parent escape", in: "../../etc", wantErr: true},
		{name: "deep escape", in: "../../../../etc/passwd", wantErr: true},
		{name: "absolute", in: "/etc", wantErr: true},
		{name: "slash separator", in: "a/b", wantErr: true},
		{name: "backslash separator", in: `a\b`, wantErr: true},
		{name: "traversal mid", in: "a/../b", wantErr: true},
		{name: "windows drive", in: "C:/x", wantErr: true},
		{name: "windows drive lower", in: "c:/x", wantErr: true},
		{name: "windows drive no slash", in: "C:", wantErr: true},
		{name: "trailing slash", in: "mysql-abc/", wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := sanitizeDBInstanceName(tc.in)
			if tc.wantErr && err == nil {
				t.Fatalf("sanitizeDBInstanceName(%q) expected error, got nil", tc.in)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("sanitizeDBInstanceName(%q) unexpected error: %v", tc.in, err)
			}
		})
	}
}

// TestLoadDatabaseFileSanitization verifies LoadDatabaseFile rejects
// traversal-style instance names and only serves files inside DataDir.
func TestLoadDatabaseFileSanitization(t *testing.T) {
	dataDir := t.TempDir()
	// decoy file that a vulnerable join would reach:
	// path.Join(dataDir, "apps/mysql/../../etc/conf/my.cnf") == dataDir/etc/conf/my.cnf
	decoyDir := filepath.Join(dataDir, "etc", "conf")
	if err := os.MkdirAll(decoyDir, 0755); err != nil {
		t.Fatalf("mkdir decoy: %v", err)
	}
	decoy := filepath.Join(decoyDir, "my.cnf")
	if err := os.WriteFile(decoy, []byte("SECRET"), 0644); err != nil {
		t.Fatalf("write decoy: %v", err)
	}
	// real file inside DataDir
	realDir := filepath.Join(dataDir, "apps", "mysql", "mysql-abc123", "conf")
	if err := os.MkdirAll(realDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	realFile := filepath.Join(realDir, "my.cnf")
	if err := os.WriteFile(realFile, []byte("REAL-CONF"), 0644); err != nil {
		t.Fatalf("write real: %v", err)
	}

	oldDataDir := global.CONF.System.DataDir
	global.CONF.System.DataDir = dataDir
	defer func() { global.CONF.System.DataDir = oldDataDir }()

	svc := NewIDBCommonService()

	// legal name reads the real file
	content, err := svc.LoadDatabaseFile(dto.OperationWithNameAndType{Type: "mysql-conf", Name: "mysql-abc123"})
	if err != nil {
		t.Fatalf("legal name: unexpected error: %v", err)
	}
	if content != "REAL-CONF" {
		t.Fatalf("legal name: got %q, want %q", content, "REAL-CONF")
	}

	// traversal names must be rejected and must not leak the decoy file
	for _, bad := range []string{"../../etc", "../../../../etc", "..", ".", "/etc", "a/../b", `a\b`, "C:/x"} {
		content, err := svc.LoadDatabaseFile(dto.OperationWithNameAndType{Type: "mysql-conf", Name: bad})
		if err == nil {
			t.Fatalf("name %q: expected error, got content %q", bad, content)
		}
		if content == "SECRET" {
			t.Fatalf("name %q: decoy file outside the instance dir was read", bad)
		}
	}

	// unknown type must be rejected even with a legal name
	if _, err := svc.LoadDatabaseFile(dto.OperationWithNameAndType{Type: "unknown-conf", Name: "mysql-abc123"}); err == nil {
		t.Fatal("unknown type: expected error, got nil")
	}
}