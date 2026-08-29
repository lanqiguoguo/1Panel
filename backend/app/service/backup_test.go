package service

import (
	"testing"

	fileUtils "github.com/1Panel-dev/1Panel/backend/utils/files"
)

func TestSanitizeBackupDir(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		wantErr bool
	}{
		// legal
		{name: "single level", in: "system", wantErr: false},
		{name: "two levels", in: "system/mysql", wantErr: false},
		{name: "three levels", in: "app/wordpress/1.0", wantErr: false},
		{name: "multidir app", in: "app/wordpress", wantErr: false},
		{name: "snapshot dir", in: "system_snapshot", wantErr: false},
		{name: "database nested", in: "database/mysql/default/site", wantErr: false},

		// illegal
		{name: "empty", in: "", wantErr: true},
		{name: "dot", in: ".", wantErr: true},
		{name: "dotdot", in: "..", wantErr: true},
		{name: "parent escape", in: "../etc", wantErr: true},
		{name: "deep escape", in: "../../../../etc", wantErr: true},
		{name: "absolute", in: "/etc", wantErr: true},
		{name: "traversal mid", in: "a/../b", wantErr: true},
		{name: "double slash", in: "a//b", wantErr: true},
		{name: "dot segment", in: "a/./b", wantErr: true},
		{name: "backslash", in: `a\b`, wantErr: true},
		{name: "trailing dotdot", in: "a/..", wantErr: true},
		{name: "windows drive", in: "C:/x", wantErr: true},
		{name: "windows drive lower", in: "c:/x/y", wantErr: true},
		{name: "trailing slash", in: "system/", wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := sanitizeBackupDir(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("sanitizeBackupDir(%q) expected error, got %q", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("sanitizeBackupDir(%q) unexpected error: %v", tc.in, err)
			}
			if got != tc.in {
				t.Fatalf("sanitizeBackupDir(%q) = %q, want unchanged input", tc.in, got)
			}
		})
	}
}

// TestDownloadRecordSanitizationGate confirms the two sanitization functions
// DownloadRecord calls at its entry point (fileDir via sanitizeBackupDir,
// fileName via fileUtils.SanitizeFilename) reject the traversal payloads that
// would previously escape the backup root. DownloadRecord itself cannot be
// driven end-to-end here because it needs a configured backup account in the
// DB (loadLocalDir / backupRepo), so the entry gate is verified instead.
func TestDownloadRecordBackupSanitizeGate(t *testing.T) {
	for _, dir := range []string{"../../../../etc", ".", "..", "/etc", `a\b`, "C:/x"} {
		if _, err := sanitizeBackupDir(dir); err == nil {
			t.Fatalf("expected FileDir %q to be rejected", dir)
		}
	}
	for _, name := range []string{"dir/../../shadow", `..\shadow`, "../../etc/passwd", "/etc/shadow"} {
		if _, err := fileUtils.SanitizeFilename(name); err == nil {
			t.Fatalf("expected FileName %q to be rejected", name)
		}
	}
	for _, name := range []string{"system", "system/mysql"} {
		if _, err := sanitizeBackupDir(name); err != nil {
			t.Fatalf("expected FileDir %q to be accepted, got err: %v", name, err)
		}
	}
	if _, err := fileUtils.SanitizeFilename("backup.tar.gz"); err != nil {
		t.Fatalf("expected FileName %q to be accepted, got err: %v", "backup.tar.gz", err)
	}
}
