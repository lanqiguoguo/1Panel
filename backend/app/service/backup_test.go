package service

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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

// TestMaskBackupVars verifies that secret var fields are masked on every echo
// path while non-secret fields (accessKey, endpoint, region, refresh status)
// are passed through unchanged.
func TestMaskBackupVars(t *testing.T) {
	vars := `{"accessKey":"AKID123","endpoint":"https://s3.example.com","region":"us-east-1","secretKey":"real-secret","password":"pw","client_secret":"azure-secret","refresh_token":"tok-abc","refresh_status":"Success","refresh_time":"2026-08-30 12:00:00","bucket":"my-bucket"}`
	got := maskBackupVars(vars)

	for _, secret := range []string{"real-secret", "pw", "azure-secret", "tok-abc"} {
		if strings.Contains(got, secret) {
			t.Fatalf("maskBackupVars leaked secret %q in: %s", secret, got)
		}
	}
	for _, keep := range []string{"AKID123", "https://s3.example.com", "us-east-1", "Success", "2026-08-30 12:00:00", "my-bucket"} {
		if !strings.Contains(got, keep) {
			t.Fatalf("maskBackupVars dropped non-secret field %q in: %s", keep, got)
		}
	}
	if !strings.Contains(got, backupMaskValue) {
		t.Fatalf("maskBackupVars did not apply mask placeholder: %s", got)
	}
}

// TestMaskBackupVarsInvalidJSON verifies masking is a no-op on malformed vars.
func TestMaskBackupVarsInvalidJSON(t *testing.T) {
	in := `{"secretKey": "x"`
	if got := maskBackupVars(in); got != in {
		t.Fatalf("maskBackupVars(%q) = %q, want input unchanged", in, got)
	}
}

// TestIsMaskedCredential covers the placeholder detection used by Update.
func TestIsMaskedCredential(t *testing.T) {
	for _, masked := range []string{"", "******"} {
		if !isMaskedCredential(masked) {
			t.Fatalf("isMaskedCredential(%q) = false, want true", masked)
		}
	}
	for _, real := range []string{"s3cr3t", "*******", "**x**"} {
		if isMaskedCredential(real) {
			t.Fatalf("isMaskedCredential(%q) = true, want false", real)
		}
	}
}

// TestMergeMaskedVars verifies the keep semantics of the update path: fields
// submitted as mask/empty keep their stored values; fields with real values
// (including secrets the user deliberately replaced) overwrite the stored
// ones; new non-secret fields are merged in.
func TestMergeMaskedVars(t *testing.T) {
	stored := `{"client_id":"cid-1","client_secret":"stored-secret","endpoint":"old-endpoint","refresh_token":"stored-token"}`
	req := `{"client_id":"cid-1","client_secret":"******","endpoint":"new-endpoint"}`
	got, err := mergeMaskedVars(stored, req)
	if err != nil {
		t.Fatalf("mergeMaskedVars returned error: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(got), &m); err != nil {
		t.Fatalf("mergeMaskedVars returned invalid json: %v", err)
	}
	if m["client_secret"] != "stored-secret" {
		t.Fatalf("client_secret = %v, want stored-secret kept", m["client_secret"])
	}
	if m["refresh_token"] != "stored-token" {
		t.Fatalf("refresh_token = %v, want stored-token kept", m["refresh_token"])
	}
	if m["endpoint"] != "new-endpoint" {
		t.Fatalf("endpoint = %v, want new-endpoint", m["endpoint"])
	}

	// an empty secret also means keep
	req2 := `{"client_id":"cid-1","client_secret":"","endpoint":"new-endpoint"}`
	got2, err := mergeMaskedVars(stored, req2)
	if err != nil {
		t.Fatalf("mergeMaskedVars returned error: %v", err)
	}
	var m2 map[string]interface{}
	_ = json.Unmarshal([]byte(got2), &m2)
	if m2["client_secret"] != "stored-secret" {
		t.Fatalf("client_secret = %v, want stored-secret kept on empty submit", m2["client_secret"])
	}

	// a real secret value replaces the stored one
	req3 := `{"client_secret":"brand-new-secret"}`
	got3, err := mergeMaskedVars(stored, req3)
	if err != nil {
		t.Fatalf("mergeMaskedVars returned error: %v", err)
	}
	var m3 map[string]interface{}
	_ = json.Unmarshal([]byte(got3), &m3)
	if m3["client_secret"] != "brand-new-secret" {
		t.Fatalf("client_secret = %v, want brand-new-secret", m3["client_secret"])
	}
}

// TestBackupJsonFilesNotWorldWritable is the regression test for the 0777
// backup staging files: app.json / runtime.json / website.json embed install
// env including credentials, so they must be written with 0640 instead of
// fs.ModePerm (0777).
func TestBackupJsonFilesNotWorldWritable(t *testing.T) {
	fileOp := fileUtils.NewFileOp()
	dir := t.TempDir()

	for _, name := range []string{"app.json", "runtime.json", "website.json"} {
		path := filepath.Join(dir, name)
		if err := fileOp.SaveFile(path, `{"key":"secret-value"}`, 0640); err != nil {
			t.Fatalf("SaveFile %s failed: %v", name, err)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}
		if got := info.Mode().Perm(); got != 0640 {
			t.Fatalf("%s mode = %v, want 0640", name, got)
		}
		if got := info.Mode().Perm() & 0o007; got != 0 {
			t.Fatalf("%s is world-accessible: %v", name, got)
		}
		if got := info.Mode().Perm() & 0o020; got != 0 {
			t.Fatalf("%s is group-writable: %v", name, got)
		}
	}
}
