package toolbox

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/buserr"
	"github.com/1Panel-dev/1Panel/backend/constant"
)

// TestFtpCheckIllegalDefense is the regression test for the FTP command
// injection: SetPath/SetPasswd/SetStatus/UserAdd/UserDel values are
// interpolated into host shell commands, so shell metacharacters must be
// rejected even if a future caller skips the entry-point validation.
func TestFtpCheckIllegalDefense(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "pwned")
	f := &Ftp{DefaultUser: "1000", DefaultGroup: "1000"}
	_ = os.Remove(marker)

	cases := []struct {
		name string
		fn   func() error
	}{
		{"SetPath path injection", func() error { return f.SetPath("ftpuser", "/x; touch "+marker) }},
		{"SetPath user injection", func() error { return f.SetPath("u; touch "+marker, "/home/x") }},
		{"SetStatus user injection", func() error { return f.SetStatus("u$(touch "+marker+")", constant.StatusEnable) }},
		{"SetPasswd user injection", func() error { return f.SetPasswd("u`touch "+marker+"`", "pw") }},
		{"UserAdd user injection", func() error { return f.UserAdd("u; touch "+marker, "pw", "/home/x") }},
		{"UserAdd path injection", func() error { return f.UserAdd("ftpuser", "pw", "/x; touch "+marker) }},
		{"UserDel user injection", func() error { return f.UserDel("u; touch " + marker) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_ = os.Remove(marker)
			err := tc.fn()
			var bizErr buserr.BusinessError
			if !errors.As(err, &bizErr) || bizErr.Msg != constant.ErrCmdIllegal {
				t.Fatalf("error = %v, want ErrCmdIllegal", err)
			}
			if _, statErr := os.Stat(marker); statErr == nil {
				t.Fatal("injection marker was created during validation")
			}
		})
	}
}

// TestFtpSetPasswdAllowsSpecialCharsInPassword verifies that a password
// containing characters that are legal in a plain-text FTP password (but
// would be shell metacharacters) does not fail the SetPasswd CheckIllegal
// defense: only the username is checked, because the password is
// bcrypt-hashed and written to the passwd file, never interpolated into a
// shell command.
func TestFtpSetPasswdAllowsSpecialCharsInPassword(t *testing.T) {
	// Never touch a real passwd file: if the system file exists, skip to
	// avoid side effects; otherwise the missing file yields an os.Open
	// error which must NOT be ErrCmdIllegal (the password is not checked).
	if _, err := os.Stat("/etc/pure-ftpd/pureftpd.passwd"); err == nil {
		t.Skip("system pureftpd.passwd exists, skipping to avoid side effects")
	}
	err := (&Ftp{}).SetPasswd("ftpuser", "P@ss$'word;`x")
	var bizErr buserr.BusinessError
	if errors.As(err, &bizErr) && bizErr.Msg == constant.ErrCmdIllegal {
		t.Fatalf("SetPasswd rejected a legal special-char password with ErrCmdIllegal: %v", err)
	}
	if err == nil {
		t.Fatal("SetPasswd unexpectedly succeeded without a passwd file")
	}
}
