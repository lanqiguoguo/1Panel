package service

import (
	"strings"
	"testing"
)

// TestValidFtpUser covers the pure-ftpd account name whitelist. The name is
// written into /etc/pure-ftpd/pureftpd.passwd and interpolated into host
// shell commands (pure-pw userdel/usermod, chown), so shell metacharacters,
// whitespace and path separators must all be rejected.
func TestValidFtpUser(t *testing.T) {
	legal := []string{
		"a",
		"ftpuser",
		"ftp_user",
		"ftp-user",
		"ftp.user",
		"a1b2c3",
		"UPPER_lower-123.x",
	}
	for _, user := range legal {
		if !validFtpUser(user) {
			t.Errorf("validFtpUser(%q) = false, want true", user)
		}
	}

	illegal := []string{
		"",
		"a b",            // whitespace
		"a\tb",           // tab
		"a; touch /tmp/x", // command injection
		"$(touch /tmp/x)",
		"`id`",
		"a&b",
		"a|b",
		"a'b",
		`a"b`,
		"a\nb",
		"a\rb",
		"a<b",
		"a>b",
		"a(b)",
		"a/b",      // path separator
		"a\\b",     // backslash
		"..",       // traversal
		"../../x",  // traversal
		"/etc/passwd",
		"a:passwd", // colon would break the passwd record
		strings.Repeat("a", 33), // too long
		"1panel\nid",
	}
	for _, user := range illegal {
		if validFtpUser(user) {
			t.Errorf("validFtpUser(%q) = true, want false", user)
		}
	}

	// boundary: 32 chars is the maximum allowed
	if !validFtpUser(strings.Repeat("a", 32)) {
		t.Error("validFtpUser(32 chars) = false, want true")
	}
}

// TestValidFtpPath covers the FTP home directory rules: absolute, free of
// shell metacharacters, free of ".." components and not ending with "/" (the
// entry is stored as "<path>/./" in pureftpd.passwd).
func TestValidFtpPath(t *testing.T) {
	legal := []string{
		"/home",
		"/home/test",
		"/home/ftp_user-1.2",
		"/srv/www/站点",
		"/data/备份/文件",
		"/a/b/c/d",
	}
	for _, p := range legal {
		if !validFtpPath(p) {
			t.Errorf("validFtpPath(%q) = false, want true", p)
		}
	}

	illegal := []string{
		"",
		"home/test",          // not absolute
		"relative/path",      // not absolute
		"~user",              // not absolute
		"/x; touch /tmp/x",   // command injection
		"/x$(touch /tmp/x)",  // command injection
		"/x`id`",             // backtick injection
		"/x&y",
		"/x|y",
		"/x'y",
		`/x"y`,
		"/x<y",
		"/x>y",
		"/x(y)",
		"/x\ny",
		"/x\r\ny",
		"/home/../etc",      // traversal
		"/../etc/passwd",    // traversal
		"/home/a/../../etc", // traversal
		"/home/",            // trailing slash
		"/",                 // root
		"/home//double",     // double slash -> Clean mismatch
		"/home/./dot",       // dot component -> Clean mismatch
	}
	for _, p := range illegal {
		if validFtpPath(p) {
			t.Errorf("validFtpPath(%q) = true, want false", p)
		}
	}
}

// TestValidateFtpEntry is the shared entry-point matrix used by both Create
// and Update.
func TestValidateFtpEntry(t *testing.T) {
	legal := []struct{ user, path string }{
		{"ftpuser", "/home/ftpuser"},
		{"web_01", "/srv/www/web_01"},
		{"ftp-1", "/data/backup"},
	}
	for _, c := range legal {
		if err := validateFtpEntry(c.user, c.path); err != nil {
			t.Errorf("validateFtpEntry(%q, %q) = %v, want nil", c.user, c.path, err)
		}
	}

	illegal := []struct{ user, path string }{
		{"", "/home/x"},                      // empty user
		{"a; touch /tmp/pwned", "/home/x"},   // user injection
		{"ftpuser", ""},                      // empty path
		{"ftpuser", "relative"},              // relative path
		{"ftpuser", "/x; touch /tmp/pwned"},  // path injection
		{"ftpuser", "/home/../etc"},          // path traversal
		{"ftpuser", "/home/"},                // trailing slash
		{"a;id", "/home/x"},                  // user injection variant
	}
	for _, c := range illegal {
		err := validateFtpEntry(c.user, c.path)
		if err == nil {
			t.Errorf("validateFtpEntry(%q, %q) = nil, want ErrCmdIllegal", c.user, c.path)
			continue
		}
		if !isErrCmdIllegal(t, err) {
			t.Errorf("validateFtpEntry(%q, %q) error = %v, want ErrCmdIllegal", c.user, c.path, err)
		}
	}
}
