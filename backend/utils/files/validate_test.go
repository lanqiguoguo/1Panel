package files

import "testing"

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
