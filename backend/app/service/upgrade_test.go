package service

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMigrate1pctlParams(t *testing.T) {
	dir := t.TempDir()
	backup := filepath.Join(dir, "1pctl.backup")
	target := filepath.Join(dir, "1pctl.new")
	oldScript := "#!/bin/bash\n" +
		"BASE_DIR=/opt\n" +
		"ORIGINAL_PORT=28080\n" +
		"ORIGINAL_VERSION=v1.10.34-lts-internal\n" +
		"ORIGINAL_ENTRANCE=old_entrance\n" +
		"ORIGINAL_USERNAME=old_admin\n" +
		"ORIGINAL_PASSWORD=p@ss/w0rd#special\n" +
		"LANGUAGE=zh\n" +
		"CHANGE_USER_INFO=abc123\n"
	newScript := "#!/bin/bash\n" +
		"BASE_DIR=directory\n" +
		"ORIGINAL_PORT=port\n" +
		"ORIGINAL_VERSION=v1.10.35-lts\n" +
		"ORIGINAL_ENTRANCE=entrance\n" +
		"ORIGINAL_USERNAME=username\n" +
		"ORIGINAL_PASSWORD=password\n" +
		"LANGUAGE=en\n"
	if err := os.WriteFile(backup, []byte(oldScript), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte(newScript), 0755); err != nil {
		t.Fatal(err)
	}

	u := &UpgradeService{}
	if err := u.migrate1pctlParams(backup, target, "v1.10.35-lts"); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	want := "#!/bin/bash\n" +
		"BASE_DIR=/opt\n" +
		"ORIGINAL_PORT=28080\n" +
		"ORIGINAL_VERSION=v1.10.35-lts\n" +
		"ORIGINAL_ENTRANCE=old_entrance\n" +
		"ORIGINAL_USERNAME=old_admin\n" +
		"ORIGINAL_PASSWORD=p@ss/w0rd#special\n" +
		"LANGUAGE=zh\n" +
		"CHANGE_USER_INFO=abc123\n"
	if string(got) != want {
		t.Fatalf("migrated 1pctl mismatch:\ngot:\n%s\nwant:\n%s", got, want)
	}
}

func TestCheckVersionSemantics(t *testing.T) {
	u := &UpgradeService{}
	cases := []struct {
		name    string
		remote  string
		current string
		expect  string
	}{
		{"newer lts over internal", "v1.10.35-lts", "v1.10.34-lts-internal", "v1.10.35-lts"},
		{"same version no prompt", "v1.10.35-lts", "v1.10.35-lts", ""},
		{"older remote no prompt", "v1.10.34-lts", "v1.10.35-lts", ""},
		{"trailing newline tolerated", "v1.10.36-lts\n", "v1.10.35-lts", "v1.10.36-lts"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := u.checkVersion(c.remote, c.current); got != c.expect {
				t.Fatalf("checkVersion(%q, %q) = %q, want %q", c.remote, c.current, got, c.expect)
			}
		})
	}
}
