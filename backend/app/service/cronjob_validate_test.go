package service

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/app/model"
	"github.com/1Panel-dev/1Panel/backend/buserr"
	"github.com/1Panel-dev/1Panel/backend/constant"
	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/sirupsen/logrus"
)

func ensureValidateLogger(t *testing.T) {
	t.Helper()
	if global.LOG == nil {
		global.LOG = logrus.New()
		t.Cleanup(func() { global.LOG = nil })
	}
}

func isErrCmdIllegal(t *testing.T, err error) bool {
	t.Helper()
	var bizErr buserr.BusinessError
	return errors.As(err, &bizErr) && bizErr.Msg == constant.ErrCmdIllegal
}

func TestValidCronjobName(t *testing.T) {
	legal := []string{
		"backup",
		"backup-01",
		"a",
		"中文任务",
		"任务_01",
		"backup.2026",
		"my job with spaces", // spaces were historically legal on the backend
		"混搭name-2026",
	}
	for _, name := range legal {
		if !validCronjobName(name) {
			t.Errorf("validCronjobName(%q) = false, want true", name)
		}
	}

	illegal := []string{
		"",
		"../../pwned",
		"a/../b",
		"a\\b",
		"a; touch /tmp/x",
		"$(touch /tmp/x)",
		"`id`",
		"a&b",
		"a|b",
		"a'b",
		"a\"b",
		"a\nb",
		"a\tb",
		"/abs",
		"..",
	}
	for _, name := range illegal {
		if validCronjobName(name) {
			t.Errorf("validCronjobName(%q) = true, want false", name)
		}
	}

	long := make([]byte, 256)
	for i := range long {
		long[i] = 'a'
	}
	if validCronjobName(string(long)) {
		t.Error("validCronjobName(256 chars) = true, want false")
	}
	if !validCronjobName(string(long[:255])) {
		t.Error("validCronjobName(255 chars) = false, want true")
	}
}

func TestValidCronjobExclusionRules(t *testing.T) {
	legal := []string{
		"",
		"*.log",
		"a,b",
		"/path/to/dir",
		"*.log,/tmp/cache/*",
		"data?/*.gz",
		"logs/[0-9]*.txt",
	}
	for _, rules := range legal {
		if !validCronjobExclusionRules(rules) {
			t.Errorf("validCronjobExclusionRules(%q) = false, want true", rules)
		}
	}

	illegal := []string{
		"x; touch /tmp/pwned",
		"$(touch /tmp/pwned)",
		"`touch /tmp/pwned`",
		"a|b",
		"a&b",
		"a' b",
		"a>b",
	}
	for _, rules := range illegal {
		if validCronjobExclusionRules(rules) {
			t.Errorf("validCronjobExclusionRules(%q) = true, want false", rules)
		}
	}
}

func TestValidateCronjobFields(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "pwned")
	tests := []struct {
		name          string
		cronType      string
		cronName      string
		sourceDir     string
		exclusion     string
		url           string
		containerName string
		command       string
		wantErr       bool
	}{
		{
			name:      "legit directory",
			cronType:  "directory",
			cronName:  "正常备份任务",
			sourceDir: "/tmp/src",
			exclusion: "*.log",
		},
		{
			name:      "name traversal",
			cronType:  "directory",
			cronName:  "../../pwned",
			sourceDir: "/tmp/src",
			wantErr:   true,
		},
		{
			name:      "sourceDir injection",
			cronType:  "directory",
			cronName:  "backup",
			sourceDir: "$(touch " + marker + ")",
			wantErr:   true,
		},
		{
			name:      "exclusion injection",
			cronType:  "directory",
			cronName:  "backup",
			sourceDir: "/tmp/src",
			exclusion: "x; touch " + marker,
			wantErr:   true,
		},
		{
			name:     "url injection",
			cronType: "curl",
			cronName: "webhook",
			url:      "http://a' ; touch " + marker,
			wantErr:  true,
		},
		{
			name:     "url bad scheme",
			cronType: "curl",
			cronName: "webhook",
			url:      "ftp://example.com/x",
			wantErr:  true,
		},
		{
			name:     "url legit",
			cronType: "curl",
			cronName: "webhook",
			url:      "https://example.com/hook",
		},
		{
			name:     "name injection",
			cronType: "shell",
			cronName: "a; touch " + marker,
			wantErr:  true,
		},
		{
			name:          "shell container legit",
			cronType:      "shell",
			cronName:      "container-job",
			containerName: "mycontainer",
			command:       "sh",
		},
		{
			name:     "shell empty container and command",
			cronType: "shell",
			cronName: "host-job",
		},
		{
			name:          "shell absolute shell path",
			cronType:      "shell",
			cronName:      "abs-shell",
			containerName: "mycontainer",
			command:       "/bin/bash",
		},
		{
			name:          "shell container injection",
			cronType:      "shell",
			cronName:      "inject-1",
			containerName: "x; touch " + marker,
			command:       "sh",
			wantErr:       true,
		},
		{
			name:          "shell container dollar paren",
			cronType:      "shell",
			cronName:      "inject-2",
			containerName: "x$(touch " + marker + ")",
			command:       "sh",
			wantErr:       true,
		},
		{
			name:          "shell command injection",
			cronType:      "shell",
			cronName:      "inject-3",
			containerName: "mycontainer",
			command:       "sh; id",
			wantErr:       true,
		},
		{
			name:          "shell command with space",
			cronType:      "shell",
			cronName:      "inject-4",
			containerName: "mycontainer",
			command:       "sh -c",
			wantErr:       true,
		},
		{
			name:          "shell command ampersand",
			cronType:      "shell",
			cronName:      "inject-5",
			containerName: "mycontainer",
			command:       "a&b",
			wantErr:       true,
		},
		{
			name:          "shell command pipe",
			cronType:      "shell",
			cronName:      "inject-6",
			containerName: "mycontainer",
			command:       "a|b",
			wantErr:       true,
		},
		{
			name:          "shell command quote",
			cronType:      "shell",
			cronName:      "inject-7",
			containerName: "mycontainer",
			command:       "a'b",
			wantErr:       true,
		},
		{
			name:          "shell command traversal",
			cronType:      "shell",
			cronName:      "inject-8",
			containerName: "mycontainer",
			command:       "../x",
			wantErr:       true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateCronjobFields(tc.cronType, tc.cronName, tc.sourceDir, tc.exclusion, tc.url, tc.containerName, tc.command)
			if tc.wantErr {
				if err == nil {
					t.Fatal("validateCronjobFields() error = nil, want ErrCmdIllegal")
				}
				if !isErrCmdIllegal(t, err) {
					t.Fatalf("validateCronjobFields() error = %v, want ErrCmdIllegal", err)
				}
				if _, statErr := os.Stat(marker); statErr == nil {
					t.Fatal("injection marker was created during validation")
				}
				return
			}
			if err != nil {
				t.Fatalf("validateCronjobFields() error = %v, want nil", err)
			}
		})
	}
}

// TestValidCronjobContainerFields covers the pure function shared by the
// entry-point (validateCronjobFields) and the runtime HandleJob guard: the
// docker-exec container name must match the docker name charset and the
// in-container shell command must be free of shell metacharacters,
// whitespace and ".." components.
func TestValidCronjobContainerFields(t *testing.T) {
	legal := []struct {
		containerName string
		command       string
	}{
		{"", ""}, // host-shell branch, both defaults
		{"", "sh"},
		{"mycontainer", ""}, // empty command defaults to sh
		{"mycontainer", "sh"},
		{"mycontainer", "bash"},
		{"mycontainer", "/bin/sh"},
		{"mycontainer", "/bin/bash"},
		{"my.1panel_web-01", "sh"},
		{"a", "zsh"},
	}
	for _, c := range legal {
		if !validCronjobContainerFields(c.containerName, c.command) {
			t.Errorf("validCronjobContainerFields(%q, %q) = false, want true", c.containerName, c.command)
		}
	}

	illegal := []struct {
		containerName string
		command       string
	}{
		{"x; touch /tmp/pwned", "sh"},
		{"x$(touch /tmp/pwned)", "sh"},
		{"x`touch /tmp/pwned`", "sh"},
		{"a&b", "sh"},
		{"a|b", "sh"},
		{"a'b", "sh"},
		{"a\"b", "sh"},
		{"a>b", "sh"},
		{"a\nb", "sh"},
		{"-i", "sh"},        // docker flag smuggling: must start with alnum
		{"../../pwned", ""}, // slash and traversal are not in the docker charset
		{"a b", "sh"},
		{"mycontainer", "sh; id"},
		{"mycontainer", "sh -c"},
		{"mycontainer", "$(touch /tmp/pwned)"},
		{"mycontainer", "a'b"},
		{"mycontainer", "../x"},
		{"mycontainer", "sh\t-x"},
	}
	for _, c := range illegal {
		if validCronjobContainerFields(c.containerName, c.command) {
			t.Errorf("validCronjobContainerFields(%q, %q) = true, want false", c.containerName, c.command)
		}
	}
}

// TestHandleJobSkipsIllegalContainerFields verifies the runtime guard: a
// legacy shell cronjob record carrying an illegal container name must be
// skipped before any shell command is built, so the injection marker is never
// created and no record state is written.
func TestHandleJobSkipsIllegalContainerFields(t *testing.T) {
	ensureValidateLogger(t)
	marker := "/tmp/pwned-cron-valid-test"

	tests := []struct {
		name    string
		cronjob *model.Cronjob
	}{
		{
			name: "container name injection",
			cronjob: &model.Cronjob{
				BaseModel:     model.BaseModel{ID: 9001},
				Name:          "legacy-inject",
				Type:          "shell",
				Spec:          "* * * * *",
				Script:        "echo hi",
				ContainerName: "x; touch " + marker,
				Command:       "sh",
			},
		},
		{
			name: "command injection",
			cronjob: &model.Cronjob{
				BaseModel:     model.BaseModel{ID: 9002},
				Name:          "legacy-inject-2",
				Type:          "shell",
				Spec:          "* * * * *",
				Script:        "echo hi",
				ContainerName: "mycontainer",
				Command:       "sh; touch " + marker,
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_ = os.Remove(marker)
			u := &CronjobService{}
			u.HandleJob(tc.cronjob)
			if _, err := os.Stat(marker); err == nil {
				t.Fatal("injection marker was created by HandleJob")
			}
		})
	}
	_ = os.Remove(marker)
}

// TestHandleJobIllegalContainerNameNotInRecordNamePath is a regression check
// that a skip for illegal container fields logs the job name without touching
// the task directory (the record name path never becomes part of a shell
// command in the skip branch).
func TestHandleJobIllegalContainerNameNotInRecordNamePath(t *testing.T) {
	ensureValidateLogger(t)
	u := &CronjobService{}
	u.HandleJob(&model.Cronjob{
		BaseModel:     model.BaseModel{ID: 9003},
		Name:          "legacy-inject-3",
		Type:          "shell",
		Spec:          "* * * * *",
		Script:        "echo hi",
		ContainerName: "../../pwned",
		Command:       "sh",
	})
	if _, err := os.Stat("/tmp/pwned"); err == nil {
		t.Fatal("unexpected path created by skipped job")
	}
}

// TestValidCronjobContainerFieldsRejectsAllMetacharacters cross-checks that
// the whitelist charset of the container-name check subsumes every character
// rejected by cmd.CheckIllegal: no string that passes the container check may
// contain a shell metacharacter.
func TestValidCronjobContainerFieldsRejectsAllMetacharacters(t *testing.T) {
	illegalChars := "&|;$'`()\"\n\r<>"
	for _, ch := range illegalChars {
		s := "a" + string(ch) + "b"
		if validCronjobContainerFields(s, "") {
			t.Errorf("validCronjobContainerFields(%q, '') = true, want false", s)
		}
		if !strings.ContainsAny(s, " ") { // only the container branch is whitelist-checked here
			if validCronjobContainerFields("mycontainer", "sh"+string(ch)) {
				t.Errorf("validCronjobContainerFields('mycontainer', %q) = true, want false", "sh"+string(ch))
			}
		}
	}
}

// TestHandleTarRejectsInjection verifies the defense-in-depth checks inside
// handleTar: malicious exclusion rules or source directories must be rejected
// before any shell command is built or executed.
func TestHandleTarRejectsInjection(t *testing.T) {
	ensureValidateLogger(t)
	marker := filepath.Join(t.TempDir(), "pwned-cron")
	srcDir := filepath.Join(t.TempDir(), "src")
	if err := os.MkdirAll(srcDir, 0755); err != nil {
		t.Fatalf("mkdir src: %v", err)
	}
	targetDir := t.TempDir()

	tests := []struct {
		caseName    string
		sourceDir   string
		targetDir   string
		archiveName string
		exclusion   string
		secret      string
	}{
		{
			caseName:    "exclusion injection",
			sourceDir:   srcDir,
			targetDir:   targetDir,
			archiveName: "backup.tar.gz",
			exclusion:   "x; touch " + marker,
		},
		{
			caseName:    "sourceDir injection",
			sourceDir:   "$(touch " + marker + ")",
			targetDir:   targetDir,
			archiveName: "backup.tar.gz",
		},
		{
			caseName:    "targetDir injection",
			sourceDir:   srcDir,
			targetDir:   "$(touch " + marker + ")",
			archiveName: "backup.tar.gz",
		},
		{
			caseName:    "secret injection",
			sourceDir:   srcDir,
			targetDir:   targetDir,
			archiveName: "backup.tar.gz",
			secret:      "$(touch " + marker + ")",
		},
	}
	for _, tc := range tests {
		t.Run(tc.caseName, func(t *testing.T) {
			err := handleTar(tc.sourceDir, tc.targetDir, tc.archiveName, tc.exclusion, tc.secret)
			if err == nil {
				t.Fatal("handleTar() error = nil, want ErrCmdIllegal")
			}
			if !isErrCmdIllegal(t, err) {
				t.Fatalf("handleTar() error = %v, want ErrCmdIllegal", err)
			}
			if _, statErr := os.Stat(marker); statErr == nil {
				t.Fatal("command injection marker was created")
			}
		})
	}
}

// TestHandleTarLegitDirectoryBackup is a regression test: a normal directory
// backup still runs end to end and produces the archive.
func TestHandleTarLegitDirectoryBackup(t *testing.T) {
	ensureValidateLogger(t)
	base := t.TempDir()
	srcDir := filepath.Join(base, "src")
	if err := os.MkdirAll(filepath.Join(srcDir, "sub"), 0755); err != nil {
		t.Fatalf("mkdir src: %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "sub", "data.txt"), []byte("hello"), 0644); err != nil {
		t.Fatalf("write data: %v", err)
	}
	targetDir := filepath.Join(base, "out")
	archiveName := "backup.tar.gz"

	if err := handleTar(srcDir, targetDir, archiveName, "*.tmp", ""); err != nil {
		t.Fatalf("handleTar() error = %v", err)
	}
	archive := filepath.Join(targetDir, archiveName)
	info, err := os.Stat(archive)
	if err != nil {
		t.Fatalf("archive %s not created: %v", archive, err)
	}
	if info.Size() == 0 {
		t.Fatalf("archive %s is empty", archive)
	}
}
