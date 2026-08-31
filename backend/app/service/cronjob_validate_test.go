package service

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/app/dto"
	"github.com/1Panel-dev/1Panel/backend/app/model"
	"github.com/1Panel-dev/1Panel/backend/buserr"
	"github.com/1Panel-dev/1Panel/backend/constant"
	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/glebarez/sqlite"
	"github.com/robfig/cron/v3"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
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

// TestValidCronjobURL covers the pure function shared by the entry-point
// (validateCronjobFields) and the runtime HandleJob guard: the URL must be
// empty, http(s) and free of shell metacharacters or quotes so it can never
// escape the `curl '<url>'` single quoting.
func TestValidCronjobURL(t *testing.T) {
	legal := []string{
		"",
		"http://example.com/hook",
		"https://example.com/hook",
		// '&' is rejected by the pre-existing CheckIllegal curl check (and
		// stays rejected: this fix must not change the accepted URL set), so
		// query separators are limited to '?'-only queries.
		"https://example.com/a/b?c=d",
		"http://127.0.0.1:8080/ping",
		"https://example.com/path%20with%20space",
	}
	for _, url := range legal {
		if !validCronjobURL(url) {
			t.Errorf("validCronjobURL(%q) = false, want true", url)
		}
	}

	illegal := []string{
		// quote escape payload of the Update type-confusion bug
		"http://x' -o /tmp/pwn '#",
		"ftp://example.com/x",
		"file:///etc/passwd",
		"http://a' ; touch /tmp/pwned",
		`http://a" -o /tmp/pwn`,
		"http://a$(touch /tmp/pwned)",
		"http://a`touch /tmp/pwned`",
		"http://a&b",
		"http://a|b",
		"http://a;b",
		"http://a>b",
		"http://a<b",
		"http://a\nb",
		"http://a\tb",
		"example.com/no-scheme",
		"/etc/passwd",
	}
	for _, url := range illegal {
		if validCronjobURL(url) {
			t.Errorf("validCronjobURL(%q) = true, want false", url)
		}
	}
}

// TestUpdateRejectsTypeConfusedURL is the regression test for the Update type
// confusion: a request declaring type=shell used to skip the URL check while
// req.URL was still persisted onto the stored type=curl job, whose next run
// interpolated it into `curl '<url>'` executed by the host shell (quote
// escape, root RCE). Update must validate the request values against the type
// actually stored in the DB, so the malicious URL is rejected and never
// written.
func TestUpdateRejectsTypeConfusedURL(t *testing.T) {
	setupCronjobUpdateTestDB(t)
	if err := global.DB.Create(&model.Cronjob{
		Name:   "legacy-curl",
		Type:   "curl",
		Spec:   "* * * * *",
		Status: constant.StatusDisable,
	}).Error; err != nil {
		t.Fatalf("seed curl cronjob: %v", err)
	}

	// The Update flow persists req.URL unconditionally (upMap["url"]), so a
	// URL that the stored curl job would execute must be rejected outright.
	malicious := []dto.CronjobUpdate{
		{
			ID:   1,
			Type: "shell", // req.Type is discarded; the DB row stays type=curl
			Name: "legacy-curl",
			Spec: "* * * * *",
			URL:  "http://x' -o /tmp/pwn '#",
		},
		{
			ID:   1,
			Type: "curl",
			Name: "legacy-curl",
			Spec: "* * * * *",
			URL:  "http://x' -o /tmp/pwn '#",
		},
	}
	for i, req := range malicious {
		if err := NewICronjobService().Update(req.ID, req); err == nil {
			t.Fatalf("Update malicious case %d: error = nil, want ErrCmdIllegal", i)
		} else if !isErrCmdIllegal(t, err) {
			t.Fatalf("Update malicious case %d: error = %v, want ErrCmdIllegal", i, err)
		}
		var stored model.Cronjob
		if err := global.DB.First(&stored, 1).Error; err != nil {
			t.Fatalf("reload cronjob: %v", err)
		}
		if stored.URL != "" {
			t.Fatalf("Update malicious case %d: malicious URL was persisted (url = %q)", i, stored.URL)
		}
	}

	// The benign edit of the same curl job (matching type, legal URL) passes.
	legal := dto.CronjobUpdate{
		ID:   1,
		Type: "curl",
		Name: "legacy-curl",
		Spec: "* * * * *",
		URL:  "https://example.com/hook",
	}
	if err := NewICronjobService().Update(legal.ID, legal); err != nil {
		t.Fatalf("Update legal curl URL: unexpected error: %v", err)
	}
	var stored model.Cronjob
	if err := global.DB.First(&stored, 1).Error; err != nil {
		t.Fatalf("reload cronjob: %v", err)
	}
	if stored.URL != "https://example.com/hook" {
		t.Fatalf("legal URL not persisted, url = %q", stored.URL)
	}
	if stored.Type != "curl" {
		t.Fatalf("Update must keep the stored type, got %q", stored.Type)
	}
}

// TestHandleJobSkipsIllegalCurlURL verifies the runtime guard: a legacy type=
// curl record carrying an unvalidated quote-escape URL must be skipped before
// `curl '<url>'` is built, so the injection marker is never created.
func TestHandleJobSkipsIllegalCurlURL(t *testing.T) {
	ensureValidateLogger(t)
	marker := "/tmp/pwned-cron-curl-guard"
	_ = os.Remove(marker)
	defer os.Remove(marker)

	u := &CronjobService{}
	u.HandleJob(&model.Cronjob{
		BaseModel: model.BaseModel{ID: 9004},
		Name:      "legacy-curl-inject",
		Type:      "curl",
		Spec:      "* * * * *",
		URL:       "http://x' -o " + marker + " '#",
	})
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("injection marker was created by HandleJob")
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

// debugLogCapture is a logrus hook collecting debug-level messages, used to
// assert the exact command shape handleTar builds (quoted exclude rules).
type debugLogCapture struct {
	messages chan string
}

func (c *debugLogCapture) Levels() []logrus.Level {
	return []logrus.Level{logrus.DebugLevel}
}

func (c *debugLogCapture) Fire(entry *logrus.Entry) error {
	select {
	case c.messages <- entry.Message:
	default:
	}
	return nil
}

func (c *debugLogCapture) drain() []string {
	var msgs []string
	for {
		select {
		case m := <-c.messages:
			msgs = append(msgs, m)
		default:
			return msgs
		}
	}
}

// swapDebugLog installs a debug-level logger wired to the capture and restores
// the previous global logger when the test finishes.
func swapDebugLog(t *testing.T, capture *debugLogCapture) {
	t.Helper()
	old := global.LOG
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)
	logger.AddHook(capture)
	global.LOG = logger
	t.Cleanup(func() { global.LOG = old })
}

// archiveMembers lists the members of a tar.gz archive via real tar.
func archiveMembers(t *testing.T, archive string) string {
	t.Helper()
	out, err := exec.Command("tar", "-tzf", archive).CombinedOutput()
	if err != nil {
		t.Fatalf("tar -tzf %s failed: %v, output: %s", archive, err, out)
	}
	return string(out)
}

// TestHandleTarRejectsTabCheckpointPayload is the regression test for the tar
// option injection: an exclusion rule whose parts are joined with tabs was
// word-split by bash after unquoted interpolation, turning the tail into
// standalone tar options (--checkpoint / --checkpoint-action=exec=<prog>) and
// achieving arbitrary program execution as root. The rule must now be rejected
// by the entry check (validCronjobExclusionRules -> cmd.CheckIllegal rejects
// tabs) before any command is built, and the planted program must never run.
func TestHandleTarRejectsTabCheckpointPayload(t *testing.T) {
	ensureValidateLogger(t)
	payloadDir := t.TempDir()
	prog := filepath.Join(payloadDir, "prog.sh")
	marker := filepath.Join(payloadDir, "pwned")
	script := "#!/bin/bash\ntouch " + marker + "\n"
	if err := os.WriteFile(prog, []byte(script), 0755); err != nil {
		t.Fatalf("write prog: %v", err)
	}

	srcDir := filepath.Join(t.TempDir(), "src")
	if err := os.MkdirAll(srcDir, 0755); err != nil {
		t.Fatalf("mkdir src: %v", err)
	}
	targetDir := t.TempDir()

	exclusion := "x\t--checkpoint=1\t--checkpoint-action=exec=" + prog

	// Defense line 1: the entry validator must reject the tab-carrying rule.
	if validCronjobExclusionRules(exclusion) {
		t.Fatal("validCronjobExclusionRules() = true for tab-separated checkpoint payload, want false")
	}

	// Defense line 2 (runtime re-check inside handleTar) returns the same
	// error, and no shell command is built or executed.
	err := handleTar(srcDir, targetDir, "backup.tar.gz", exclusion, "")
	if err == nil {
		t.Fatal("handleTar() error = nil, want ErrCmdIllegal")
	}
	if !isErrCmdIllegal(t, err) {
		t.Fatalf("handleTar() error = %v, want ErrCmdIllegal", err)
	}
	if _, statErr := os.Stat(marker); statErr == nil {
		t.Fatal("checkpoint-action program was executed")
	}
}

// TestHandleTarQuotesAndAppliesExclusionRules verifies both the shape and the
// semantics of the quoting fix: benign rules must appear single-quoted in the
// built command (--exclude '*.log'), tar must still run end to end, and the
// excluded entries must really be missing from the archive while the rest is
// kept.
func TestHandleTarQuotesAndAppliesExclusionRules(t *testing.T) {
	capture := &debugLogCapture{messages: make(chan string, 16)}
	swapDebugLog(t, capture)

	base := t.TempDir()
	srcDir := filepath.Join(base, "src")
	if err := os.MkdirAll(filepath.Join(srcDir, "node_modules", "pkg"), 0755); err != nil {
		t.Fatalf("mkdir src: %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "app.log"), []byte("log"), 0644); err != nil {
		t.Fatalf("write app.log: %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "data.txt"), []byte("data"), 0644); err != nil {
		t.Fatalf("write data.txt: %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "node_modules", "pkg", "index.js"), []byte("js"), 0644); err != nil {
		t.Fatalf("write index.js: %v", err)
	}
	targetDir := filepath.Join(base, "out")

	if err := handleTar(srcDir, targetDir, "backup.tar.gz", "*.log,node_modules", ""); err != nil {
		t.Fatalf("handleTar() error = %v", err)
	}

	archive := filepath.Join(targetDir, "backup.tar.gz")
	if _, err := os.Stat(archive); err != nil {
		t.Fatalf("archive not created: %v", err)
	}

	msgs := capture.drain()
	joined := strings.Join(msgs, "\n")
	for _, want := range []string{"--exclude '*.log'", "--exclude 'node_modules'"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("built tar command does not contain quoted rule %q, commands logged:\n%s", want, joined)
		}
	}

	members := archiveMembers(t, archive)
	if strings.Contains(members, "app.log") {
		t.Fatalf("*.log rule not applied, app.log in archive:\n%s", members)
	}
	if strings.Contains(members, "node_modules") {
		t.Fatalf("node_modules rule not applied:\n%s", members)
	}
	if !strings.Contains(members, "data.txt") {
		t.Fatalf("data.txt missing from archive:\n%s", members)
	}
}

// TestHandleTarSourceDirWithSpaces proves the -C quoting: a directory whose
// name contains spaces (legal and previously split into two tar arguments)
// is now passed as one argument and archived correctly.
func TestHandleTarSourceDirWithSpaces(t *testing.T) {
	capture := &debugLogCapture{messages: make(chan string, 16)}
	swapDebugLog(t, capture)

	base := t.TempDir()
	srcDir := filepath.Join(base, "my dir")
	if err := os.MkdirAll(srcDir, 0755); err != nil {
		t.Fatalf("mkdir src: %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "data.txt"), []byte("hello"), 0644); err != nil {
		t.Fatalf("write data: %v", err)
	}
	targetDir := filepath.Join(base, "out")

	if err := handleTar(srcDir, targetDir, "backup.tar.gz", "", ""); err != nil {
		t.Fatalf("handleTar() error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(targetDir, "backup.tar.gz")); err != nil {
		t.Fatalf("archive not created: %v", err)
	}

	joined := strings.Join(capture.drain(), "\n")
	if !strings.Contains(joined, "-C '"+base+"' 'my dir'") {
		t.Fatalf("built tar command does not quote the -C operands, commands logged:\n%s", joined)
	}
	members := archiveMembers(t, filepath.Join(targetDir, "backup.tar.gz"))
	if !strings.Contains(members, "data.txt") {
		t.Fatalf("data.txt missing from archive (space-in-name dir not archived):\n%s", members)
	}
}

// TestHandleTarEncryptedRoundTrip proves the fd-based encryption end to end:
// handleTar encrypts through `openssl -pass fd:3` (the secret is inherited
// over fd 3 from the ExtraFiles-aware exec helper and never appears in the
// bash -c argv), and the panel's own untar path decrypts the result again.
// Together with TestHandleUnTarExtractsPlainAndEncryptedArchives (which feeds
// a legacy `-k`-generated archive into the same decrypt path) this pins both
// directions of the format compatibility.
func TestHandleTarEncryptedRoundTrip(t *testing.T) {
	ensureValidateLogger(t)
	base := t.TempDir()
	srcDir := filepath.Join(base, "src")
	if err := os.MkdirAll(filepath.Join(srcDir, "sub"), 0755); err != nil {
		t.Fatalf("mkdir src: %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "sub", "data.txt"), []byte("cronjob payload"), 0644); err != nil {
		t.Fatalf("write data: %v", err)
	}
	targetDir := filepath.Join(base, "out")

	const secret = "roundtrip S3cret.42"
	if err := handleTar(srcDir, targetDir, "backup.tar.gz", "", secret); err != nil {
		t.Fatalf("handleTar() error = %v", err)
	}
	archive := filepath.Join(targetDir, "backup.tar.gz")
	if _, err := os.Stat(archive); err != nil {
		t.Fatalf("encrypted archive not created: %v", err)
	}

	restoreDir := filepath.Join(base, "restore")
	if err := handleUnTar(archive, restoreDir, secret); err != nil {
		t.Fatalf("handleUnTar() error = %v", err)
	}
	// handleTar archives the source directory itself (-C '<base>' 'src'), so
	// the member path carries the "src" prefix.
	content, err := os.ReadFile(filepath.Join(restoreDir, "src", "sub", "data.txt"))
	if err != nil {
		t.Fatalf("read restored file: %v", err)
	}
	if string(content) != "cronjob payload" {
		t.Fatalf("restored content = %q, want %q", content, "cronjob payload")
	}
}

// setupCronjobUpdateTestDB wires an in-memory sqlite with the Cronjob and
// JobRecords tables so the service Update method can read the stored row back
// through cronjobRepo. It also installs an idle (never started) scheduler and
// a logger, mirroring the setupMonitorConcurrentTest pattern in
// monitor_test.go, and restores the previous globals when the test finishes.
func setupCronjobUpdateTestDB(t *testing.T) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open in-memory sqlite failed: %v", err)
	}
	if err := db.AutoMigrate(&model.Cronjob{}, &model.JobRecords{}); err != nil {
		t.Fatalf("migrate cronjob tables failed: %v", err)
	}
	oldDB, oldCron := global.DB, global.Cron
	global.DB = db
	global.Cron = cron.New()
	t.Cleanup(func() { global.DB, global.Cron = oldDB, oldCron })
	if global.LOG == nil {
		global.LOG = logrus.New()
	}
}
