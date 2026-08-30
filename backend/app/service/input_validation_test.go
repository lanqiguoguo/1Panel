package service

import (
	"context"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/app/dto/request"
	"github.com/1Panel-dev/1Panel/backend/app/model"
	"github.com/1Panel-dev/1Panel/backend/buserr"
	"github.com/1Panel-dev/1Panel/backend/constant"
	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/glebarez/sqlite"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

// setupValidationTestDB prepares an in-memory sqlite DB with the tables the
// service entry points touch after the input validation passes, mirroring
// the harness style of app_install_test.go. This lets the "valid input
// proceeds" assertions run without a real panel database.
func setupValidationTestDB(t *testing.T) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open in-memory sqlite failed: %v", err)
	}
	if err := db.AutoMigrate(
		&model.Runtime{},
		&model.App{},
		&model.AppDetail{},
		&model.AppInstall{},
		&model.Setting{},
		&model.WebsiteAcmeAccount{},
		&model.WebsiteSSL{},
	); err != nil {
		t.Fatalf("migrate tables failed: %v", err)
	}
	global.DB = db
}

func isBusinessErr(err error, want string) bool {
	if err == nil {
		return false
	}
	be, ok := err.(buserr.BusinessError)
	if !ok {
		return false
	}
	if want == "" {
		return true
	}
	return be.Msg == want
}

// TestOperateNodeModulesRejectsInjection verifies that req.Module is
// validated before it reaches the container bash -c command. A module name
// containing a single quote (which would close the `bash -c '...'` quoting
// in ExecContainerScript) or whitespace (which would split the npm
// argument) must be rejected with ErrCmdIllegal. Legitimate npm specs —
// plain names, scoped packages, version ranges, aliases and git URLs —
// must pass the validation (they may fail later on the missing runtime,
// which proves the check is not over-broad).
func TestOperateNodeModulesRejectsInjection(t *testing.T) {
	if global.LOG == nil {
		global.LOG = logrus.New()
	}
	svc := &RuntimeService{}
	setupValidationTestDB(t)

	malicious := []string{
		"x'; touch /tmp/pwned-node; '",
		"lodash;id",
		"pkg`id`",
		"pkg$(id)",
		"pkg&id",
		"pkg|id",
		"pkg>id",
		"pkg<id",
		"pkg\nid",
		"pkg id",  // space splits the npm argument
		"pkg\tid", // tab
		`pkg"id`,
	}
	for _, module := range malicious {
		err := svc.OperateNodeModules(request.NodeModuleOperateReq{
			Operate:    constant.RuntimeInstall,
			ID:         1,
			Module:     module,
			PkgManager: constant.RuntimeNpm,
		})
		if !isBusinessErr(err, constant.ErrCmdIllegal) {
			t.Errorf("OperateNodeModules(module=%q) error = %v, want ErrCmdIllegal", module, err)
		}
	}

	// Legitimate npm specs: must NOT be rejected by the injection check.
	// (They may still fail because the runtime row does not exist.)
	// Note: specs with "<" or ">" (e.g. "pkg@>=1.0.0") are rejected by
	// design — they are redirection characters in the rejected charset and
	// never needed for a single module install (use "^" or "~" ranges).
	legit := []string{
		"lodash",
		"@scope/pkg",
		"@scope/pkg@^1.0.0",
		"pkg@~1.2.3",
		"pkg@1.0.0",
		"pkg@npm:other",
		"@scope/pkg@git+https://github.com/user/repo.git",
		"pkg-1.0",
		"pkg_2",
		"pkg@1.0.0-beta.1",
	}
	for _, module := range legit {
		err := svc.OperateNodeModules(request.NodeModuleOperateReq{
			Operate:    constant.RuntimeUninstall,
			ID:         1,
			Module:     module,
			PkgManager: constant.RuntimeYarn,
		})
		if isBusinessErr(err, constant.ErrCmdIllegal) {
			t.Errorf("OperateNodeModules(module=%q) unexpectedly rejected as illegal", module)
		}
	}
}

// TestAppInstallRejectsBadName verifies that a malicious install name is
// rejected with ErrCmdIllegal before the docker network or the install
// directory logic runs. Valid names must pass the whitelist and proceed to
// the network step (which may fail on the docker client, but not with
// ErrCmdIllegal).
func TestAppInstallRejectsBadName(t *testing.T) {
	if global.LOG == nil {
		global.LOG = logrus.New()
	}
	svc := AppService{}
	setupValidationTestDB(t)

	malicious := []string{
		"../../evil",
		"../evil",
		"a/../../evil",
		"/abs",
		".hidden",
		"..",
		".",
		"a b",
		"a$b",
		"a;b",
		"a`b",
		"a'b",
		"a&b",
		"a|b",
		"a<b",
		"a>b",
		"a(b)",
		"a/b", // app names have no namespacing
		"a:b", // colon breaks container/image references
		"a\\b",
		"",
	}
	for _, name := range malicious {
		_, err := svc.Install(context.Background(), request.AppInstallCreate{AppDetailId: 1, Name: name})
		if !isBusinessErr(err, constant.ErrCmdIllegal) {
			t.Errorf("AppService.Install(name=%q) error = %v, want ErrCmdIllegal", name, err)
		}
	}

	// Valid app names (frontend appName rule: [a-zA-Z0-9_-]{1,30}).
	// They pass the whitelist and fail later at the docker network step,
	// which is a non-ErrCmdIllegal error (or success if docker is up).
	valid := []string{
		"mysql",
		"nginx",
		"openresty",
		"my-app_1",
		"Redis7",
	}
	for _, name := range valid {
		_, err := svc.Install(context.Background(), request.AppInstallCreate{AppDetailId: 1, Name: name})
		if isBusinessErr(err, constant.ErrCmdIllegal) {
			t.Errorf("AppService.Install(name=%q) unexpectedly rejected as illegal", name)
		}
	}
}

// TestRuntimeCreateRejectsBadName verifies that a malicious runtime name is
// rejected with ErrCmdIllegal before any directory, repo lookup or compose
// path is built. Valid names pass the whitelist and proceed (they may fail
// later on the app detail lookup, but not with ErrCmdIllegal).
func TestRuntimeCreateRejectsBadName(t *testing.T) {
	if global.LOG == nil {
		global.LOG = logrus.New()
	}
	svc := &RuntimeService{}
	setupValidationTestDB(t)

	malicious := []string{
		"../../evil",
		"../evil",
		"a/../../evil",
		"/abs",
		".hidden",
		"..",
		".",
		"a b",
		"a$b",
		"a;b",
		"a`b",
		"a'b",
		"a&b",
		"a|b",
		"a<b",
		"a>b",
		"a(b)",
		"a/b",
		"a:b",
		"a\\b",
		"",
	}
	for _, name := range malicious {
		_, err := svc.Create(request.RuntimeCreate{Name: name, Type: constant.RuntimePHP})
		if !isBusinessErr(err, constant.ErrCmdIllegal) {
			t.Errorf("RuntimeService.Create(name=%q) error = %v, want ErrCmdIllegal", name, err)
		}
	}

	valid := []string{
		"php-8.1",
		"node-18",
		"my_runtime",
		"Go-1.22",
	}
	for _, name := range valid {
		_, err := svc.Create(request.RuntimeCreate{Name: name, Type: constant.RuntimePHP})
		if isBusinessErr(err, constant.ErrCmdIllegal) {
			t.Errorf("RuntimeService.Create(name=%q) unexpectedly rejected as illegal", name)
		}
	}
}

// TestSSLCreateRejectsBadPrimaryDomain verifies that PrimaryDomain is
// validated with the same IsValidDomain rule already applied to
// OtherDomains. Path traversal, shell metacharacters and malformed domains
// must be rejected with ErrDomainFormat; wildcard domains (used for
// wildcard certificates) and normal domains must pass.
func TestSSLCreateRejectsBadPrimaryDomain(t *testing.T) {
	if global.LOG == nil {
		global.LOG = logrus.New()
	}
	svc := WebsiteSSLService{}
	setupValidationTestDB(t)

	malicious := []string{
		"../../var/log/x",
		"../x",
		"a/../../evil",
		"example.com/../../x",
		"x;id",
		"x$(id)",
		"x`id`",
		"x&id",
		"x|id",
		"x'id",
		`x"id`,
		"x y",
		"",
		"..",
		".example.com",
	}
	for _, domain := range malicious {
		_, err := svc.Create(request.WebsiteSSLCreate{PrimaryDomain: domain, Provider: constant.SelfSigned})
		if !isBusinessErr(err, "ErrDomainFormat") {
			t.Errorf("WebsiteSSLService.Create(primary=%q) error = %v, want ErrDomainFormat", domain, err)
		}
	}

	valid := []string{
		"example.com",
		"www.example.com",
		"*.example.com", // wildcard certificate
		"a-b.example.co.uk",
		"xn--fsq.example.com",
		"example.com:8443",
	}
	for _, domain := range valid {
		_, err := svc.Create(request.WebsiteSSLCreate{PrimaryDomain: domain, Provider: constant.SelfSigned})
		if isBusinessErr(err, "ErrDomainFormat") {
			t.Errorf("WebsiteSSLService.Create(primary=%q) unexpectedly rejected as invalid domain", domain)
		}
	}
}

// TestSSLUpdateRejectsBadPrimaryDomain mirrors the Create check for the
// update entry point, which persists primary_domain used later in log and
// download paths.
func TestSSLUpdateRejectsBadPrimaryDomain(t *testing.T) {
	if global.LOG == nil {
		global.LOG = logrus.New()
	}
	svc := WebsiteSSLService{}
	setupValidationTestDB(t)

	err := svc.Update(request.WebsiteSSLUpdate{ID: 1, PrimaryDomain: "../../var/log/x", Provider: constant.SelfSigned})
	if !isBusinessErr(err, "ErrDomainFormat") {
		t.Errorf("WebsiteSSLService.Update(primary=%q) error = %v, want ErrDomainFormat", "../../var/log/x", err)
	}

	// A valid domain passes the check and proceeds to the repo lookup,
	// which must not produce ErrDomainFormat.
	err = svc.Update(request.WebsiteSSLUpdate{ID: 1, PrimaryDomain: "example.com", Provider: constant.SelfSigned})
	if isBusinessErr(err, "ErrDomainFormat") {
		t.Errorf("WebsiteSSLService.Update(primary=%q) unexpectedly rejected as invalid domain", "example.com")
	}
}
