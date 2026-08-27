package service

import (
	"strings"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/app/dto/request"
	"github.com/1Panel-dev/1Panel/backend/constant"
	"github.com/1Panel-dev/1Panel/backend/utils/files"
)

// TestValidSiteName covers the shared validator used for website aliases and
// nginx proxy/redirect include file names: traversal names, dot segments and
// shell metacharacters must be rejected, while CJK characters, spaces, dots,
// dashes and underscores stay valid (reject-based, not an ASCII whitelist).
func TestValidSiteName(t *testing.T) {
	valid := []string{
		"my-proxy",
		"代理 名称.v2",
		"site_1",
		"xn--fiq228c",
		"a.b-c_d",
		"Web Site 01",
		"a.b",   // single dots are legitimate
		"a1.b2", // dot in the middle, no dot-dot segment
	}

	invalid := []string{
		"", // empty (also enforced by files.ValidShellArgs)
		".",
		"..",
		"../x",
		"a/../b",
		"a/b",
		"a\\b",
		"..a..", // contains a dot-dot segment
		"a'b",
		"a\"b",
		"a;b",
		"a|b",
		"a&b",
		"a$(x)b",
		"a`b",
		"a(b)",
		"a>b",
		"a<b",
		"a\nb",
		"a\rb",
	}

	for _, s := range valid {
		if !validSiteName(s) {
			t.Errorf("validSiteName(%q) = false, want true", s)
		}
	}
	for _, s := range invalid {
		if validSiteName(s) {
			t.Errorf("validSiteName(%q) = true, want false", s)
		}
	}
}

// TestValidContainerName covers the docker container-name charset applied to
// AppInstall container names at create/update: 1-128 characters of
// alphanumerics, underscore, dot and dash, starting with a letter or digit.
func TestValidContainerName(t *testing.T) {
	valid := []string{
		"a",
		"A",
		"1Panel-openresty-ab12",
		"1Panel_openresty.v2",
		"my_app.1-x",
		strings.Repeat("a", 128),
	}

	invalid := []string{
		"",
		"-lead",
		".lead",
		"_lead",
		"1Panel openresty", // space
		"a/b",
		"a\\b",
		"..",
		"a$(x)b",
		"a'b",
		"a`b",
		"a;b",
		"容器",
		strings.Repeat("a", 129),
	}

	for _, s := range valid {
		if !files.ValidContainerName(s) {
			t.Errorf("ValidContainerName(%q) = false, want true", s)
		}
	}
	for _, s := range invalid {
		if files.ValidContainerName(s) {
			t.Errorf("ValidContainerName(%q) = true, want false", s)
		}
	}
}

// TestWebsiteServiceProxyRedirectNameRejected proves that the proxy/redirect
// service entry points reject hostile req.Name values with ErrCmdIllegal
// before any path is built or any repo/DB access happens: the validation is
// the first statement of each method, so these calls return without touching
// the database (nil here) and without reading or writing any file.
func TestWebsiteServiceProxyRedirectNameRejected(t *testing.T) {
	hostile := []string{
		"../etc/cron.d/pwn",
		"..",
		"a/b",
		"a\\b",
		"a'b",
		"a$(x)b",
		"a;b",
	}

	svc := WebsiteService{}
	for _, name := range hostile {
		assertBusinessError(t, svc.DeleteProxy(request.WebsiteProxyDel{ID: 1, Name: name}), constant.ErrCmdIllegal)
		assertBusinessError(t, svc.OperateProxy(request.WebsiteProxyConfig{ID: 1, Operate: "create", Name: name, Match: "/", ProxyPass: "http://127.0.0.1:80", ProxyHost: "x"}), constant.ErrCmdIllegal)
		assertBusinessError(t, svc.OperateRedirect(request.NginxRedirectReq{WebsiteID: 1, Operate: "create", Name: name, Type: "path", Redirect: "404", Target: "/"}), constant.ErrCmdIllegal)
		assertBusinessError(t, svc.UpdateProxyFile(request.NginxProxyUpdate{WebsiteID: 1, Name: name, Content: "x"}), constant.ErrCmdIllegal)
		assertBusinessError(t, svc.UpdateRedirectFile(request.NginxRedirectUpdate{WebsiteID: 1, Name: name, Content: "x"}), constant.ErrCmdIllegal)
	}
}

// TestCreateWebsiteAliasRejected proves the alias gate in CreateWebsite fires
// before any DB or openresty access (it is the first check after the
// "default" reservation), and that the reserved alias still errors as before.
func TestCreateWebsiteAliasRejected(t *testing.T) {
	svc := WebsiteService{}
	for _, alias := range []string{"../x", "a/b", "a\\b", "a'b", "a$(x)b", "a;b", ".."} {
		assertBusinessError(t, svc.CreateWebsite(request.WebsiteCreate{Alias: alias, PrimaryDomain: "a.com", Type: "deployment", WebsiteGroupID: 1}), constant.ErrCmdIllegal)
	}
	assertBusinessError(t, svc.CreateWebsite(request.WebsiteCreate{Alias: "default", PrimaryDomain: "a.com", Type: "deployment", WebsiteGroupID: 1}), "ErrDefaultAlias")
}

// TestLegacyDefaultContainerNamesStillValid spot-checks that the docker
// charset of ValidContainerName accepts the panel-generated default names
// ("1Panel-<key>-<rand4>") so pre-existing openresty rows keep passing the
// new gates; validSiteName is checked for the same values because website
// aliases may legitimately look identical.
func TestLegacyDefaultContainerNamesStillValid(t *testing.T) {
	legacy := []string{"1Panel-openresty-ab12", "1Panel-mysql-x9k2", "1Panel-openresty-Zx91"}
	for _, name := range legacy {
		if !files.ValidContainerName(name) {
			t.Errorf("ValidContainerName(%q) = false, want true for legacy default name", name)
		}
		if !validSiteName(name) {
			t.Errorf("validSiteName(%q) = false, want true", name)
		}
	}
}
