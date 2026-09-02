package service

import (
	"testing"

	"github.com/1Panel-dev/1Panel/backend/app/model"
)

// TestRewriteIncludePathPrimaryDomain pins the L3 invariant: the rewrite
// include path used by opWebsite (stop/start), UpdateRewriteConfig and
// GetRewriteConfig all derive the file name from the PRIMARY DOMAIN, not the
// alias. The old opWebsite code built the path from the alias, so a website
// whose primary domain differs from its alias lost its rewrite include on
// stop/start (the remove probe never matched the directive UpdateRewriteConfig
// had added and the start probe never found the file).
func TestRewriteIncludePathPrimaryDomain(t *testing.T) {
	website := &model.Website{Alias: "my-site-alias", PrimaryDomain: "primary.example.com"}
	got := rewriteIncludePath(website)
	want := "/www/sites/my-site-alias/rewrite/primary.example.com.conf"
	if got != want {
		t.Errorf("rewriteIncludePath = %q, want %q", got, want)
	}
	if got == "/www/sites/my-site-alias/rewrite/my-site-alias.conf" {
		t.Error("rewriteIncludePath must not use the alias as the file name")
	}
}

// TestRewriteIncludePathAliasEqualsPrimaryDomain keeps the common case (alias
// derived from the primary domain) stable: the include path then naturally
// reads rewrite/<domain>.conf, exactly like it did before.
func TestRewriteIncludePathAliasEqualsPrimaryDomain(t *testing.T) {
	website := &model.Website{Alias: "www.example.com", PrimaryDomain: "www.example.com"}
	got := rewriteIncludePath(website)
	want := "/www/sites/www.example.com/rewrite/www.example.com.conf"
	if got != want {
		t.Errorf("rewriteIncludePath = %q, want %q", got, want)
	}
}
