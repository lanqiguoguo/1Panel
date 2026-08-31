package service

import (
	"errors"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/app/dto/request"
	"github.com/1Panel-dev/1Panel/backend/app/model"
	"github.com/1Panel-dev/1Panel/backend/buserr"
	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

// setupWebsiteUpdateTestDB wires an in-memory sqlite with the Website table so
// UpdateWebsite can read the seeded row back through websiteRepo, mirroring
// the setupCronjobUpdateTestDB pattern in cronjob_validate_test.go.
func setupWebsiteUpdateTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open in-memory sqlite failed: %v", err)
	}
	if err := db.AutoMigrate(&model.Website{}, &model.WebsiteDomain{}); err != nil {
		t.Fatalf("migrate website tables failed: %v", err)
	}
	oldDB := global.DB
	global.DB = db
	t.Cleanup(func() { global.DB = oldDB })
	return db
}

func seedWebsite(t *testing.T, db *gorm.DB, primaryDomain, alias string) model.Website {
	t.Helper()
	website := model.Website{
		PrimaryDomain: primaryDomain,
		Type:          "deployment",
		Alias:         alias,
		Status:        "Running",
	}
	if err := db.Create(&website).Error; err != nil {
		t.Fatalf("seed website failed: %v", err)
	}
	return website
}

// TestUpdateWebsiteRejectsMalformedPrimaryDomain is the integration regression
// for the P1-3 fix: UpdateWebsite must apply the same IsValidDomain gate as
// the create path (getWebsiteDomains) BEFORE assigning req.PrimaryDomain, so
// shell-injection payloads that would later reach the unquoted tar command in
// backupLogFile (cronjob_helper.go) or the rewrite .conf path (website.go)
// can never be persisted.
func TestUpdateWebsiteRejectsMalformedPrimaryDomain(t *testing.T) {
	db := setupWebsiteUpdateTestDB(t)
	seeded := seedWebsite(t, db, "seed.example.com", "seed-site")

	payloads := []string{
		"a;id>x;b",   // P1-3 report payload: command chaining + redirection
		"../evil",    // path traversal into rewrite/backup paths
		"a b.com",    // whitespace (would split shell words)
		"a'id",       // single quote (breaks the new tar quoting)
		"a\"b",       // double quote
		"a`id`b",     // backticks
		"$(id).com",  // command substitution
		"a.com/x",    // slash
		"..",         // traversal root
		"a|id|b.com", // pipe chaining
		"a&b.com",    // background chaining
		"a\nb.com",   // newline
	}
	for _, payload := range payloads {
		err := NewIWebsiteService().UpdateWebsite(request.WebsiteUpdate{
			ID:            seeded.ID,
			PrimaryDomain: payload,
		})
		if err == nil {
			t.Errorf("UpdateWebsite with PrimaryDomain %q: expected error, got nil", payload)
			continue
		}
		var bizErr buserr.BusinessError
		if !errors.As(err, &bizErr) || bizErr.Msg != "ErrDomainFormat" {
			t.Errorf("UpdateWebsite with PrimaryDomain %q: error = %v, want ErrDomainFormat business error (same as create path)", payload, err)
		}
		var stored model.Website
		if err := db.First(&stored, seeded.ID).Error; err != nil {
			t.Fatalf("re-load seeded website failed: %v", err)
		}
		if stored.PrimaryDomain != "seed.example.com" {
			t.Errorf("UpdateWebsite with PrimaryDomain %q: persisted primaryDomain = %q, want unchanged %q", payload, stored.PrimaryDomain, "seed.example.com")
		}
	}
}

// TestUpdateWebsiteAcceptsValidPrimaryDomain guards against false positives:
// every value the create path already accepts (plain domains, wildcard,
// Chinese IDN, domain with port, punycode) must keep being accepted by the
// update path, otherwise existing websites could no longer be edited.
func TestUpdateWebsiteAcceptsValidPrimaryDomain(t *testing.T) {
	db := setupWebsiteUpdateTestDB(t)

	valid := []string{
		"a.com",
		"*.a.cn",
		"中文域名.公司",
		"a.com:8080",
		"xn--fiq228c.com",
		"a-b.cn",
	}
	for _, domain := range valid {
		seeded := seedWebsite(t, db, "seed.example.com", "seed-site")
		if err := NewIWebsiteService().UpdateWebsite(request.WebsiteUpdate{
			ID:            seeded.ID,
			PrimaryDomain: domain,
		}); err != nil {
			t.Errorf("UpdateWebsite with PrimaryDomain %q: unexpected error %v", domain, err)
			continue
		}
		var stored model.Website
		if err := db.First(&stored, seeded.ID).Error; err != nil {
			t.Fatalf("re-load seeded website failed: %v", err)
		}
		if stored.PrimaryDomain != domain {
			t.Errorf("UpdateWebsite with PrimaryDomain %q: persisted primaryDomain = %q", domain, stored.PrimaryDomain)
		}
	}
}
