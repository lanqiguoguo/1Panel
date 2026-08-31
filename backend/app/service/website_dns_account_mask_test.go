package service

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/app/dto"
	"github.com/1Panel-dev/1Panel/backend/app/dto/request"
	"github.com/1Panel-dev/1Panel/backend/app/model"
	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/glebarez/sqlite"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

// setupDnsAccountMaskTest prepares an in-memory sqlite DB with one seeded DNS
// account whose authorization holds a mix of secret and identifier fields, so
// the Page/Update echo semantics can be driven end-to-end at service level.
func setupDnsAccountMaskTest(t *testing.T) model.WebsiteDnsAccount {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open in-memory sqlite failed: %v", err)
	}
	if err := db.AutoMigrate(&model.WebsiteDnsAccount{}); err != nil {
		t.Fatalf("migrate WebsiteDnsAccount failed: %v", err)
	}
	global.DB = db
	global.LOG = logrus.New()

	account := model.WebsiteDnsAccount{
		Name:          "test-dns",
		Type:          "AliYun",
		Authorization: `{"accessKey":"AKID-REAL","secretKey":"SK-REAL-SECRET","region":"cn-north-1"}`,
	}
	if err := websiteDnsRepo.Create(account); err != nil {
		t.Fatalf("seed dns account failed: %v", err)
	}
	// Create copies the model, so the ID is not back-filled; re-read the row.
	seeded, err := websiteDnsRepo.GetFirst(commonRepo.WithByName("test-dns"))
	if err != nil {
		t.Fatalf("reload seeded dns account failed: %v", err)
	}
	return *seeded
}

// TestDnsAccountPageMasksAuthorization mirrors the backup-account contract:
// the Page echo replaces every secret value with the mask placeholder while
// keeping key names and identifier fields readable.
func TestDnsAccountPageMasksAuthorization(t *testing.T) {
	seeded := setupDnsAccountMaskTest(t)

	total, accounts, err := WebsiteDnsAccountService{}.Page(dto.PageInfo{Page: 1, PageSize: 10})
	if err != nil {
		t.Fatalf("Page failed: %v", err)
	}
	if total != 1 || len(accounts) != 1 {
		t.Fatalf("expected 1 account, got total=%d len=%d", total, len(accounts))
	}
	dto := accounts[0]
	if dto.ID != seeded.ID {
		t.Fatalf("unexpected account id %d", dto.ID)
	}
	if dto.Authorization["secretKey"] != backupMaskValue {
		t.Fatalf("secretKey not masked, got %q", dto.Authorization["secretKey"])
	}
	// identifiers and config stay readable so the edit form keeps working
	if dto.Authorization["accessKey"] != "AKID-REAL" {
		t.Fatalf("accessKey should pass through, got %q", dto.Authorization["accessKey"])
	}
	if dto.Authorization["region"] != "cn-north-1" {
		t.Fatalf("region should pass through, got %q", dto.Authorization["region"])
	}
	// key names must be preserved
	for _, key := range []string{"accessKey", "secretKey", "region"} {
		if _, ok := dto.Authorization[key]; !ok {
			t.Fatalf("masked echo dropped key %q", key)
		}
	}
	raw, _ := json.Marshal(dto)
	if strings.Contains(string(raw), "SK-REAL-SECRET") {
		t.Fatalf("Page echo leaked the stored secret: %s", raw)
	}
	// stored value untouched by the read path
	stored, err := websiteDnsRepo.GetFirst(commonRepo.WithByID(seeded.ID))
	if err != nil {
		t.Fatalf("reload stored account failed: %v", err)
	}
	if !strings.Contains(stored.Authorization, "SK-REAL-SECRET") {
		t.Fatalf("stored authorization was modified by Page: %s", stored.Authorization)
	}
}

// TestDnsAccountUpdateMaskedSecretsPreserved covers the three Update cases the
// edit form produces: a masked secret (user left the field alone), an empty
// secret (user cleared the field) and a newly typed secret.
func TestDnsAccountUpdateMaskedSecretsPreserved(t *testing.T) {
	seeded := setupDnsAccountMaskTest(t)
	svc := WebsiteDnsAccountService{}

	// masked secret + empty secret are kept, identifiers and new plaintext apply
	_, err := svc.Update(request.WebsiteDnsAccountUpdate{
		ID:   seeded.ID,
		Name: "test-dns",
		Type: "AliYun",
		Authorization: map[string]string{
			"accessKey": "AKID-NEW",
			"region":    "eu-west-1",
			"secretKey": backupMaskValue,
		},
	})
	if err != nil {
		t.Fatalf("Update with masked secret failed: %v", err)
	}
	stored, err := websiteDnsRepo.GetFirst(commonRepo.WithByID(seeded.ID))
	if err != nil {
		t.Fatalf("reload stored account failed: %v", err)
	}
	var merged map[string]string
	if err := json.Unmarshal([]byte(stored.Authorization), &merged); err != nil {
		t.Fatalf("stored authorization is not valid json: %v", err)
	}
	if merged["secretKey"] != "SK-REAL-SECRET" {
		t.Fatalf("masked secret must keep stored value, got %q", merged["secretKey"])
	}
	if merged["accessKey"] != "AKID-NEW" || merged["region"] != "eu-west-1" {
		t.Fatalf("non-secret fields should take submitted values, got %v", merged)
	}
	if strings.Contains(stored.Authorization, backupMaskValue) {
		t.Fatalf("mask placeholder must never be persisted: %s", stored.Authorization)
	}

	// empty secret is kept too
	if _, err := svc.Update(request.WebsiteDnsAccountUpdate{
		ID:   seeded.ID,
		Name: "test-dns",
		Type: "AliYun",
		Authorization: map[string]string{
			"accessKey": "AKID-NEW",
			"region":    "eu-west-1",
			"secretKey": "",
		},
	}); err != nil {
		t.Fatalf("Update with empty secret failed: %v", err)
	}
	stored, err = websiteDnsRepo.GetFirst(commonRepo.WithByID(seeded.ID))
	if err != nil {
		t.Fatalf("reload stored account failed: %v", err)
	}
	if !strings.Contains(stored.Authorization, "SK-REAL-SECRET") {
		t.Fatalf("empty secret must keep stored value, got %s", stored.Authorization)
	}

	// a newly typed secret takes effect
	if _, err := svc.Update(request.WebsiteDnsAccountUpdate{
		ID:   seeded.ID,
		Name: "test-dns",
		Type: "AliYun",
		Authorization: map[string]string{
			"accessKey": "AKID-NEW",
			"region":    "eu-west-1",
			"secretKey": "SK-ROTATED",
		},
	}); err != nil {
		t.Fatalf("Update with plaintext secret failed: %v", err)
	}
	stored, err = websiteDnsRepo.GetFirst(commonRepo.WithByID(seeded.ID))
	if err != nil {
		t.Fatalf("reload stored account failed: %v", err)
	}
	if !strings.Contains(stored.Authorization, "SK-ROTATED") {
		t.Fatalf("plaintext secret should be stored, got %s", stored.Authorization)
	}
}
