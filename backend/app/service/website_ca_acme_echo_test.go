package service

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/app/dto/response"
	"github.com/1Panel-dev/1Panel/backend/app/model"
)

// TestCAModelJSONHidesPrivateKey asserts the CA private key never leaves the
// process through the model (Page list path), while the GetCA detail DTO —
// which feeds the CA detail drawer's key view/copy tab — still carries it.
func TestCAModelJSONHidesPrivateKey(t *testing.T) {
	ca := model.WebsiteCA{
		Name:       "root-ca",
		CSR:        "-----BEGIN CERTIFICATE-----",
		PrivateKey: "-----BEGIN RSA PRIVATE KEY--ROOT-KEY-SECRET--",
		KeyType:    "2048",
	}
	raw, err := json.Marshal(ca)
	if err != nil {
		t.Fatalf("marshal WebsiteCA failed: %v", err)
	}
	if strings.Contains(string(raw), "ROOT-KEY-SECRET") {
		t.Fatalf("WebsiteCA json leaks privateKey: %s", raw)
	}
	if strings.Contains(string(raw), "privateKey") {
		t.Fatalf("WebsiteCA json still exposes a privateKey field: %s", raw)
	}

	// detail path: GetCA copies the key onto the DTO explicitly
	dto := response.WebsiteCADTO{WebsiteCA: ca}
	dto.PrivateKey = ca.PrivateKey
	dtoRaw, err := json.Marshal(dto)
	if err != nil {
		t.Fatalf("marshal WebsiteCADTO failed: %v", err)
	}
	if !strings.Contains(string(dtoRaw), "ROOT-KEY-SECRET") {
		t.Fatalf("GetCA detail DTO lost the privateKey echo: %s", dtoRaw)
	}

	// list path: Page builds DTOs without copying the key
	listDTO, err := json.Marshal(response.WebsiteCADTO{WebsiteCA: ca})
	if err != nil {
		t.Fatalf("marshal list WebsiteCADTO failed: %v", err)
	}
	if strings.Contains(string(listDTO), "ROOT-KEY-SECRET") {
		t.Fatalf("list DTO leaks privateKey: %s", listDTO)
	}
}

// TestAcmeModelJSONHidesEabHmacKey asserts the EAB HMAC secret is dropped
// from JSON (the ACME page has no edit form; renew reads the DB model) while
// the public EabKid identifier and the rest of the account stay visible.
func TestAcmeModelJSONHidesEabHmacKey(t *testing.T) {
	account := model.WebsiteAcmeAccount{
		Email:      "test@example.com",
		URL:        "https://acme.example.com/account/1",
		Type:       "google",
		EabKid:     "kid-123-public",
		EabHmacKey: "hmac-456-SECRET",
		KeyType:    "P256",
	}
	raw, err := json.Marshal(account)
	if err != nil {
		t.Fatalf("marshal WebsiteAcmeAccount failed: %v", err)
	}
	if strings.Contains(string(raw), "hmac-456-SECRET") {
		t.Fatalf("WebsiteAcmeAccount json leaks EabHmacKey: %s", raw)
	}
	if strings.Contains(string(raw), "eabHmacKey") {
		t.Fatalf("WebsiteAcmeAccount json still exposes an eabHmacKey field: %s", raw)
	}
	if !strings.Contains(string(raw), "kid-123-public") {
		t.Fatalf("public EabKid must stay in the echo: %s", raw)
	}
	if !strings.Contains(string(raw), "test@example.com") {
		t.Fatalf("account email must stay in the echo: %s", raw)
	}
}
