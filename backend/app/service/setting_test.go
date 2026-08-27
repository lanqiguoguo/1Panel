package service

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/app/dto"
)

func TestSanitizeSettingInfo(t *testing.T) {
	info := &dto.SettingInfo{
		UserName:               "admin",
		SecurityEntrance:       "entrance-123",
		AllowIPs:               "1.2.3.4",
		MFAStatus:              "enable",
		MFASecret:              "JBSWY3DPEHPK3PXP",
		MFAInterval:            "30",
		ApiInterfaceStatus:     "enable",
		ApiKey:                 "abcdefghijklmnopqrstuvwxyz123456",
		IpWhiteList:            "127.0.0.1",
		ApiKeyValidityTime:     "120",
		ProxyPasswdKeep:        "true",
		ProxyPasswd:            "proxy-plaintext",
		ProxyType:              "http",
		ProxyUrl:               "127.0.0.1",
		ProxyUser:              "u",
		SessionTimeout:         "60",
		FileRecycleBin:         "enable",
		AppStoreSyncStatus:     "done",
		ComplexityVerification: "disable",
	}

	sanitizeSettingInfo(info)

	if info.MFASecret != "" {
		t.Errorf("sanitizeSettingInfo: MFASecret = %q, want empty", info.MFASecret)
	}
	if info.ProxyPasswd != "" {
		t.Errorf("sanitizeSettingInfo: ProxyPasswd = %q, want empty", info.ProxyPasswd)
	}

	// fields the frontend actually needs must be preserved
	preserved := []struct {
		name  string
		value string
	}{
		{"UserName", info.UserName},
		{"SecurityEntrance", info.SecurityEntrance},
		{"AllowIPs", info.AllowIPs},
		{"MFAStatus", info.MFAStatus},
		{"MFAInterval", info.MFAInterval},
		{"ApiInterfaceStatus", info.ApiInterfaceStatus},
		{"ApiKey", info.ApiKey},
		{"IpWhiteList", info.IpWhiteList},
		{"ApiKeyValidityTime", info.ApiKeyValidityTime},
		{"ProxyPasswdKeep", info.ProxyPasswdKeep},
		{"ProxyType", info.ProxyType},
		{"ProxyUrl", info.ProxyUrl},
		{"ProxyUser", info.ProxyUser},
		{"SessionTimeout", info.SessionTimeout},
		{"FileRecycleBin", info.FileRecycleBin},
		{"AppStoreSyncStatus", info.AppStoreSyncStatus},
		{"ComplexityVerification", info.ComplexityVerification},
	}
	for _, p := range preserved {
		if p.value == "" {
			t.Errorf("sanitizeSettingInfo: %s = %q, want preserved non-empty", p.name, p.value)
		}
	}

	// the serialized payload must not carry the secrets
	raw, err := json.Marshal(info)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	for _, secret := range []string{"JBSWY3DPEHPK3PXP", "proxy-plaintext"} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("sanitizeSettingInfo: serialized payload still contains secret %q", secret)
		}
	}
	var decoded map[string]interface{}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}
	if v, ok := decoded["mfaSecret"]; !ok || v != "" {
		t.Errorf("serialized mfaSecret = %v (present=%v), want empty string", v, ok)
	}
	if v, ok := decoded["proxyPasswd"]; !ok || v != "" {
		t.Errorf("serialized proxyPasswd = %v (present=%v), want empty string", v, ok)
	}
}

func TestSanitizeSettingInfoIdempotent(t *testing.T) {
	info := &dto.SettingInfo{MFASecret: "", ProxyPasswd: ""}
	sanitizeSettingInfo(info)
	if info.MFASecret != "" || info.ProxyPasswd != "" {
		t.Fatalf("sanitizeSettingInfo not idempotent: %+v", info)
	}
}
