package service

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/app/dto"
	"github.com/1Panel-dev/1Panel/backend/app/model"
	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/1Panel-dev/1Panel/backend/init/cache/badger_db"
	"github.com/1Panel-dev/1Panel/backend/init/session/psession"
	"github.com/dgraph-io/badger/v4"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
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

// setupSettingUpdateTest prepares an in-memory sqlite DB with a seeded settings
// table plus an in-memory session store, mirroring auth_test.go.
func setupSettingUpdateTest(t *testing.T) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open in-memory sqlite failed: %v", err)
	}
	if err := db.AutoMigrate(&model.Setting{}); err != nil {
		t.Fatalf("migrate settings failed: %v", err)
	}
	seeds := []model.Setting{
		{Key: "SessionTimeout", Value: "60"},
		{Key: "MonitorStatus", Value: "disable"},
		{Key: "MFAStatus", Value: "disable"},
		{Key: "UserName", Value: "admin"},
		{Key: "PanelName", Value: "1Panel"},
		{Key: "SecurityEntrance", Value: "entrance-1"},
	}
	for i := range seeds {
		if err := db.Create(&seeds[i]).Error; err != nil {
			t.Fatalf("seed setting %s failed: %v", seeds[i].Key, err)
		}
	}
	global.DB = db

	cache, err := badger.Open(badger.DefaultOptions("").WithInMemory(true))
	if err != nil {
		t.Fatalf("open in-memory badger failed: %v", err)
	}
	t.Cleanup(func() { _ = cache.Close() })
	global.SESSION = psession.NewPSession(badger_db.NewCacheDB(cache))
}

func TestSettingUpdateWhitelist(t *testing.T) {
	setupSettingUpdateTest(t)
	u := &SettingService{}

	allowed := []struct {
		key   string
		value string
	}{
		{"SessionTimeout", "120"},
		{"MonitorStatus", "disable"},
		{"PanelName", "my-panel"},
		{"SecurityEntrance", "entrance-1"},
		{"AllowIPs", "1.2.3.4"},
		{"BindDomain", ""},
		{"NoAuthSetting", "200"},
		{"ComplexityVerification", "enable"},
		{"FileRecycleBin", "enable"},
		{"SnapshotIgnore", "a,b"},
		{"DockerSockPath", "unix:///var/run/docker.sock"},
		{"Theme", "dark"},
		{"MenuTabs", "enable"},
		{"Language", "zh"},
		{"DeveloperMode", "disable"},
		{"DefaultNetwork", "all"},
		{"SystemIP", "10.0.0.1"},
		{"ExpirationDays", "90"},
		{"MonitorStoreDays", "7"},
		{"UserName", "admin"}, // only existing value passes the frontend rename flow
	}
	for _, tt := range allowed {
		if err := u.Update(tt.key, tt.value); err != nil {
			t.Errorf("Update(%q, %q) returned error: %v", tt.key, tt.value, err)
		}
	}

	check := func(key, want string) {
		t.Helper()
		got, err := settingRepo.Get(settingRepo.WithByKey(key))
		if err != nil {
			t.Fatalf("read setting %s failed: %v", key, err)
		}
		if got.Value != want {
			t.Errorf("setting %s = %q, want %q", key, got.Value, want)
		}
	}
	check("SessionTimeout", "120")
	check("PanelName", "my-panel")
	check("SecurityEntrance", "entrance-1")
	check("UserName", "admin")
}

func TestSettingUpdateWhitelistRejectsSensitiveKeys(t *testing.T) {
	setupSettingUpdateTest(t)
	u := &SettingService{}

	denied := []struct {
		key   string
		value string
	}{
		{"Password", "attacker-password"},
		{"MFAStatus", "enable"}, // enabling MFA requires /settings/mfa/bind
		{"MFASecret", "JBSWY3DPEHPK3PXP"},
		{"MFAInterval", "30"},
		{"ApiKey", "attacker-api-key"},
		{"ApiInterfaceStatus", "enable"},
		{"IpWhiteList", "0.0.0.0"},
		{"ApiKeyValidityTime", "99999"},
		{"PASSWORD_PRIVATE_KEY", "attacker-private-key"},
		{"PASSWORD_PUBLIC_KEY", "attacker-public-key"},
		{"SSL", "disable"},
		{"SSLType", "self"},
		{"ServerPort", "11111"},
		{"BindAddress", "0.0.0.0"},
		{"Ipv6", "enable"},
		{"ProxyPasswd", "attacker-proxy-passwd"},
		{"ExpirationTime", "2026-01-01 00:00:00"},
		{"SystemStatus", "Free"},
		{"SystemVersion", "v1.0.0"},
	}
	for _, tt := range denied {
		if err := u.Update(tt.key, tt.value); err == nil {
			t.Errorf("Update(%q, %q) succeeded, want error (key must be rejected)", tt.key, tt.value)
		}
	}

	// the attempts must not have changed anything in the DB: an absent key
	// (record not found) also proves nothing was written
	for _, tt := range denied {
		got, err := settingRepo.Get(settingRepo.WithByKey(tt.key))
		if err == nil && got.Value == tt.value {
			t.Errorf("setting %s was modified to %q by a rejected update", tt.key, tt.value)
		}
	}
}

func TestSettingUpdateRejectsEmptyAndUnknownKeys(t *testing.T) {
	setupSettingUpdateTest(t)
	u := &SettingService{}

	for _, key := range []string{"", "DoesNotExist", "monitorStatus", "session_timeout"} {
		if err := u.Update(key, "x"); err == nil {
			t.Errorf("Update(%q, \"x\") succeeded, want error", key)
		}
	}
}

func TestSettingUpdateMFAStatusDisable(t *testing.T) {
	setupSettingUpdateTest(t)
	u := &SettingService{}

	if err := u.Update("MFAStatus", "disable"); err != nil {
		t.Fatalf("Update(MFAStatus, disable) failed: %v", err)
	}
	got, err := settingRepo.Get(settingRepo.WithByKey("MFAStatus"))
	if err != nil {
		t.Fatalf("read MFAStatus failed: %v", err)
	}
	if got.Value != "disable" {
		t.Errorf("MFAStatus = %q, want disable", got.Value)
	}
}
