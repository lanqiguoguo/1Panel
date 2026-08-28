package service

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/app/dto"
	"github.com/1Panel-dev/1Panel/backend/app/model"
	"github.com/1Panel-dev/1Panel/backend/constant"
	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/1Panel-dev/1Panel/backend/init/cache/badger_db"
	"github.com/1Panel-dev/1Panel/backend/init/session/psession"
	"github.com/1Panel-dev/1Panel/backend/utils/encrypt"
	httpUtil "github.com/1Panel-dev/1Panel/backend/utils/http"
	"github.com/dgraph-io/badger/v4"
	"github.com/glebarez/sqlite"
	"github.com/sirupsen/logrus"
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

// ---- password update / expired-handle flows (encrypted envelope wire format) ----

const (
	testEncryptKey    = "abcdefghijklmnop"                 // 16 bytes, required by StringEncrypt's AES-128
	testAESKey        = "0123456789abcdef0123456789abcdef" // 32 bytes, mirrors the frontend generateAESKey() hex output
	storedOldPassword = "old-password-123"
)

// setupPasswordFlowTest extends setupSettingUpdateTest with the settings the
// password flows rely on: EncryptKey (storage salt key), the current Password,
// expiration fields and the RSA keypair used for the password envelopes.
// It returns the private key so tests can mint valid envelopes.
func setupPasswordFlowTest(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	setupSettingUpdateTest(t)

	// StringEncrypt/StringDecrypt cache the storage key in global config;
	// clear it so the value seeded below is used and restore it afterwards.
	prevKey := global.CONF.System.EncryptKey
	global.CONF.System.EncryptKey = ""
	t.Cleanup(func() { global.CONF.System.EncryptKey = prevKey })

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key failed: %v", err)
	}
	priPEM := exportPrivateKeyToPEM(privateKey)
	pubPEM, err := exportPublicKeyToPEM(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("export public key failed: %v", err)
	}

	// EncryptKey must be seeded before StringEncrypt is called, since it loads
	// the storage key from the settings table
	if err := global.DB.Create(&model.Setting{Key: "EncryptKey", Value: testEncryptKey}).Error; err != nil {
		t.Fatalf("seed setting EncryptKey failed: %v", err)
	}
	storedPassword, err := encrypt.StringEncrypt(storedOldPassword)
	if err != nil {
		t.Fatalf("encrypt stored password failed: %v", err)
	}
	seeds := []model.Setting{
		{Key: "Password", Value: storedPassword},
		{Key: "ExpirationDays", Value: "90"},
		{Key: "ExpirationTime", Value: "2000-01-01 00:00:00"},
		{Key: "PASSWORD_PRIVATE_KEY", Value: priPEM},
		{Key: "PASSWORD_PUBLIC_KEY", Value: pubPEM},
	}
	for i := range seeds {
		if err := global.DB.Create(&seeds[i]).Error; err != nil {
			t.Fatalf("seed setting %s failed: %v", seeds[i].Key, err)
		}
	}
	return privateKey
}

// buildPasswordEnvelope mints an envelope in the exact wire format the
// frontend encryptPassword() helper produces:
// base64(RSA-PKCS1v15(aesKey)):base64(iv):base64(AES-CBC-PKCS7(password)).
func buildPasswordEnvelope(t *testing.T, publicKey *rsa.PublicKey, password string) string {
	t.Helper()
	keyCipher, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, []byte(testAESKey))
	if err != nil {
		t.Fatalf("rsa encrypt aes key failed: %v", err)
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		t.Fatalf("generate iv failed: %v", err)
	}
	block, err := aes.NewCipher([]byte(testAESKey))
	if err != nil {
		t.Fatalf("new aes cipher failed: %v", err)
	}
	padded := pkcs7PadForTest([]byte(password), aes.BlockSize)
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)
	return base64.StdEncoding.EncodeToString(keyCipher) +
		":" + base64.StdEncoding.EncodeToString(iv) +
		":" + base64.StdEncoding.EncodeToString(ciphertext)
}

func pkcs7PadForTest(data []byte, blockSize int) []byte {
	padLen := blockSize - len(data)%blockSize
	return append(data, bytes.Repeat([]byte{byte(padLen)}, padLen)...)
}

// storedPasswordEquals decrypts the Password setting and compares it with the
// given plaintext.
func storedPasswordEquals(t *testing.T, want string) bool {
	t.Helper()
	got, err := settingRepo.Get(settingRepo.WithByKey("Password"))
	if err != nil {
		t.Fatalf("read Password setting failed: %v", err)
	}
	plaintext, err := encrypt.StringDecrypt(got.Value)
	if err != nil {
		t.Fatalf("decrypt stored password failed: %v", err)
	}
	return plaintext == want
}

// TestUpdatePasswordEncryptedEnvelope covers a successful password change with
// correctly encrypted old+new envelopes: the new password must be stored (in
// the existing StringEncrypt format) and the stale session must be cleaned.
func TestUpdatePasswordEncryptedEnvelope(t *testing.T) {
	privateKey := setupPasswordFlowTest(t)
	u := &SettingService{}

	if err := global.SESSION.Set("stale-sid", psession.SessionUser{ID: 1, Name: "admin", LoggedIn: true}, 60); err != nil {
		t.Fatal(err)
	}
	c, _ := newAuthTestContext(t)

	oldEnc := buildPasswordEnvelope(t, &privateKey.PublicKey, storedOldPassword)
	newEnc := buildPasswordEnvelope(t, &privateKey.PublicKey, "new-password-456")
	if err := u.UpdatePassword(c, oldEnc, newEnc); err != nil {
		t.Fatalf("UpdatePassword with encrypted envelopes failed: %v", err)
	}

	if !storedPasswordEquals(t, "new-password-456") {
		t.Fatal("stored password does not match the decrypted new password")
	}
	if _, err := global.SESSION.Get("stale-sid"); err == nil {
		t.Fatal("session was not cleaned after password change")
	}

	// the new password must be accepted by the login flow (which consumes the
	// same encrypted envelope format)
	if err := checkPassword(buildPasswordEnvelope(t, &privateKey.PublicKey, "new-password-456")); err != nil {
		t.Fatalf("login checkPassword rejected the new password: %v", err)
	}
}

// TestUpdatePasswordWrongOldPassword ensures a wrong (but correctly
// encrypted) old password fails and leaves the stored password untouched.
func TestUpdatePasswordWrongOldPassword(t *testing.T) {
	privateKey := setupPasswordFlowTest(t)
	u := &SettingService{}

	c, _ := newAuthTestContext(t)
	oldEnc := buildPasswordEnvelope(t, &privateKey.PublicKey, "wrong-password")
	newEnc := buildPasswordEnvelope(t, &privateKey.PublicKey, "new-password-456")
	if err := u.UpdatePassword(c, oldEnc, newEnc); err != constant.ErrInitialPassword {
		t.Fatalf("UpdatePassword with wrong old password = %v, want %v", err, constant.ErrInitialPassword)
	}
	if !storedPasswordEquals(t, storedOldPassword) {
		t.Fatal("stored password was modified despite a failed update")
	}
}

// TestUpdatePasswordRejectsPlaintext ensures the fail-closed behavior:
// plaintext (non-envelope) passwords must be rejected, never silently accepted.
func TestUpdatePasswordRejectsPlaintext(t *testing.T) {
	setupPasswordFlowTest(t)
	u := &SettingService{}

	c, _ := newAuthTestContext(t)
	if err := u.UpdatePassword(c, storedOldPassword, "brand-new-password"); err == nil {
		t.Fatal("UpdatePassword accepted plaintext passwords, want error (fail closed)")
	}
	if !storedPasswordEquals(t, storedOldPassword) {
		t.Fatal("stored password was modified by a rejected plaintext update")
	}
}

// TestPasswordFlowsFailClosedWithoutRSAKey ensures that when the RSA private
// key setting is missing or unparseable, both password endpoints fail exactly
// like login does (raw parse error), instead of falling back to plaintext.
func TestPasswordFlowsFailClosedWithoutRSAKey(t *testing.T) {
	privateKey := setupPasswordFlowTest(t)
	u := &SettingService{}

	oldEnc := buildPasswordEnvelope(t, &privateKey.PublicKey, storedOldPassword)

	// simulate a missing/corrupted key after minting a valid envelope
	if err := settingRepo.Update("PASSWORD_PRIVATE_KEY", "not-a-valid-key"); err != nil {
		t.Fatalf("corrupt PASSWORD_PRIVATE_KEY failed: %v", err)
	}

	c, _ := newAuthTestContext(t)
	if err := u.UpdatePassword(c, oldEnc, oldEnc); err == nil {
		t.Fatal("UpdatePassword succeeded without a valid RSA private key, want error")
	}
	if err := u.HandlePasswordExpired(c, oldEnc, oldEnc); err == nil {
		t.Fatal("HandlePasswordExpired succeeded without a valid RSA private key, want error")
	}
	if !storedPasswordEquals(t, storedOldPassword) {
		t.Fatal("stored password was modified while the RSA key was unavailable")
	}
}

// TestHandlePasswordExpiredEncryptedEnvelope covers the expired-password flow:
// a valid encrypted envelope must rotate the password and refresh the
// expiration time, and the new password must then work for login.
func TestHandlePasswordExpiredEncryptedEnvelope(t *testing.T) {
	privateKey := setupPasswordFlowTest(t)
	u := &SettingService{}

	c, _ := newAuthTestContext(t)
	oldEnc := buildPasswordEnvelope(t, &privateKey.PublicKey, storedOldPassword)
	newEnc := buildPasswordEnvelope(t, &privateKey.PublicKey, "expired-new-password")
	if err := u.HandlePasswordExpired(c, oldEnc, newEnc); err != nil {
		t.Fatalf("HandlePasswordExpired with encrypted envelopes failed: %v", err)
	}

	if !storedPasswordEquals(t, "expired-new-password") {
		t.Fatal("stored password does not match the decrypted new password")
	}
	expTime, err := settingRepo.Get(settingRepo.WithByKey("ExpirationTime"))
	if err != nil {
		t.Fatalf("read ExpirationTime failed: %v", err)
	}
	if strings.HasPrefix(expTime.Value, "2000-01-01") {
		t.Fatalf("ExpirationTime was not refreshed, got %q", expTime.Value)
	}
	if err := checkPassword(buildPasswordEnvelope(t, &privateKey.PublicKey, "expired-new-password")); err != nil {
		t.Fatalf("login checkPassword rejected the new password: %v", err)
	}
}

// ---- proxy update flow (empty password means "keep" per the frontend form) ----

const storedProxyPassword = "proxy-passwd-old"

// setupProxyUpdateTest extends setupSettingUpdateTest with a stored proxy
// configuration (including an encrypted password) plus the EncryptKey storage
// key StringEncrypt/StringDecrypt rely on.
func setupProxyUpdateTest(t *testing.T) {
	t.Helper()
	setupSettingUpdateTest(t)

	// StringEncrypt/StringDecrypt cache the storage key in global config;
	// clear it so the value seeded below is used and restore it afterwards.
	prevKey := global.CONF.System.EncryptKey
	global.CONF.System.EncryptKey = ""
	t.Cleanup(func() { global.CONF.System.EncryptKey = prevKey })

	// UpdateProxy ends with RefreshProxy, whose loadAndApplyProxy logs.
	if global.LOG == nil {
		global.LOG = logrus.New()
	}

	if err := global.DB.Create(&model.Setting{Key: "EncryptKey", Value: testEncryptKey}).Error; err != nil {
		t.Fatalf("seed setting EncryptKey failed: %v", err)
	}
	storedPass, err := encrypt.StringEncrypt(storedProxyPassword)
	if err != nil {
		t.Fatalf("encrypt stored proxy password failed: %v", err)
	}
	seeds := []model.Setting{
		{Key: "ProxyType", Value: "http"},
		{Key: "ProxyUrl", Value: "10.0.0.1"},
		{Key: "ProxyPort", Value: "8888"},
		{Key: "ProxyUser", Value: "proxy-user"},
		{Key: "ProxyPasswd", Value: storedPass},
		{Key: "ProxyPasswdKeep", Value: "true"},
		{Key: "ProxyDockerSync", Value: "false"},
	}
	for i := range seeds {
		if err := global.DB.Create(&seeds[i]).Error; err != nil {
			t.Fatalf("seed setting %s failed: %v", seeds[i].Key, err)
		}
	}

	// UpdateProxy ends with RefreshProxy, which stores the proxy on the shared
	// outbound transport; reset it so later tests keep direct connectivity.
	t.Cleanup(func() { httpUtil.SetProxyURL(nil) })
}

// proxySettingValue reads a raw setting value from the DB.
func proxySettingValue(t *testing.T, key string) string {
	t.Helper()
	got, err := settingRepo.Get(settingRepo.WithByKey(key))
	if err != nil {
		t.Fatalf("read setting %s failed: %v", key, err)
	}
	return got.Value
}

// proxyStoredPasswdPlaintext decrypts the stored ProxyPasswd setting.
func proxyStoredPasswdPlaintext(t *testing.T) string {
	t.Helper()
	stored := proxySettingValue(t, "ProxyPasswd")
	if stored == "" {
		return ""
	}
	plaintext, err := encrypt.StringDecrypt(stored)
	if err != nil {
		t.Fatalf("decrypt stored proxy password failed: %v", err)
	}
	return plaintext
}

// TestUpdateProxyKeepPassword covers the form's "leave empty to keep the
// stored password" promise: an empty submitted password with
// ProxyPasswdKeep == "true" must not touch the stored encrypted password,
// while the other fields (url/port/user) are updated as submitted.
func TestUpdateProxyKeepPassword(t *testing.T) {
	setupProxyUpdateTest(t)
	u := &SettingService{}
	storedEncrypted := proxySettingValue(t, "ProxyPasswd")

	err := u.UpdateProxy(dto.ProxyUpdate{
		ProxyType:       "http",
		ProxyUrl:        "10.0.0.2",
		ProxyPort:       "9999",
		ProxyUser:       "proxy-user",
		ProxyPasswd:     "",
		ProxyPasswdKeep: "true",
	})
	if err != nil {
		t.Fatalf("UpdateProxy with empty password and keep=true failed: %v", err)
	}

	if got := proxySettingValue(t, "ProxyPasswd"); got != storedEncrypted {
		t.Errorf("stored ProxyPasswd changed to %q, want unchanged %q", got, storedEncrypted)
	}
	if got := proxyStoredPasswdPlaintext(t); got != storedProxyPassword {
		t.Errorf("decrypted stored ProxyPasswd = %q, want %q", got, storedProxyPassword)
	}
	if got := proxySettingValue(t, "ProxyUrl"); got != "10.0.0.2" {
		t.Errorf("ProxyUrl = %q, want 10.0.0.2", got)
	}
	if got := proxySettingValue(t, "ProxyPort"); got != "9999" {
		t.Errorf("ProxyPort = %q, want 9999", got)
	}
	if got := proxySettingValue(t, "ProxyUser"); got != "proxy-user" {
		t.Errorf("ProxyUser = %q, want proxy-user", got)
	}
	if got := proxySettingValue(t, "ProxyPasswdKeep"); got != "true" {
		t.Errorf("ProxyPasswdKeep = %q, want true", got)
	}
}

// TestUpdateProxyClearPassword ensures clearing stays possible: an empty
// password without the keep flag (the form sends keep=false when the user
// unchecks "remember password") must wipe the stored password.
func TestUpdateProxyClearPassword(t *testing.T) {
	setupProxyUpdateTest(t)
	u := &SettingService{}

	err := u.UpdateProxy(dto.ProxyUpdate{
		ProxyType:       "http",
		ProxyUrl:        "10.0.0.1",
		ProxyPort:       "8888",
		ProxyUser:       "proxy-user",
		ProxyPasswd:     "",
		ProxyPasswdKeep: "false",
	})
	if err != nil {
		t.Fatalf("UpdateProxy with empty password and keep=false failed: %v", err)
	}

	if got := proxySettingValue(t, "ProxyPasswd"); got != "" {
		t.Errorf("stored ProxyPasswd = %q, want empty", got)
	}
	if got := proxySettingValue(t, "ProxyPasswdKeep"); got != "false" {
		t.Errorf("ProxyPasswdKeep = %q, want false", got)
	}
}

// TestUpdateProxyReplacePassword ensures a non-empty password always replaces
// the stored encrypted value.
func TestUpdateProxyReplacePassword(t *testing.T) {
	setupProxyUpdateTest(t)
	u := &SettingService{}
	storedEncrypted := proxySettingValue(t, "ProxyPasswd")

	err := u.UpdateProxy(dto.ProxyUpdate{
		ProxyType:       "http",
		ProxyUrl:        "10.0.0.1",
		ProxyPort:       "8888",
		ProxyUser:       "proxy-user",
		ProxyPasswd:     "proxy-passwd-new",
		ProxyPasswdKeep: "true",
	})
	if err != nil {
		t.Fatalf("UpdateProxy with a new password failed: %v", err)
	}

	storedEncryptedNew := proxySettingValue(t, "ProxyPasswd")
	if storedEncryptedNew == storedEncrypted {
		t.Error("stored ProxyPasswd was not replaced by the new password")
	}
	if got := proxyStoredPasswdPlaintext(t); got != "proxy-passwd-new" {
		t.Errorf("decrypted stored ProxyPasswd = %q, want proxy-passwd-new", got)
	}
}

// TestUpdateProxyDisableClearsPassword guards the disable path: switching the
// proxy off (empty type) blanks ProxyPasswdKeep, so the stored password must
// still be wiped even though the submitted password is empty.
func TestUpdateProxyDisableClearsPassword(t *testing.T) {
	setupProxyUpdateTest(t)
	u := &SettingService{}

	err := u.UpdateProxy(dto.ProxyUpdate{
		ProxyType:       "",
		ProxyUrl:        "",
		ProxyPort:       "",
		ProxyUser:       "",
		ProxyPasswd:     "",
		ProxyPasswdKeep: "",
	})
	if err != nil {
		t.Fatalf("UpdateProxy with empty type failed: %v", err)
	}

	for _, key := range []string{"ProxyType", "ProxyUrl", "ProxyPort", "ProxyUser", "ProxyPasswd", "ProxyPasswdKeep"} {
		if got := proxySettingValue(t, key); got != "" {
			t.Errorf("setting %s = %q after disabling the proxy, want empty", key, got)
		}
	}
}
