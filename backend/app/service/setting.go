package service

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/1Panel-dev/1Panel/backend/app/dto/request"

	"github.com/1Panel-dev/1Panel/backend/app/dto"
	"github.com/1Panel-dev/1Panel/backend/buserr"
	"github.com/1Panel-dev/1Panel/backend/constant"
	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/1Panel-dev/1Panel/backend/utils/common"
	"github.com/1Panel-dev/1Panel/backend/utils/encrypt"
	"github.com/1Panel-dev/1Panel/backend/utils/files"
	"github.com/1Panel-dev/1Panel/backend/utils/systemctl"
	"github.com/gin-gonic/gin"
)

type SettingService struct{}

type ISettingService interface {
	GetSettingInfo() (*dto.SettingInfo, error)
	LoadInterfaceAddr() ([]string, error)
	Update(key, value string) error
	UpdateProxy(req dto.ProxyUpdate) error
	TestProxy(req dto.ProxyUpdate) (string, error)
	UpdatePassword(c *gin.Context, old, new string) error
	UpdatePort(port uint) error
	UpdateBindInfo(req dto.BindInfo) error
	UpdateSSL(c *gin.Context, req dto.SSLUpdate) error
	LoadFromCert() (*dto.SSLInfo, error)
	HandlePasswordExpired(c *gin.Context, old, new string) error
	GenerateApiKey() (string, error)
	GetApiConfig() (*dto.ApiInterfaceConfig, error)
	UpdateApiConfig(req dto.ApiInterfaceConfig) error
	UpdateMFA(interval, secret string) error
	GenerateRSAKey() error
}

func NewISettingService() ISettingService {
	return &SettingService{}
}

func (u *SettingService) GetSettingInfo() (*dto.SettingInfo, error) {
	setting, err := settingRepo.GetList()
	if err != nil {
		return nil, constant.ErrRecordNotFound
	}
	settingMap := make(map[string]string)
	for _, set := range setting {
		settingMap[set.Key] = set.Value
	}
	var info dto.SettingInfo
	arr, err := json.Marshal(settingMap)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(arr, &info); err != nil {
		return nil, err
	}
	sanitizeSettingInfo(&info)

	info.LocalTime = time.Now().Format("2006-01-02 15:04:05 MST -0700")
	return &info, err
}

// sanitizeSettingInfo clears sensitive fields that must not be echoed back to
// the frontend through the generic settings query API. ApiKey (the interface
// signing key) is masked to its last four characters: the value leaves the
// server only through the dedicated /settings/api/config endpoint, which is
// reachable exclusively with a valid login session (JwtAuth + SessionAuth +
// PasswordExpired, and the API-key headers are refused there).
func sanitizeSettingInfo(info *dto.SettingInfo) {
	info.MFASecret = ""
	info.ProxyPasswd = ""
	info.ApiKey = maskApiKey(info.ApiKey)
}

// maskApiKey masks an API interface key so only the last four characters are
// visible ("****abcd"), preserving the empty value. A key shorter than or
// equal to four characters is replaced entirely ("****"), so the raw key is
// never recoverable from the masked form.
func maskApiKey(apiKey string) string {
	if apiKey == "" {
		return ""
	}
	if len(apiKey) <= 4 {
		return "****"
	}
	return "****" + apiKey[len(apiKey)-4:]
}

// settingUpdateWhitelist contains the setting keys that may be written through
// the generic /settings/update interface. Keys used by the panel frontend's
// settings pages are allowed; keys that hold credentials or security policies
// with dedicated endpoints must NOT be added here, otherwise an authenticated
// session could bypass those endpoints and tamper with login credentials
// (UserName/Password), MFA (MFAStatus/MFASecret), API access (ApiKey/
// IpWhiteList/ApiInterfaceStatus) and other sensitive settings at will.
var settingUpdateWhitelist = map[string]struct{}{
	"MonitorStatus":          {},
	"MonitorInterval":        {},
	"MonitorStoreDays":       {},
	"SessionTimeout":         {},
	"ExpirationDays":         {},
	"PanelName":              {},
	"SystemIP":               {},
	"Theme":                  {},
	"MenuTabs":               {},
	"Language":               {},
	"DeveloperMode":          {},
	"DefaultNetwork":         {},
	"BindDomain":             {},
	"AllowIPs":               {},
	"SecurityEntrance":       {},
	"NoAuthSetting":          {},
	"ComplexityVerification": {},
	"MFAStatus":              {},
	"FileRecycleBin":         {},
	"SnapshotIgnore":         {},
	"DockerSockPath":         {},
	"AppStoreLastModified":   {},
	"AppStoreSyncStatus":     {},
	"UserName":               {},
}

func (u *SettingService) Update(key, value string) error {
	if _, ok := settingUpdateWhitelist[key]; !ok {
		return fmt.Errorf("setting key %s is not allowed", key)
	}
	switch key {
	// The global.MonitorCronID checks below are fast-path filters only: they
	// are allowed to go stale because startMonitor/stopMonitor serialize all
	// actual mutations of monitorCancel and global.MonitorCronID under
	// monitorMu. startMonitor re-checks under the lock (via stopMonitorLocked)
	// before publishing a new entry id, so a concurrent double-start can never
	// leave two cron jobs or a dangling cancel; stopMonitor is idempotent, so
	// a concurrent disable can never Remove(0) or call a nil cancel.
	case "MonitorStatus":
		if value == "enable" && global.MonitorCronID == 0 {
			interval, err := settingRepo.Get(settingRepo.WithByKey("MonitorInterval"))
			if err != nil {
				return err
			}
			if err := StartMonitor(false, interval.Value); err != nil {
				return err
			}
		}
		if value == "disable" && global.MonitorCronID != 0 {
			stopMonitor()
		}
	case "MonitorInterval":
		status, err := settingRepo.Get(settingRepo.WithByKey("MonitorStatus"))
		if err != nil {
			return err
		}
		if status.Value == "enable" && global.MonitorCronID != 0 {
			if err := StartMonitor(true, value); err != nil {
				return err
			}
		}
	case "MFAStatus":
		// Enabling MFA requires a validated TOTP code and a secret, and is only
		// possible through /settings/mfa/bind (UpdateMFA). The generic update
		// interface may only turn MFA off, matching the frontend behavior.
		if value != "disable" {
			return fmt.Errorf("setting key %s is not allowed", key)
		}
	case "AppStoreLastModified":
		exist, _ := settingRepo.Get(settingRepo.WithByKey("AppStoreLastModified"))
		if exist.ID == 0 {
			_ = settingRepo.Create("AppStoreLastModified", value)
			return nil
		}
	}

	if err := settingRepo.Update(key, value); err != nil {
		return err
	}

	switch key {
	case "ExpirationDays":
		timeout, err := strconv.Atoi(value)
		if err != nil {
			return err
		}
		if err := settingRepo.Update("ExpirationTime", time.Now().AddDate(0, 0, timeout).Format(constant.DateTimeLayout)); err != nil {
			return err
		}
	case "BindDomain":
		if len(value) != 0 {
			_ = global.SESSION.Clean()
		}
	case "UserName", "Password":
		_ = global.SESSION.Clean()

	}

	return nil
}

func (u *SettingService) LoadInterfaceAddr() ([]string, error) {
	addrMap := make(map[string]struct{})
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if ok && ipNet.IP.To16() != nil {
			addrMap[ipNet.IP.String()] = struct{}{}
		}
	}
	var data []string
	for key := range addrMap {
		data = append(data, key)
	}
	return data, nil
}

func (u *SettingService) UpdateBindInfo(req dto.BindInfo) error {
	if err := settingRepo.Update("Ipv6", req.Ipv6); err != nil {
		return err
	}
	if err := settingRepo.Update("BindAddress", req.BindAddress); err != nil {
		return err
	}
	go func() {
		time.Sleep(1 * time.Second)
		err := systemctl.Restart("1panel")
		if err != nil {
			global.LOG.Errorf("restart system with new bind info failed, err: %v", err)
		}
	}()
	return nil
}

func (u *SettingService) UpdateProxy(req dto.ProxyUpdate) error {
	req.ProxyType = strings.ToLower(strings.TrimSpace(req.ProxyType))
	if req.ProxyDockerSync != "true" {
		// normalize to the "true"/"false" string convention used by the setting
		req.ProxyDockerSync = "false"
	}
	switch req.ProxyType {
	case "":
		// 不启用：清空全部代理配置，恢复直连（出站回落环境变量）
		req.ProxyUrl, req.ProxyPort, req.ProxyUser, req.ProxyPasswd, req.ProxyPasswdKeep = "", "", "", "", ""
	case "http", "https", "socks5":
	default:
		return fmt.Errorf("unsupported proxy type %s", req.ProxyType)
	}
	req.ProxyUrl = strings.TrimSpace(req.ProxyUrl)
	req.ProxyPort = strings.TrimSpace(req.ProxyPort)
	if req.ProxyType != "" {
		if req.ProxyUrl == "" {
			return fmt.Errorf("proxy address is required")
		}
		if req.ProxyPort != "" {
			port, err := strconv.Atoi(req.ProxyPort)
			if err != nil || port < 1 || port > 65535 {
				return fmt.Errorf("invalid proxy port %s", req.ProxyPort)
			}
		}
	}

	// snapshot the previous sync flag before it is overwritten below, so the
	// docker sync knows whether "sync off" means "clean up a previous sync"
	prevSync := "false"
	if item, err := settingRepo.Get(settingRepo.WithByKey("ProxyDockerSync")); err == nil {
		prevSync = item.Value
	}
	if err := settingRepo.Update("ProxyUrl", req.ProxyUrl); err != nil {
		return err
	}
	if err := settingRepo.Update("ProxyType", req.ProxyType); err != nil {
		return err
	}
	if err := settingRepo.Update("ProxyPort", req.ProxyPort); err != nil {
		return err
	}
	if err := settingRepo.Update("ProxyUser", req.ProxyUser); err != nil {
		return err
	}
	// The proxy form sends an empty password with ProxyPasswdKeep == "true" to
	// mean "keep the stored password" (see the frontend buildReq in
	// setting/panel/proxy/index.vue). Skip the write in that case so the stored
	// encrypted password survives; an empty password without the keep flag
	// still clears it, and a non-empty password always replaces it.
	if req.ProxyPasswd != "" || req.ProxyPasswdKeep != "true" {
		pass, _ := encrypt.StringEncrypt(req.ProxyPasswd)
		if err := settingRepo.Update("ProxyPasswd", pass); err != nil {
			return err
		}
	}
	if err := settingRepo.Update("ProxyPasswdKeep", req.ProxyPasswdKeep); err != nil {
		return err
	}
	if err := settingRepo.Update("ProxyDockerSync", req.ProxyDockerSync); err != nil {
		return err
	}
	RefreshProxy()

	// Mirror the (already persisted) proxy into the Docker daemon config. The
	// proxy settings stay saved even when the daemon sync fails, so the error
	// only reports the sync outcome to the UI.
	if err := syncDockerDaemonProxy(prevSync, req); err != nil {
		global.LOG.Errorf("sync panel proxy to docker daemon failed: %v", err)
		return fmt.Errorf("panel proxy saved, but docker daemon sync failed: %w", err)
	}
	return nil
}

func (u *SettingService) UpdatePort(port uint) error {
	if common.ScanPort(int(port)) {
		return buserr.WithDetail(constant.ErrPortInUsed, port, nil)
	}
	serverPort, err := settingRepo.Get(settingRepo.WithByKey("ServerPort"))
	if err != nil {
		return err
	}
	portValue, _ := strconv.Atoi(serverPort.Value)
	if err := OperateFirewallPort([]int{portValue}, []int{int(port)}); err != nil {
		global.LOG.Errorf("set system firewall ports failed, err: %v", err)
	}
	if err := settingRepo.Update("ServerPort", strconv.Itoa(int(port))); err != nil {
		return err
	}
	go func() {
		time.Sleep(1 * time.Second)
		err := systemctl.Restart("1panel")
		if err != nil {
			global.LOG.Errorf("restart system port failed, err: %v", err)
		}
	}()
	return nil
}

func (u *SettingService) UpdateSSL(c *gin.Context, req dto.SSLUpdate) error {
	secretDir := path.Join(global.CONF.System.BaseDir, "1panel/secret")
	if req.SSL == "disable" {
		if err := settingRepo.Update("SSL", "disable"); err != nil {
			return err
		}
		if err := settingRepo.Update("SSLType", "self"); err != nil {
			return err
		}
		_ = os.Remove(path.Join(secretDir, "server.crt"))
		_ = os.Remove(path.Join(secretDir, "server.key"))
		sID, _ := c.Cookie(constant.SessionName)
		c.SetSameSite(http.SameSiteLaxMode)
		c.SetCookie(constant.SessionName, sID, 0, "", "", false, true)

		go func() {
			err := systemctl.Restart("1panel")
			if err != nil {
				global.LOG.Errorf("restart system failed, err: %v", err)
			}
		}()
		return nil
	}
	if _, err := os.Stat(secretDir); err != nil && os.IsNotExist(err) {
		if err = os.MkdirAll(secretDir, os.ModePerm); err != nil {
			return err
		}
	}
	if err := settingRepo.Update("SSLType", req.SSLType); err != nil {
		return err
	}
	var (
		secret string
		key    string
	)

	switch req.SSLType {
	case "self":
		if len(req.Domain) == 0 {
			return fmt.Errorf("load domain failed")
		}
		defaultCA, err := websiteCARepo.GetFirst(commonRepo.WithByName("1Panel"))
		if err != nil {
			return err
		}
		websiteSSL, err := NewIWebsiteCAService().ObtainSSL(request.WebsiteCAObtain{
			ID:        defaultCA.ID,
			KeyType:   "P256",
			Domains:   req.Domain,
			Time:      1,
			Unit:      "year",
			AutoRenew: true,
		})
		if err != nil {
			return err
		}
		secret = websiteSSL.Pem
		key = websiteSSL.PrivateKey
		if err := settingRepo.Update("SSLID", strconv.Itoa(int(websiteSSL.ID))); err != nil {
			return err
		}
	case "select":
		websiteSSL, err := websiteSSLRepo.GetFirst(commonRepo.WithByID(req.SSLID))
		if err != nil {
			return err
		}
		secret = websiteSSL.Pem
		key = websiteSSL.PrivateKey
		if err := settingRepo.Update("SSLID", strconv.Itoa(int(req.SSLID))); err != nil {
			return err
		}
	case "import-paste":
		secret = req.Cert
		key = req.Key
	case "import-local":
		keyFile, err := os.ReadFile(req.Key)
		if err != nil {
			return err
		}
		key = string(keyFile)
		certFile, err := os.ReadFile(req.Cert)
		if err != nil {
			return err
		}
		secret = string(certFile)
	}

	fileOp := files.NewFileOp()
	if err := fileOp.WriteFile(path.Join(secretDir, "server.crt.tmp"), strings.NewReader(secret), 0600); err != nil {
		return err
	}
	if err := fileOp.WriteFile(path.Join(secretDir, "server.key.tmp"), strings.NewReader(key), 0600); err != nil {
		return err
	}
	if err := checkCertValid(); err != nil {
		return err
	}
	if err := fileOp.Rename(path.Join(secretDir, "server.crt.tmp"), path.Join(secretDir, "server.crt")); err != nil {
		return err
	}
	if err := fileOp.Rename(path.Join(secretDir, "server.key.tmp"), path.Join(secretDir, "server.key")); err != nil {
		return err
	}
	if err := settingRepo.Update("SSL", req.SSL); err != nil {
		return err
	}
	if err := settingRepo.Update("AutoRestart", req.AutoRestart); err != nil {
		return err
	}

	sID, _ := c.Cookie(constant.SessionName)
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(constant.SessionName, sID, 0, "", "", true, true)
	go func() {
		time.Sleep(1 * time.Second)
		err := systemctl.Restart("1panel")
		if err != nil {
			global.LOG.Errorf("restart system failed, err: %v", err)
		}
	}()
	return nil
}

func (u *SettingService) LoadFromCert() (*dto.SSLInfo, error) {
	ssl, err := settingRepo.Get(settingRepo.WithByKey("SSL"))
	if err != nil {
		return nil, err
	}
	if ssl.Value == "disable" {
		return &dto.SSLInfo{}, nil
	}
	sslType, err := settingRepo.Get(settingRepo.WithByKey("SSLType"))
	if err != nil {
		return nil, err
	}
	var data dto.SSLInfo
	switch sslType.Value {
	case "self":
		data, err = loadInfoFromCert()
		if err != nil {
			return nil, err
		}
	case "import-paste", "import-local":
		data, err = loadInfoFromCert()
		if err != nil {
			return nil, err
		}
		if _, err := os.Stat(path.Join(global.CONF.System.BaseDir, "1panel/secret/server.crt")); err != nil {
			return nil, fmt.Errorf("load server.crt file failed, err: %v", err)
		}
		certFile, _ := os.ReadFile(path.Join(global.CONF.System.BaseDir, "1panel/secret/server.crt"))
		data.Cert = string(certFile)

		if _, err := os.Stat(path.Join(global.CONF.System.BaseDir, "1panel/secret/server.key")); err != nil {
			return nil, fmt.Errorf("load server.key file failed, err: %v", err)
		}
		keyFile, _ := os.ReadFile(path.Join(global.CONF.System.BaseDir, "1panel/secret/server.key"))
		data.Key = string(keyFile)
	case "select":
		sslID, err := settingRepo.Get(settingRepo.WithByKey("SSLID"))
		if err != nil {
			return nil, err
		}
		id, _ := strconv.Atoi(sslID.Value)
		ssl, err := websiteSSLRepo.GetFirst(commonRepo.WithByID(uint(id)))
		if err != nil {
			return nil, err
		}
		data.Domain = ssl.PrimaryDomain
		data.SSLID = uint(id)
		data.Timeout = ssl.ExpireDate.Format(constant.DateTimeLayout)
	}
	return &data, nil
}

// decryptEnvelope decrypts an RSA/AES password envelope produced by the
// frontend encryptPassword() helper (format: "RSA(aesKey):iv:aesCiphertext"),
// mirroring the login flow in auth.go checkPassword: it loads the RSA private
// key from the PASSWORD_PRIVATE_KEY setting and fails closed when the key is
// missing or unparseable (the raw parse/decrypt error is returned, the same
// error login returns), so plaintext passwords are never accepted.
func decryptEnvelope(envelope string) (string, error) {
	priKey, _ := settingRepo.Get(settingRepo.WithByKey("PASSWORD_PRIVATE_KEY"))

	privateKey, err := encrypt.ParseRSAPrivateKey(priKey.Value)
	if err != nil {
		return "", err
	}
	return encrypt.DecryptPassword(envelope, privateKey)
}

func (u *SettingService) HandlePasswordExpired(c *gin.Context, old, new string) error {
	// old and new arrive as encrypted envelopes; decrypt both before any
	// comparison or storage, so complexity rules (checked client-side on the
	// plaintext) and the stored value keep operating on plaintext.
	oldPassword, err := decryptEnvelope(old)
	if err != nil {
		return err
	}
	newPassword, err := decryptEnvelope(new)
	if err != nil {
		return err
	}
	setting, err := settingRepo.Get(settingRepo.WithByKey("Password"))
	if err != nil {
		return err
	}
	passwordFromDB, err := encrypt.StringDecrypt(setting.Value)
	if err != nil {
		return err
	}
	// constant-time comparison, matching the login flow
	if hmac.Equal([]byte(passwordFromDB), []byte(oldPassword)) {
		encryptedNew, err := encrypt.StringEncrypt(newPassword)
		if err != nil {
			return err
		}
		if err := settingRepo.Update("Password", encryptedNew); err != nil {
			return err
		}

		expiredSetting, err := settingRepo.Get(settingRepo.WithByKey("ExpirationDays"))
		if err != nil {
			return err
		}
		timeout, _ := strconv.Atoi(expiredSetting.Value)
		if err := settingRepo.Update("ExpirationTime", time.Now().AddDate(0, 0, timeout).Format(constant.DateTimeLayout)); err != nil {
			return err
		}
		return nil
	}
	return constant.ErrInitialPassword
}

func (u *SettingService) UpdatePassword(c *gin.Context, old, new string) error {
	if err := u.HandlePasswordExpired(c, old, new); err != nil {
		return err
	}
	_ = global.SESSION.Clean()
	return nil
}

func loadInfoFromCert() (dto.SSLInfo, error) {
	var info dto.SSLInfo
	certFile := path.Join(global.CONF.System.BaseDir, "1panel/secret/server.crt")
	if _, err := os.Stat(certFile); err != nil {
		return info, err
	}
	certData, err := os.ReadFile(certFile)
	if err != nil {
		return info, err
	}
	certBlock, _ := pem.Decode(certData)
	if certBlock == nil {
		return info, err
	}
	certObj, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return info, err
	}
	var domains []string
	if len(certObj.IPAddresses) != 0 {
		for _, ip := range certObj.IPAddresses {
			domains = append(domains, ip.String())
		}
	}
	if len(certObj.DNSNames) != 0 {
		domains = append(domains, certObj.DNSNames...)
	}
	return dto.SSLInfo{
		Domain:   strings.Join(domains, ","),
		Timeout:  certObj.NotAfter.Format(constant.DateTimeLayout),
		RootPath: path.Join(global.CONF.System.BaseDir, "1panel/secret/server.crt"),
	}, nil
}

func checkCertValid() error {
	certificate, err := os.ReadFile(path.Join(global.CONF.System.BaseDir, "1panel/secret/server.crt.tmp"))
	if err != nil {
		return err
	}
	key, err := os.ReadFile(path.Join(global.CONF.System.BaseDir, "1panel/secret/server.key.tmp"))
	if err != nil {
		return err
	}
	if _, err = tls.X509KeyPair(certificate, key); err != nil {
		return err
	}
	certBlock, _ := pem.Decode(certificate)
	if certBlock == nil {
		return err
	}
	if _, err := x509.ParseCertificate(certBlock.Bytes); err != nil {
		return err
	}

	return nil
}

func (u *SettingService) GenerateApiKey() (string, error) {
	apiKey := common.RandStr(32)
	if err := settingRepo.Update("ApiKey", apiKey); err != nil {
		return global.CONF.System.ApiKey, err
	}
	global.CONF.System.ApiKey = apiKey
	return apiKey, nil
}

func (u *SettingService) GetApiConfig() (*dto.ApiInterfaceConfig, error) {
	values := make(map[string]string)
	for _, key := range []string{"ApiInterfaceStatus", "ApiKey", "IpWhiteList", "ApiKeyValidityTime"} {
		setting, err := settingRepo.Get(settingRepo.WithByKey(key))
		if err != nil {
			return nil, err
		}
		values[key] = setting.Value
	}
	return &dto.ApiInterfaceConfig{
		ApiInterfaceStatus: values["ApiInterfaceStatus"],
		ApiKey:             values["ApiKey"],
		IpWhiteList:        values["IpWhiteList"],
		ApiKeyValidityTime: values["ApiKeyValidityTime"],
	}, nil
}

func (u *SettingService) UpdateApiConfig(req dto.ApiInterfaceConfig) error {
	if err := settingRepo.Update("ApiInterfaceStatus", req.ApiInterfaceStatus); err != nil {
		return err
	}
	global.CONF.System.ApiInterfaceStatus = req.ApiInterfaceStatus
	// The apiKey field is masked (****xxxx) in /settings/search so the generic
	// settings query never leaks the signing key; the frontend API config page
	// loads the plaintext from the dedicated /settings/api/config endpoint and
	// keeps it in memory. When a submit carries the masked form (e.g. the
	// enable/disable switch which echoes back the value it loaded), treat it as
	// "keep the stored key" instead of persisting the mask over the real key.
	// An exact mask match is rejected too, so a masked value can never be
	// persisted as the actual key.
	stored, err := settingRepo.Get(settingRepo.WithByKey("ApiKey"))
	if err == nil && stored.Value != "" {
		if req.ApiKey == maskApiKey(stored.Value) || strings.HasPrefix(req.ApiKey, "****") {
			req.ApiKey = stored.Value
		}
	}
	if err := settingRepo.Update("ApiKey", req.ApiKey); err != nil {
		return err
	}
	global.CONF.System.ApiKey = req.ApiKey
	if err := settingRepo.Update("IpWhiteList", req.IpWhiteList); err != nil {
		return err
	}
	global.CONF.System.IpWhiteList = req.IpWhiteList
	if err := settingRepo.Update("ApiKeyValidityTime", req.ApiKeyValidityTime); err != nil {
		return err
	}
	global.CONF.System.ApiKeyValidityTime = req.ApiKeyValidityTime
	return nil
}

// UpdateMFA persists the MFA binding (status, interval and secret). It is only
// reachable from /settings/mfa/bind, which validates the TOTP code before
// calling, so MFAStatus/MFAInterval/MFASecret are deliberately not part of the
// generic setting update whitelist.
func (u *SettingService) UpdateMFA(interval, secret string) error {
	if err := settingRepo.Update("MFAInterval", interval); err != nil {
		return err
	}
	if err := settingRepo.Update("MFAStatus", "enable"); err != nil {
		return err
	}
	return settingRepo.Update("MFASecret", secret)
}

func exportPrivateKeyToPEM(privateKey *rsa.PrivateKey) string {
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})
	return string(privateKeyPEM)
}

func exportPublicKeyToPEM(publicKey *rsa.PublicKey) (string, error) {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", err
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})
	return string(publicKeyPEM), nil
}

func (u *SettingService) GenerateRSAKey() error {
	priKey, _ := settingRepo.Get(settingRepo.WithByKey("PASSWORD_PRIVATE_KEY"))
	pubKey, _ := settingRepo.Get(settingRepo.WithByKey("PASSWORD_PUBLIC_KEY"))
	if priKey.Value != "" && pubKey.Value != "" {
		return nil
	}
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	privateKeyPEM := exportPrivateKeyToPEM(privateKey)
	publicKeyPEM, _ := exportPublicKeyToPEM(&privateKey.PublicKey)
	err = settingRepo.UpdateOrCreate("PASSWORD_PRIVATE_KEY", privateKeyPEM)
	if err != nil {
		return err
	}
	err = settingRepo.UpdateOrCreate("PASSWORD_PUBLIC_KEY", publicKeyPEM)
	if err != nil {
		return err
	}
	return nil
}
