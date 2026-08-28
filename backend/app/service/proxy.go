package service

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/1Panel-dev/1Panel/backend/app/dto"
	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/1Panel-dev/1Panel/backend/utils/encrypt"
	httpUtil "github.com/1Panel-dev/1Panel/backend/utils/http"
)

// proxyTestTarget 测试连接的固定目标：仅验证代理链路可用性，不接受外部传入地址。
const proxyTestTarget = "https://www.baidu.com"

var proxyLoadOnce sync.Once

// InitProxyConfig 服务启动时从 settings 表加载代理配置（幂等）。
func InitProxyConfig() {
	proxyLoadOnce.Do(func() {
		loadAndApplyProxy()
	})
}

// RefreshProxy 代理设置变更后重建全局出站代理。
func RefreshProxy() {
	loadAndApplyProxy()
}

func loadProxyMap() (map[string]string, error) {
	list, err := settingRepo.GetList()
	if err != nil {
		return nil, err
	}
	m := make(map[string]string)
	for _, item := range list {
		m[item.Key] = item.Value
	}
	return m, nil
}

func buildProxyURL(proxyType, addr, port, user, pass string) (*url.URL, error) {
	proxyType = strings.ToLower(strings.TrimSpace(proxyType))
	addr = strings.TrimSpace(addr)
	port = strings.TrimSpace(port)
	if proxyType == "" && addr == "" {
		return nil, nil
	}
	switch proxyType {
	case "http", "https", "socks5":
	default:
		return nil, fmt.Errorf("unsupported proxy type %q", proxyType)
	}
	if addr == "" {
		return nil, fmt.Errorf("proxy address is required")
	}
	u := &url.URL{Scheme: proxyType, Host: addr}
	if port != "" {
		u.Host = addr + ":" + port
	}
	if user != "" {
		u.User = url.UserPassword(user, pass)
	}
	return u, nil
}

func loadAndApplyProxy() {
	m, err := loadProxyMap()
	if err != nil {
		global.LOG.Warnf("load proxy settings failed, outbound falls back to env, err: %v", err)
		httpUtil.SetProxyURL(nil)
		return
	}
	pass := ""
	if m["ProxyPasswd"] != "" {
		if p, err := encrypt.StringDecrypt(m["ProxyPasswd"]); err == nil {
			pass = p
		} else {
			global.LOG.Warnf("decrypt stored proxy password failed: %v", err)
		}
	}
	u, err := buildProxyURL(m["ProxyType"], m["ProxyUrl"], m["ProxyPort"], m["ProxyUser"], pass)
	if err != nil {
		global.LOG.Warnf("invalid proxy config ignored (%v), outbound falls back to env", err)
		httpUtil.SetProxyURL(nil)
		return
	}
	httpUtil.SetProxyURL(u)
	if u != nil {
		global.LOG.Infof("outbound proxy enabled: %s://%s", u.Scheme, u.Host)
	}
}

// resolveProxyPassword 解析表单提交的代理密码，与保存路径的 keep 语义一致：
// 密码为空且 ProxyPasswdKeep == "true" 时，回退读取 settings 表已存（加密）
// 的 ProxyPasswd 并解密；解密失败不硬报错，仅记录日志（保持调用方既有行为）。
func resolveProxyPassword(req dto.ProxyUpdate) string {
	pass := req.ProxyPasswd
	if pass == "" && req.ProxyPasswdKeep == "true" {
		if stored, err := settingRepo.Get(settingRepo.WithByKey("ProxyPasswd")); err == nil && stored.Value != "" {
			if plain, derr := encrypt.StringDecrypt(stored.Value); derr == nil {
				pass = plain
			} else {
				global.LOG.Errorf("decrypt stored proxy password for test failed: %v", derr)
			}
		}
	}
	return pass
}

// maskProxyCredentials replaces any proxy userinfo ("user:pass@") embedded in
// an error message with "***@". *url.Error renders the request/proxy URL in
// some failure paths, and buildProxyURL injects the credentials via
// url.UserPassword while resolveProxyPassword may bring in the decrypted
// password stored in the settings table — so no error may be returned to the
// caller unmasked.
func maskProxyCredentials(err error, u *url.URL) error {
	if err == nil || u == nil || u.User == nil {
		return err
	}
	cred := u.User.String() + "@"
	if !strings.Contains(err.Error(), cred) {
		return err
	}
	return errors.New(strings.ReplaceAll(err.Error(), cred, "***@"))
}

// TestProxy 用表单当前值建立临时代理客户端访问固定目标，返回耗时描述。
func (s *SettingService) TestProxy(req dto.ProxyUpdate) (string, error) {
	req.ProxyPasswd = resolveProxyPassword(req)
	u, err := buildProxyURL(req.ProxyType, req.ProxyUrl, req.ProxyPort, req.ProxyUser, req.ProxyPasswd)
	if err != nil {
		return "", err
	}
	if u == nil {
		return "", fmt.Errorf("proxy is not enabled")
	}
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyURL(u)},
	}
	start := time.Now()
	resp, err := client.Head(proxyTestTarget)
	if err != nil {
		return "", maskProxyCredentials(err, u)
	}
	defer resp.Body.Close()
	return fmt.Sprintf("%s -> %d ms", proxyTestTarget, time.Since(start).Milliseconds()), nil
}
