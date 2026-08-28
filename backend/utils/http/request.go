package http

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"

	"github.com/1Panel-dev/1Panel/backend/global"
)

// configuredProxy 为面板设置里配置的出站代理；nil 表示未启用，
// 此时回落到标准代理环境变量（HTTP_PROXY/HTTPS_PROXY/NO_PROXY）。
var configuredProxy atomic.Pointer[url.URL]

// SetProxyURL 由设置服务在启动加载与保存代理配置时调用。
func SetProxyURL(u *url.URL) {
	configuredProxy.Store(u)
}

// NewTransport 返回统一的出站 Transport：
// 代理优先级为面板设置 > 环境变量，环回地址始终直连，启用证书校验。
func NewTransport() *http.Transport {
	return NewTransportWith(10*time.Second, 5*time.Second)
}

// NewTransportWith returns the unified outbound transport with configurable
// timeouts; proxy priority is panel settings > environment variables,
// loopback addresses are always direct, and TLS verification is enabled.
func NewTransportWith(responseHeaderTimeout, tlsHandshakeTimeout time.Duration) *http.Transport {
	return &http.Transport{
		Proxy: func(req *http.Request) (*url.URL, error) {
			if host := req.URL.Hostname(); host == "localhost" || host == "127.0.0.1" || host == "::1" {
				return nil, nil
			}
			if u := configuredProxy.Load(); u != nil {
				return u, nil
			}
			return http.ProxyFromEnvironment(req)
		},
		DialContext: (&net.Dialer{
			Timeout:   60 * time.Second,
			KeepAlive: 60 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout:   tlsHandshakeTimeout,
		ResponseHeaderTimeout: responseHeaderTimeout,
		IdleConnTimeout:       15 * time.Second,
	}
}

// ValidatePublicURL 校验目标 URL 可被服务端安全请求：
// 仅允许 http/https，且 host 解析结果不得为环回/私有/链路本地/保留地址，防 SSRF。
func ValidatePublicURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("only http/https schemes are allowed")
	}
	host := u.Hostname()
	if host == "" {
		return errors.New("empty host in url")
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return err
	}
	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
			ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
			return errors.New("request to internal or reserved address is forbidden")
		}
	}
	return nil
}

func HandleGet(url, method string, timeout int) (int, []byte, error) {
	return HandleGetWithTransport(url, method, NewTransport(), timeout)
}

func HandleGetWithTransport(url, method string, transport *http.Transport, timeout int) (int, []byte, error) {
	defer func() {
		if r := recover(); r != nil {
			global.LOG.Errorf("handle request failed, error message: %v", r)
			return
		}
	}()

	client := http.Client{Timeout: time.Duration(timeout) * time.Second, Transport: transport}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return 0, nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(request)
	if err != nil {
		return 0, nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return 0, nil, errors.New(resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()

	return resp.StatusCode, body, nil
}
