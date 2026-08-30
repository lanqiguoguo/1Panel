package middleware

import (
	"strings"
	"testing"
)

func TestRenderOperationDetail(t *testing.T) {
	tests := []struct {
		name         string
		operationDic operationJson
		formatMap    map[string]interface{}
		wantZH       string
		wantEN       string
	}{
		{
			name: "asymmetric key only in ZH",
			operationDic: operationJson{
				FormatZH: "更新数据库 [database] 用户 [username] 权限",
				FormatEN: "Update privileges of database [database]",
			},
			formatMap: map[string]interface{}{
				"database": "mydb",
				"username": "alice",
			},
			wantZH: "更新数据库 [mydb] 用户 [alice] 权限",
			wantEN: "Update privileges of database [mydb]",
		},
		{
			name: "asymmetric key only in EN",
			operationDic: operationJson{
				FormatZH: "创建容器网络 name",
				FormatEN: "create container network [name]",
			},
			formatMap: map[string]interface{}{
				"name": "net1",
			},
			wantZH: "创建容器网络 name",
			wantEN: "create container network [net1]",
		},
		{
			name: "key appears twice in both languages",
			operationDic: operationJson{
				FormatZH: "服务器代理配置 [proxyUrl]:[proxyPort]",
				FormatEN: "set proxy [proxyUrl]:[proxyPort].",
			},
			formatMap: map[string]interface{}{
				"proxyUrl":  "http://127.0.0.1",
				"proxyPort": "10810",
			},
			wantZH: "服务器代理配置 [http://127.0.0.1]:[10810]",
			wantEN: "set proxy [http://127.0.0.1]:[10810].",
		},
		{
			name: "key missing from formatMap stays untouched",
			operationDic: operationJson{
				FormatZH: "修改系统配置 [key] => [value]",
				FormatEN: "update system setting [key] => [value]",
			},
			formatMap: map[string]interface{}{
				"value": "v1",
			},
			wantZH: "修改系统配置 [key] => [v1]",
			wantEN: "update system setting [key] => [v1]",
		},
		{
			name: "slice value joined with comma",
			operationDic: operationJson{
				FormatZH: "删除应用 [names]",
				FormatEN: "delete app [names]",
			},
			formatMap: map[string]interface{}{
				"names": []string{"a", "b"},
			},
			wantZH: "删除应用 [a,b]",
			wantEN: "delete app [a,b]",
		},
		{
			name: "symmetric normal case",
			operationDic: operationJson{
				FormatZH: "修改系统端口 => [serverPort]",
				FormatEN: "update system port => [serverPort]",
			},
			formatMap: map[string]interface{}{
				"serverPort": 9999,
			},
			wantZH: "修改系统端口 => [9999]",
			wantEN: "update system port => [9999]",
		},
		{
			name: "non-string slice elements render instead of panicking",
			operationDic: operationJson{
				FormatZH: "批量删除文件/文件夹 [paths]",
				FormatEN: "Batch delete dir or file [paths]",
			},
			formatMap: map[string]interface{}{
				// a malformed body unmarshals arrays of numbers as
				// []interface{}{float64,...}; the old .(string) assertion
				// panicked here and dropped the whole operation log
				"paths": []interface{}{float64(1), float64(2)},
			},
			wantZH: "批量删除文件/文件夹 [1,2]",
			wantEN: "Batch delete dir or file [1,2]",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotZH, gotEN := renderOperationDetail(tt.operationDic, tt.formatMap)
			if gotZH != tt.wantZH {
				t.Errorf("FormatZH = %q, want %q", gotZH, tt.wantZH)
			}
			if gotEN != tt.wantEN {
				t.Errorf("FormatEN = %q, want %q", gotEN, tt.wantEN)
			}
		})
	}
}

// TestMaskSensitiveLogValue is the regression test for the plaintext
// credential leak in operation logs: generic `bodyKeys:["key","value"]`
// requests must have their value redacted when the named key is sensitive.
func TestMaskSensitiveLogValue(t *testing.T) {
	cases := []struct {
		name     string
		bodyMap  map[string]interface{}
		bodyKeys []string
		want     string
	}{
		{name: "apikey masked", bodyMap: map[string]interface{}{"key": "ApiKey", "value": "secret-test-xyz"}, bodyKeys: []string{"key", "value"}, want: "******"},
		{name: "password masked", bodyMap: map[string]interface{}{"key": "Password", "value": "hunter2"}, bodyKeys: []string{"key", "value"}, want: "******"},
		{name: "lowercase secret masked", bodyMap: map[string]interface{}{"key": "secret", "value": "xyz"}, bodyKeys: []string{"key", "value"}, want: "******"},
		{name: "token masked", bodyMap: map[string]interface{}{"key": "ApiToken", "value": "tok"}, bodyKeys: []string{"key", "value"}, want: "******"},
		{name: "proxykey masked", bodyMap: map[string]interface{}{"key": "ProxyKey", "value": "p"}, bodyKeys: []string{"key", "value"}, want: "******"},
		{name: "non-sensitive kept", bodyMap: map[string]interface{}{"key": "port", "value": "22"}, bodyKeys: []string{"key", "value"}, want: "22"},
		{name: "bantime kept", bodyMap: map[string]interface{}{"key": "bantime", "value": "600"}, bodyKeys: []string{"key", "value"}, want: "600"},
		{name: "key not string noop", bodyMap: map[string]interface{}{"key": 1, "value": "v"}, bodyKeys: []string{"key", "value"}, want: "v"},
		{name: "value not in bodyKeys noop", bodyMap: map[string]interface{}{"key": "ApiKey", "value": "v"}, bodyKeys: []string{"key"}, want: ""},
		{name: "compound name masked", bodyMap: map[string]interface{}{"key": "DBPassword", "value": "v"}, bodyKeys: []string{"key", "value"}, want: "******"},
		{name: "accesskeysecret masked", bodyMap: map[string]interface{}{"key": "AccessKeySecret", "value": "v"}, bodyKeys: []string{"key", "value"}, want: "******"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			formatMap := make(map[string]interface{})
			for _, k := range tt.bodyKeys {
				if v, ok := tt.bodyMap[k]; ok {
					formatMap[k] = v
				}
			}
			maskSensitiveLogValue(formatMap, tt.bodyMap, tt.bodyKeys)
			got, exists := formatMap["value"]
			if tt.want == "" {
				if exists {
					t.Fatalf("formatMap[value] = %v, want absent", got)
				}
				return
			}
			if got != tt.want {
				t.Fatalf("formatMap[value] = %v, want %q", got, tt.want)
			}
		})
	}
}

// TestMaskSensitiveLogValueThroughRender ties the mask into the rendered log
// detail exactly as the middleware does.
func TestMaskSensitiveLogValueThroughRender(t *testing.T) {
	bodyMap := map[string]interface{}{"key": "ApiKey", "value": "secret-test-xyz"}
	formatMap := map[string]interface{}{"key": "ApiKey", "value": "secret-test-xyz"}
	bodyKeys := []string{"key", "value"}
	maskSensitiveLogValue(formatMap, bodyMap, bodyKeys)
	zh, en := renderOperationDetail(operationJson{
		FormatZH: "修改系统配置 [key] => [value]",
		FormatEN: "update system setting [key] => [value]",
	}, formatMap)
	for _, detail := range []string{zh, en} {
		if strings.Contains(detail, "secret-test-xyz") {
			t.Fatalf("rendered operation log leaks the credential: %s", detail)
		}
		if !strings.Contains(detail, "******") {
			t.Fatalf("rendered operation log has no mask placeholder: %s", detail)
		}
	}
}
