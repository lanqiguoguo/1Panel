package middleware

import "testing"

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
