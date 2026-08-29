package service

import (
	"strings"
	"testing"
)

// TestValidSupervisorName 验证 Supervisor 进程名校验规则与前端正则
// ^[a-zA-Z0-9]{1}[a-zA-Z0-9_-]{0,127}$ 完全一致，防止路径穿越与参数注入。
func TestValidSupervisorName(t *testing.T) {
	valid := []string{
		"myapp",
		"my-app",
		"my_app",
		"a1",
		"A",
		"a",
		"x-y_z",
	}
	invalid := []string{
		"",
		".",
		"..",
		"a/b",
		`a\b`,
		"../x",
		"a b",
		"-abc",
		"-x",
		"_x",
		"x$y",
		"x;y",
		strings.Repeat("a", 129),
	}

	for _, name := range valid {
		if !validSupervisorName(name) {
			t.Errorf("validSupervisorName(%q) = false, want true", name)
		}
	}
	// 长度上界的边界：128 个字符合法、129 个字符非法
	if !validSupervisorName(strings.Repeat("a", 128)) {
		t.Errorf("validSupervisorName(128x'a') = false, want true")
	}
	for _, name := range invalid {
		if validSupervisorName(name) {
			t.Errorf("validSupervisorName(%q) = true, want false", name)
		}
	}
}