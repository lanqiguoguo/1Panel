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

// TestValidSupervisorNumprocs 验证 numprocs 入口校验：必须是 1-999 内的整数。
// 该值会写入 ini 并被 getProcessName 展开为进程名列表，无上限的循环展开
// 可能耗尽内存，因此非数字、越界值一律拒绝。
func TestValidSupervisorNumprocs(t *testing.T) {
	valid := []string{
		"1",
		"2",
		"10",
		"999",
	}
	invalid := []string{
		"", // 空
		"0",
		"-1",
		"1000",   // 越界上界 +1
		"100000", // 越界
		"abc",    // Atoi 失败
		"1.5",
		" 1",
		"1 ",
		"1\n",
		"0x10",
	}
	for _, num := range valid {
		if !validSupervisorNumprocs(num) {
			t.Errorf("validSupervisorNumprocs(%q) = false, want true", num)
		}
	}
	for _, num := range invalid {
		if validSupervisorNumprocs(num) {
			t.Errorf("validSupervisorNumprocs(%q) = true, want false", num)
		}
	}
}

// TestGetProcessNameBounded 验证 getProcessName 的兜底防护：即使 numprocs
// 来自历史遗留或手工编辑过的 ini 文件，越界/非法值也不会触发无上限的切片
// 展开；合法边界值的行为保持不变。
func TestGetProcessNameBounded(t *testing.T) {
	if got := getProcessName("app", "1"); len(got) != 1 || got[0] != "app:app_00" {
		t.Errorf("getProcessName(app, 1) = %v, want [app:app_00]", got)
	}
	if got := getProcessName("app", "3"); len(got) != 3 || got[0] != "app:app_00" || got[2] != "app:app_02" {
		t.Errorf("getProcessName(app, 3) = %v, want 3 entries", got)
	}
	if got := getProcessName("app", "999"); len(got) != 999 || got[998] != "app:app_998" {
		t.Errorf("getProcessName(app, 999) = %d entries, want 999 entries", len(got))
	}
	for _, numprocs := range []string{"0", "-1", "1000", "1000000", "abc", ""} {
		if got := getProcessName("app", numprocs); len(got) != 0 {
			t.Errorf("getProcessName(app, %q) = %d entries, want 0", numprocs, len(got))
		}
	}
}
