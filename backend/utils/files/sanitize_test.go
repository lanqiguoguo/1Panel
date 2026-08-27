package files

import "testing"

func TestSanitizeFilename(t *testing.T) {
	valid := []string{
		"backup.tar.gz",
		"backup_2026-08-27.tar.gz",
		"file name with space.txt",
		"中文文件.txt",
	}
	for _, s := range valid {
		name, err := SanitizeFilename(s)
		if err != nil {
			t.Errorf("SanitizeFilename(%q) returned error: %v, want nil", s, err)
		}
		if name != s {
			t.Errorf("SanitizeFilename(%q) = %q, want %q", s, name, s)
		}
	}

	invalid := []string{
		"",
		".",
		"..",
		"../../../etc/cron.d/evil",
		"/etc/passwd",
		`..\..\evil`,
		"a/b",
		`a\b`,
		"dir/../evil",
		"/",
		".. /evil",
	}
	for _, s := range invalid {
		if _, err := SanitizeFilename(s); err == nil {
			t.Errorf("SanitizeFilename(%q) returned nil error, want error", s)
		}
	}
}
