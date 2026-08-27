package common

import "testing"

func TestComparePanelVersion(t *testing.T) {
	tests := []struct {
		name     string
		version1 string
		version2 string
		want     bool
	}{
		{"equal with different segment count", "1.10", "1.10.0", false},
		{"equal with lts suffix variant", "v1.10.36-lts", "v1.10.36-lts.0", false},
		{"greater", "v1.10.37", "v1.10.36", true},
		{"less", "v1.10.36", "v1.10.37", false},
		{"equal", "v1.10.36", "v1.10.36", false},
		{"lts vs zero segment", "v1.10.36-lts", "v1.10.36", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ComparePanelVersion(tt.version1, tt.version2); got != tt.want {
				t.Errorf("ComparePanelVersion(%q, %q) = %v, want %v", tt.version1, tt.version2, got, tt.want)
			}
		})
	}
}

func TestCompareVersion(t *testing.T) {
	tests := []struct {
		name     string
		version1 string
		version2 string
		want     bool
	}{
		{"equal with different segment count", "1.10", "1.10.0", false},
		{"greater", "1.10.37", "1.10.36", true},
		{"less", "1.10.36", "1.10.37", false},
		{"equal", "1.10.36", "1.10.36", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CompareVersion(tt.version1, tt.version2); got != tt.want {
				t.Errorf("CompareVersion(%q, %q) = %v, want %v", tt.version1, tt.version2, got, tt.want)
			}
		})
	}
}
