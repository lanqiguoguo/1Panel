package service

import (
	"testing"

	"github.com/1Panel-dev/1Panel/backend/app/model"
)

// TestParseOllamaModelList verifies the whitelist applied to `ollama list`
// output before any model row is persisted by Sync: header lines and rows
// whose NAME fails validOllamaModelName are dropped, well-formed rows are
// kept with their size columns, and the two existing DB-sync behaviours
// (size update / drop list) operate on whitelisted names only.
func TestParseOllamaModelList(t *testing.T) {
	ensureValidateLogger(t)
	out := `NAME              ID              SIZE      MODIFIED
llama3:8b          1234            4.9 GB    2 minutes ago
qwen/qwen2.5:7b    abcd            4.7 GB    3 minutes ago
$(id)              dead            evil  --  1 minute ago
mischief;rm       ffff            1.0 GB    1 minute ago
llama3:70b-instruct-q4_K_M  1e2f   41 GB      5 seconds ago
`
	list := parseOllamaModelList(out)
	want := []model.OllamaModel{
		{Name: "llama3:8b", Size: "4.9 GB"},
		{Name: "qwen/qwen2.5:7b", Size: "4.7 GB"},
		{Name: "llama3:70b-instruct-q4_K_M", Size: "41 GB"},
	}
	if len(list) != len(want) {
		t.Fatalf("parseOllamaModelList returned %d rows, want %d: %+v", len(list), len(want), list)
	}
	for i := range want {
		if list[i].Name != want[i].Name || list[i].Size != want[i].Size {
			t.Errorf("row %d = %+v, want %+v", i, list[i], want[i])
		}
	}
}

// TestLoadModelSizeColumnMatch verifies that loadModelSize matches the model
// by its NAME column. Under the old `ollama list | grep <name>` pipeline a
// model named "a" matched the row of a prefix model "a:8b" (whichever row
// the grep hit first); the argv rework must return the exact NAME row even
// when prefix-named models sort before it.
func TestLoadModelSizeColumnMatch(t *testing.T) {
	out := `NAME              ID              SIZE      MODIFIED
a:8b              2222            5.0 GB    3 minutes ago
a                 1111            1.1 GB    2 minutes ago
b                 3333            3.0 GB    4 minutes ago
`
	got, err := matchModelSize(out, "a")
	if err != nil {
		t.Fatalf("matchModelSize(a) failed: %v", err)
	}
	if got != "1.1 GB" {
		t.Fatalf("matchModelSize(a) = %q, want 1.1 GB (must not hit prefix model a:8b)", got)
	}
	got, err = matchModelSize(out, "b")
	if err != nil {
		t.Fatalf("matchModelSize(b) failed: %v", err)
	}
	if got != "3.0 GB" {
		t.Fatalf("matchModelSize(b) = %q, want 3.0 GB", got)
	}
	if _, err := matchModelSize(out, "missing"); err == nil {
		t.Fatal("matchModelSize(missing) should report the model as absent")
	}
}
