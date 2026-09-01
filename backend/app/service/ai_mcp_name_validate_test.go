package service

import (
	"os"
	"strings"
	"testing"
)

// TestValidOllamaModelName covers the whitelist gate applied to ollama model
// names before they are joined into the DataDir/log/AITools log path and
// interpolated into `docker exec ... ollama pull <name>`.
func TestValidOllamaModelName(t *testing.T) {
	valid := []string{
		"llama3:8b",                  // namespaced tag form
		"llama3",                     // plain name
		"qwen/qwen2.5:7b",            // namespace slash (legal ollama identifier)
		"x/y",                        // namespace slash
		"a",                          // single char
		"Model_1.2-b",                // mixed charset
		"llama3:70b-instruct-q4_K_M", // realistic long tag
		strings.Repeat("a", 128),     // 128 chars = whitelist cap
	}
	invalid := []string{
		"",                       // empty
		"../..",                  // traversal
		"..",                     // traversal
		"a/../b",                 // traversal embedded in namespace
		"../evil",                // traversal
		"evil/..",                // traversal
		"a/../../b",              // traversal
		".",                      // dot name
		"$(id)",                  // command substitution
		"a b",                    // space (bash word-splitting)
		"a;b",                    // shell metacharacter
		"a|b",                    // shell metacharacter
		"a&b",                    // shell metacharacter
		"a`id`b",                 // shell metacharacter
		"a'b",                    // shell metacharacter
		`a"b`,                    // shell metacharacter
		"a>b",                    // redirection
		"a<b",                    // redirection
		"a\\b",                   // backslash
		"a\nb",                   // newline
		"a\tb",                   // tab
		"名前",                     // outside whitelist charset
		strings.Repeat("a", 129), // > 128 chars
	}

	for _, s := range valid {
		if !validOllamaModelName(s) {
			t.Errorf("validOllamaModelName(%q) = false, want true", s)
		}
	}
	for _, s := range invalid {
		if validOllamaModelName(s) {
			t.Errorf("validOllamaModelName(%q) = true, want false", s)
		}
	}
}

// TestOllamaModelLogPathContainment verifies the defense-in-depth check on the
// joined log path: it must either stay under DataDir/log/AITools or be empty.
func TestOllamaModelLogPathContainment(t *testing.T) {
	const dataDir = "/opt/1panel"
	const baseDir = "/opt/1panel/log/AITools"

	for _, name := range []string{"llama3:8b", "qwen/qwen2.5:7b", "Model_1.2-b"} {
		got := ollamaModelLogPath(dataDir, name)
		if got == "" {
			t.Fatalf("ollamaModelLogPath(%q) unexpectedly empty for valid name", name)
		}
		if !strings.HasPrefix(got, baseDir+string(os.PathSeparator)) {
			t.Errorf("ollamaModelLogPath(%q) = %q escapes %s", name, got, baseDir)
		}
	}

	// Even if a hostile name somehow passed the whitelist, the join check must
	// refuse to return an in-bounds path for traversal payloads.
	for _, name := range []string{"../..", "../evil", "a/../.."} {
		if got := ollamaModelLogPath(dataDir, name); got != "" && !strings.HasPrefix(got, baseDir+string(os.PathSeparator)) {
			t.Errorf("ollamaModelLogPath(%q) = %q escapes %s", name, got, baseDir)
		}
	}
}

// TestValidMcpName covers the whitelist gate applied to MCP server names before
// they are joined into constant.McpDir for the compose/.env directory.
func TestValidMcpName(t *testing.T) {
	valid := []string{
		"mcp-server",
		"Server_01",
		"a",
		"srv.name",   // dot allowed by the backend whitelist
		"my-mcp_1.0", // mixed charset
		// 64 chars: the name column cap the whitelist enforces
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	invalid := []string{
		"",         // empty
		"..",       // traversal
		"../..",    // traversal
		"a/b",      // path separator
		`a\b`,      // path separator
		"$(id)",    // command substitution
		"a b",      // space
		"a;b",      // shell metacharacter
		"a|b",      // shell metacharacter
		"a&b",      // shell metacharacter
		"a`id`b",   // shell metacharacter
		"a\nb",     // newline
		"a\tb",     // tab
		"名前",       // outside whitelist charset
		"-leading", // starts with a separator (matches frontend appName rule)
		"_leading", // starts with a separator (matches frontend appName rule)
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1", // 65 chars > cap
	}

	for _, s := range valid {
		if !validMcpName(s) {
			t.Errorf("validMcpName(%q) = false, want true", s)
		}
	}
	for _, s := range invalid {
		if validMcpName(s) {
			t.Errorf("validMcpName(%q) = true, want false", s)
		}
	}
}
