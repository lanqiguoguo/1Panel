package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/i18n"
)

func TestWritePasswordUpdateSuccessDoesNotExposePassword(t *testing.T) {
	i18n.UseI18nForCmd("en")

	const (
		username = "admin"
		password = "new-admin-password-123!"
	)
	var output bytes.Buffer

	writePasswordUpdateSuccess(&output, username)
	result := output.String()

	if strings.Contains(result, password) {
		t.Fatalf("password update output contains the new password: %q", result)
	}
	if strings.Contains(result, "Panel password:") {
		t.Fatalf("password update output contains a password field: %q", result)
	}
	wantUser := i18n.GetMsgWithMapForCmd("UpdateUserResult", map[string]interface{}{"name": username})
	if !strings.Contains(result, wantUser) {
		t.Fatalf("password update output lost the panel user: %q", result)
	}
}

// isValidPassword reports whether a password satisfies the panel complexity
// rule: true = valid (at least two of letter/digit/special character classes,
// total length 8-30). The 1pctl update password flow rejects the user input
// with UpdatePasswordFormat when it is not valid (i.e. when it returns false).
func TestIsValidPassword(t *testing.T) {
	valid := []string{
		"Abcdefg1",                       // letter + digit, 8 chars
		"abcdefg1",                       // letter + digit
		"12345678a",                      // digit + letter
		"abcd!@#$",                       // letter + special
		"12345678!@",                     // digit + special
		"Ab3!eF9#kL2mN8",                 // letter + digit + special
		"a1!a1!a1!a1!a1!a1!a1!a1!a1!a1!", // 30 chars, letter + digit + special
	}
	invalid := []string{
		"",                                  // empty
		"abcdefg",                           // 7 chars (too short) + single class
		"Abcdefgh",                          // single class (letters only), 8 chars
		"12345678",                          // single class (digits only)
		"!!!!!!!!",                          // single class (special only)
		"Abcdefg1Abcdefg1Abcdefg1Abcdefg11", // 33 chars
		"a1!a1!a1!a1!a1!a1!a1!a1!a1!a1!a1!", // 33 chars, too long
		"newPassword",                       // the old literal: letters only -> single class, must be invalid
	}
	for _, p := range valid {
		if !isValidPassword(p) {
			t.Errorf("isValidPassword(%q) = false, want true (valid)", p)
		}
	}
	for _, p := range invalid {
		if isValidPassword(p) {
			t.Errorf("isValidPassword(%q) = true, want false (invalid)", p)
		}
	}
}
