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
