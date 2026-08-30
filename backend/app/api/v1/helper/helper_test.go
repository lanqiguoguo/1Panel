package helper

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/app/dto"
	"github.com/1Panel-dev/1Panel/backend/constant"
	"github.com/1Panel-dev/1Panel/backend/i18n"
	"github.com/gin-gonic/gin"
)

func runErrorWithDetail(t *testing.T, err error) dto.Response {
	t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	ErrorWithDetail(c, constant.CodeErrInternalServer, constant.ErrTypeInternalServer, err)
	var resp dto.Response
	if unmarshalErr := json.Unmarshal(w.Body.Bytes(), &resp); unmarshalErr != nil {
		t.Fatalf("failed to decode response body %q: %v", w.Body.String(), unmarshalErr)
	}
	return resp
}

// TestErrorWithDetailWrappedRecordNotFound proves that an error wrapping the
// ErrRecordNotFound sentinel maps to the not-found user message branch instead
// of the generic internal-server-error branch.
func TestErrorWithDetailWrappedRecordNotFound(t *testing.T) {
	err := fmt.Errorf("load website: %w", constant.ErrRecordNotFound)
	resp := runErrorWithDetail(t, err)

	want := i18n.GetMsgWithMap("ErrRecordNotFound", nil)
	defaultMsg := i18n.GetMsgWithMap(constant.ErrTypeInternalServer, map[string]interface{}{"detail": err})
	if want == defaultMsg {
		t.Fatalf("test setup invalid: not-found message equals the default internal message")
	}
	if resp.Message != want {
		t.Errorf("wrapped ErrRecordNotFound: got message %q, want %q (default branch leaked: %v)", resp.Message, want, resp.Message == defaultMsg)
	}
	if resp.Code != constant.CodeErrInternalServer {
		t.Errorf("wrapped ErrRecordNotFound: got code %d, want %d", resp.Code, constant.CodeErrInternalServer)
	}
}

// TestErrorWithDetailWrappedAuth proves that an error wrapping the ErrAuth
// sentinel maps to the auth branch (auth code + fixed message).
func TestErrorWithDetailWrappedAuth(t *testing.T) {
	err := fmt.Errorf("check session: %w", constant.ErrAuth)
	resp := runErrorWithDetail(t, err)

	if resp.Code != constant.CodeAuth {
		t.Errorf("wrapped ErrAuth: got code %d, want %d", resp.Code, constant.CodeAuth)
	}
	if resp.Message != "ErrAuth" {
		t.Errorf("wrapped ErrAuth: got message %q, want %q", resp.Message, "ErrAuth")
	}
}

// TestErrorWithDetailWrappedInvalidParams proves that an error wrapping the
// ErrInvalidParams sentinel maps to the invalid-params branch.
func TestErrorWithDetailWrappedInvalidParams(t *testing.T) {
	err := fmt.Errorf("parse input: %w", constant.ErrInvalidParams)
	resp := runErrorWithDetail(t, err)

	want := i18n.GetMsgWithMap("ErrInvalidParams", nil)
	if resp.Message != want {
		t.Errorf("wrapped ErrInvalidParams: got message %q, want %q", resp.Message, want)
	}
}

// TestErrorWithDetailWrappedInitialPassword proves that an error wrapping the
// ErrInitialPassword sentinel maps to the initial-password branch. The raw
// wrapped error is logged, never spliced into the response.
func TestErrorWithDetailWrappedInitialPassword(t *testing.T) {
	err := fmt.Errorf("check password: %w", constant.ErrInitialPassword)
	resp := runErrorWithDetail(t, err)

	want := i18n.GetMsgWithMap("ErrInitialPassword", nil)
	if resp.Message != want {
		t.Errorf("wrapped ErrInitialPassword: got message %q, want %q", resp.Message, want)
	}
	if strings.Contains(resp.Message, "check password") {
		t.Errorf("wrapped ErrInitialPassword: raw error leaked into response: %q", resp.Message)
	}
}

// TestErrorWithDetailGenericError proves the default branch still handles
// unrelated errors with a fixed message (no raw err in the response).
func TestErrorWithDetailGenericError(t *testing.T) {
	err := fmt.Errorf("boom")
	resp := runErrorWithDetail(t, err)

	want := i18n.GetMsgWithMap(constant.ErrTypeInternalServer, nil)
	if resp.Message != want {
		t.Errorf("generic error: got message %q, want %q", resp.Message, want)
	}
	if resp.Code != constant.CodeErrInternalServer {
		t.Errorf("generic error: got code %d, want %d", resp.Code, constant.CodeErrInternalServer)
	}
}

// TestErrorWithDetailNoPathLeak proves the default branch no longer splices
// raw errors (which can embed absolute file paths) into the response.
func TestErrorWithDetailNoPathLeak(t *testing.T) {
	const secretPath = "/opt/1panel/secret/data.db"
	err := fmt.Errorf("open %s: no such file or directory", secretPath)
	resp := runErrorWithDetail(t, err)

	if strings.Contains(resp.Message, secretPath) {
		t.Errorf("default branch leaked path %q into response: %q", secretPath, resp.Message)
	}
	if strings.Contains(resp.Message, "no such file") {
		t.Errorf("default branch leaked raw error into response: %q", resp.Message)
	}
}

// TestErrorWithDetailStructTransformNoLeak proves the ErrStructTransform
// branch keeps its generic template without the raw wrapped error.
func TestErrorWithDetailStructTransformNoLeak(t *testing.T) {
	const secretPath = "/var/lib/1panel/runtime/go/app/main.go"
	err := fmt.Errorf("copy %s: %w", secretPath, constant.ErrStructTransform)
	resp := runErrorWithDetail(t, err)

	want := i18n.GetMsgWithMap("ErrStructTransform", nil)
	if resp.Message != want {
		t.Errorf("ErrStructTransform: got message %q, want %q", resp.Message, want)
	}
	if strings.Contains(resp.Message, secretPath) {
		t.Errorf("ErrStructTransform leaked path %q into response: %q", secretPath, resp.Message)
	}
}

// TestErrorWithDetailInvalidParamsNoEcho proves the non-internal branch does
// not echo the raw binding/validation error (which can contain request
// content) back to the client.
func TestErrorWithDetailInvalidParamsNoEcho(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	err := fmt.Errorf("invalid character 'x' looking for beginning of value, request body: {\"path\":\"/opt/secret\"}")
	ErrorWithDetail(c, constant.CodeErrBadRequest, constant.ErrTypeInvalidParams, err)
	var resp dto.Response
	if unmarshalErr := json.Unmarshal(w.Body.Bytes(), &resp); unmarshalErr != nil {
		t.Fatalf("failed to decode response body %q: %v", w.Body.String(), unmarshalErr)
	}
	want := i18n.GetMsgWithMap("ErrInvalidParams", nil)
	if resp.Message != want {
		t.Errorf("invalid params: got message %q, want %q", resp.Message, want)
	}
	if strings.Contains(resp.Message, "/opt/secret") || strings.Contains(resp.Message, "invalid character") {
		t.Errorf("invalid params branch echoed raw error: %q", resp.Message)
	}
}

func paramContext(t *testing.T, params gin.Params) *gin.Context {
	t.Helper()
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Params = params
	return c
}

// TestGetParamIDInvalid tests that a non-numeric id param returns an error
// instead of silently producing 0.
func TestGetParamIDInvalid(t *testing.T) {
	c := paramContext(t, gin.Params{{Key: "id", Value: "abc"}})
	id, err := GetParamID(c)
	if err == nil {
		t.Fatalf("GetParamID with non-numeric id: expected error, got id %d and nil error", id)
	}
	if id != 0 {
		t.Errorf("GetParamID with non-numeric id: got id %d, want 0", id)
	}
}

// TestGetParamIDValid tests that a numeric id param still parses.
func TestGetParamIDValid(t *testing.T) {
	c := paramContext(t, gin.Params{{Key: "id", Value: "42"}})
	id, err := GetParamID(c)
	if err != nil {
		t.Fatalf("GetParamID with numeric id: unexpected error: %v", err)
	}
	if id != 42 {
		t.Errorf("GetParamID: got id %d, want 42", id)
	}
}

// TestGetParamIDMissing tests the missing-param branch.
func TestGetParamIDMissing(t *testing.T) {
	c := paramContext(t, nil)
	if _, err := GetParamID(c); err == nil {
		t.Fatalf("GetParamID without id param: expected error, got nil")
	}
}

// TestGetIntParamByKeyInvalid tests that a non-numeric named param returns an
// error instead of silently producing 0.
func TestGetIntParamByKeyInvalid(t *testing.T) {
	c := paramContext(t, gin.Params{{Key: "websiteId", Value: "1x2"}})
	id, err := GetIntParamByKey(c, "websiteId")
	if err == nil {
		t.Fatalf("GetIntParamByKey with non-numeric websiteId: expected error, got id %d and nil error", id)
	}
	if id != 0 {
		t.Errorf("GetIntParamByKey with non-numeric websiteId: got id %d, want 0", id)
	}
}

// TestGetIntParamByKeyValid tests that a numeric named param still parses.
func TestGetIntParamByKeyValid(t *testing.T) {
	c := paramContext(t, gin.Params{{Key: "websiteId", Value: "7"}})
	id, err := GetIntParamByKey(c, "websiteId")
	if err != nil {
		t.Fatalf("GetIntParamByKey with numeric websiteId: unexpected error: %v", err)
	}
	if id != 7 {
		t.Errorf("GetIntParamByKey: got id %d, want 7", id)
	}
}
