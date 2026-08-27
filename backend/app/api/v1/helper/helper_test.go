package helper

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
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
// ErrInitialPassword sentinel maps to the initial-password branch.
func TestErrorWithDetailWrappedInitialPassword(t *testing.T) {
	err := fmt.Errorf("check password: %w", constant.ErrInitialPassword)
	resp := runErrorWithDetail(t, err)

	want := i18n.GetMsgWithMap("ErrInitialPassword", map[string]interface{}{"detail": err})
	if resp.Message != want {
		t.Errorf("wrapped ErrInitialPassword: got message %q, want %q", resp.Message, want)
	}
}

// TestErrorWithDetailGenericError proves the default branch still handles
// unrelated errors.
func TestErrorWithDetailGenericError(t *testing.T) {
	err := fmt.Errorf("boom")
	resp := runErrorWithDetail(t, err)

	want := i18n.GetMsgWithMap(constant.ErrTypeInternalServer, map[string]interface{}{"detail": err})
	if resp.Message != want {
		t.Errorf("generic error: got message %q, want %q", resp.Message, want)
	}
	if resp.Code != constant.CodeErrInternalServer {
		t.Errorf("generic error: got code %d, want %d", resp.Code, constant.CodeErrInternalServer)
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
