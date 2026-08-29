package v1

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/app/dto"
	"github.com/1Panel-dev/1Panel/backend/app/dto/request"
	"github.com/1Panel-dev/1Panel/backend/app/service"
	"github.com/1Panel-dev/1Panel/backend/constant"
	"github.com/gin-gonic/gin"
)

// batchRoleFileServiceStub overrides only the method under test. The embedded
// interface supplies the unrelated methods without invoking them.
type batchRoleFileServiceStub struct {
	service.IFileService
	err   error
	calls int
}

func (s *batchRoleFileServiceStub) BatchChangeModeAndOwner(request.FileRoleReq) error {
	s.calls++
	return s.err
}

var _ service.IFileService = (*batchRoleFileServiceStub)(nil)

func runBatchChangeModeAndOwner(t *testing.T, body string, stub *batchRoleFileServiceStub) (int, []byte) {
	t.Helper()

	originalService := fileService
	fileService = stub
	defer func() { fileService = originalService }()

	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/files/batch/role", strings.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")

	new(BaseApi).BatchChangeModeAndOwner(c)
	return recorder.Code, recorder.Body.Bytes()
}

func decodeBatchRoleResponse(t *testing.T, body []byte) dto.Response {
	t.Helper()

	var response dto.Response
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatalf("batch role response must contain exactly one JSON document, body=%q: %v", body, err)
	}
	return response
}

func TestBatchChangeModeAndOwnerServiceErrorReturnsOnlyError(t *testing.T) {
	stub := &batchRoleFileServiceStub{err: errors.New("permission denied")}
	status, body := runBatchChangeModeAndOwner(t, `{"paths":["/tmp/file"],"mode":420,"user":"root","group":"root"}`, stub)

	if status != http.StatusOK {
		t.Fatalf("service error status = %d, want %d", status, http.StatusOK)
	}
	response := decodeBatchRoleResponse(t, body)
	if response.Code == constant.CodeSuccess {
		t.Fatalf("service error response unexpectedly succeeded: %+v", response)
	}
	if response.Message == "" {
		t.Fatal("service error response has an empty message")
	}
	if stub.calls != 1 {
		t.Fatalf("service calls = %d, want 1", stub.calls)
	}
}

func TestBatchChangeModeAndOwnerValidationErrorReturnsOnlyError(t *testing.T) {
	stub := &batchRoleFileServiceStub{}
	status, body := runBatchChangeModeAndOwner(t, `{}`, stub)

	if status != http.StatusOK {
		t.Fatalf("validation error status = %d, want %d", status, http.StatusOK)
	}
	response := decodeBatchRoleResponse(t, body)
	if response.Code == constant.CodeSuccess {
		t.Fatalf("validation error response unexpectedly succeeded: %+v", response)
	}
	if stub.calls != 0 {
		t.Fatalf("service calls = %d, want 0", stub.calls)
	}
}

func TestBatchChangeModeAndOwnerSuccessReturnsOnlySuccess(t *testing.T) {
	stub := &batchRoleFileServiceStub{}
	status, body := runBatchChangeModeAndOwner(t, `{"paths":["/tmp/file"],"mode":420,"user":"root","group":"root"}`, stub)

	if status != http.StatusOK {
		t.Fatalf("success status = %d, want %d", status, http.StatusOK)
	}
	response := decodeBatchRoleResponse(t, body)
	if response.Code != constant.CodeSuccess {
		t.Fatalf("success response = %+v, want code %d", response, constant.CodeSuccess)
	}
	if stub.calls != 1 {
		t.Fatalf("service calls = %d, want 1", stub.calls)
	}
}
