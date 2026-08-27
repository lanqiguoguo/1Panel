package v1

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/app/dto"
	"github.com/1Panel-dev/1Panel/backend/app/model"
	"github.com/1Panel-dev/1Panel/backend/app/service"
	"github.com/1Panel-dev/1Panel/backend/constant"
	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/1Panel-dev/1Panel/backend/init/auth"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/go-playground/validator/v10"
	"github.com/mojocn/base64Captcha"
	"gorm.io/gorm"
)

// TestMFALoginAllowed guards MFA brute-force rate limiting: once an IP
// accumulates enough failures in the shared IPTracker (the same counter the
// normal login path uses), further MFA attempts must be refused until the
// flag is cleared or expires.
func TestMFALoginAllowed(t *testing.T) {
	original := global.IPTracker
	global.IPTracker = auth.NewIPTracker()
	defer func() { global.IPTracker = original }()

	const ip = "192.0.2.10"

	if !mfaLoginAllowed(ip) {
		t.Fatal("mfaLoginAllowed() = false for an unknown IP, want true")
	}

	for i := 0; i < auth.MaxFailCount; i++ {
		global.IPTracker.RecordFailure(ip)
	}
	if mfaLoginAllowed(ip) {
		t.Fatal("mfaLoginAllowed() = true for a flagged IP, want false")
	}

	// A different, unflagged IP must still be allowed.
	const otherIP = "192.0.2.11"
	if !mfaLoginAllowed(otherIP) {
		t.Fatal("mfaLoginAllowed() = false for an unflagged IP, want true")
	}

	// Clearing the flag must restore access.
	global.IPTracker.Clear(ip)
	if !mfaLoginAllowed(ip) {
		t.Fatal("mfaLoginAllowed() = false after Clear(), want true")
	}
}

// TestShouldClearTracker pins the stage-1 success discriminator: only an
// empty MfaStatus means authentication fully completed (a session was
// issued). A non-empty MfaStatus means the credentials were accepted but the
// TOTP step is still pending, so the IP tracker must not be reset.
func TestShouldClearTracker(t *testing.T) {
	if !shouldClearTracker("") {
		t.Fatal(`shouldClearTracker("") = false, want true (session issued)`)
	}
	if shouldClearTracker("enable") {
		t.Fatal(`shouldClearTracker("enable") = true, want false (MFA pending)`)
	}
}

// fakeAuthService stubs service.IAuthService so the Login/MFALogin handlers
// can be exercised without a database-backed user store.
type fakeAuthService struct {
	loginRes    *dto.UserLoginInfo
	loginErr    error
	mfaLoginRes *dto.UserLoginInfo
	mfaLoginErr error
}

func (f *fakeAuthService) GetResponsePage() (string, error) { return "", nil }
func (f *fakeAuthService) VerifyCode(string) (bool, error)  { return true, nil }
func (f *fakeAuthService) GetSecurityEntrance() string      { return "" }
func (f *fakeAuthService) IsLogin(*gin.Context) bool        { return false }
func (f *fakeAuthService) LogOut(*gin.Context) error        { return nil }
func (f *fakeAuthService) Login(*gin.Context, dto.Login, string) (*dto.UserLoginInfo, error) {
	return f.loginRes, f.loginErr
}
func (f *fakeAuthService) MFALogin(*gin.Context, dto.MFALogin, string) (*dto.UserLoginInfo, error) {
	return f.mfaLoginRes, f.mfaLoginErr
}

func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode)
	global.VALID = validator.New()
	// The Login handler logs asynchronously via saveLoginLogs, which writes
	// to global.DB; provide an in-memory DB so that goroutine never sees nil.
	db, err := gorm.Open(sqlite.Open("file:auth_api_test?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "open in-memory sqlite failed: %v\n", err)
		os.Exit(1)
	}
	if err := db.AutoMigrate(&model.LoginLog{}); err != nil {
		fmt.Fprintf(os.Stderr, "migrate login log failed: %v\n", err)
		os.Exit(1)
	}
	global.DB = db
	os.Exit(m.Run())
}

// postJSON invokes handler with a JSON POST request coming from ip and
// returns the decoded response envelope.
func postJSON(t *testing.T, handler gin.HandlerFunc, ip, body string) *dto.Response {
	t.Helper()
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = ip + ":12345"
	c.Request = req
	handler(c)
	var res dto.Response
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatalf("invalid JSON response %q: %v", w.Body.String(), err)
	}
	return &res
}

// seedCaptcha registers a known captcha answer so the flagged-IP captcha
// check in the Login handler can pass deterministically.
func seedCaptcha(t *testing.T, id, code string) {
	t.Helper()
	if err := base64Captcha.DefaultMemStore.Set(id, code); err != nil {
		t.Fatalf("seed captcha failed: %v", err)
	}
}

// flagIP accumulates enough login failures to flag the IP.
func flagIP(ip string) {
	for i := 0; i < auth.MaxFailCount; i++ {
		global.IPTracker.RecordFailure(ip)
	}
}

// TestLoginMFAPendingDoesNotClearTracker guards the MFA brute-force fix: a
// stage-1 login for an MFA-pending account (service answers with MfaStatus
// set, no session issued) must not reset the IP tracker, otherwise an
// attacker who knows the username+password could wipe the TOTP failure
// counter by re-running stage-1 login and guess MFA codes indefinitely.
func TestLoginMFAPendingDoesNotClearTracker(t *testing.T) {
	originalTracker := global.IPTracker
	originalService := authService
	global.IPTracker = auth.NewIPTracker()
	authService = &fakeAuthService{loginRes: &dto.UserLoginInfo{Name: "admin", MfaStatus: "enable"}}
	defer func() {
		global.IPTracker = originalTracker
		authService = originalService
	}()

	const ip = "192.0.2.20"
	flagIP(ip)
	if mfaLoginAllowed(ip) {
		t.Fatal("mfaLoginAllowed() = true for a flagged IP, want false")
	}

	seedCaptcha(t, "mfa-pending-captcha", "abcde")
	res := postJSON(t, new(BaseApi).Login, ip,
		`{"name":"admin","password":"secret","authMethod":"session","language":"en","captchaID":"mfa-pending-captcha","captcha":"abcde"}`)
	if res.Code != constant.CodeSuccess {
		t.Fatalf("stage-1 login for MFA-pending account did not succeed: %+v", res)
	}
	if mfaLoginAllowed(ip) {
		t.Fatal("stage-1 MFA-pending login cleared the IP tracker; the TOTP failure counter must survive")
	}
}

// TestLoginFullSuccessClearsTracker pins the non-MFA behavior: a stage-1
// login that completes authentication (empty MfaStatus, session issued)
// clears the IP tracker so the failure counter starts fresh.
func TestLoginFullSuccessClearsTracker(t *testing.T) {
	originalTracker := global.IPTracker
	originalService := authService
	global.IPTracker = auth.NewIPTracker()
	authService = &fakeAuthService{loginRes: &dto.UserLoginInfo{Name: "admin"}}
	defer func() {
		global.IPTracker = originalTracker
		authService = originalService
	}()

	const ip = "192.0.2.21"
	flagIP(ip)
	seedCaptcha(t, "full-success-captcha", "abcde")
	res := postJSON(t, new(BaseApi).Login, ip,
		`{"name":"admin","password":"secret","authMethod":"session","language":"en","captchaID":"full-success-captcha","captcha":"abcde"}`)
	if res.Code != constant.CodeSuccess {
		t.Fatalf("full login did not succeed: %+v", res)
	}
	if !mfaLoginAllowed(ip) {
		t.Fatal("full login success did not clear the IP tracker")
	}
}

// TestMFALoginSuccessClearsTracker verifies the /auth/mfa-login success path
// resets the failure counter: a legitimate user who passes the TOTP check
// gets a clean tracker state even though earlier wrong codes accumulated.
func TestMFALoginSuccessClearsTracker(t *testing.T) {
	originalTracker := global.IPTracker
	originalService := authService
	global.IPTracker = auth.NewIPTracker()
	authService = &fakeAuthService{mfaLoginRes: &dto.UserLoginInfo{Name: "admin"}}
	defer func() {
		global.IPTracker = originalTracker
		authService = originalService
	}()

	const ip = "192.0.2.22"
	// Failures below the flag threshold, so the handler is not refused.
	for i := 0; i < auth.MaxFailCount-1; i++ {
		global.IPTracker.RecordFailure(ip)
	}
	res := postJSON(t, new(BaseApi).MFALogin, ip, `{"name":"admin","password":"secret","code":"123456"}`)
	if res.Code != constant.CodeSuccess {
		t.Fatalf("MFA login did not succeed: %+v", res)
	}
	// The counter was wiped by the successful login, so one more failure
	// must not reach the flag threshold.
	global.IPTracker.RecordFailure(ip)
	if !mfaLoginAllowed(ip) {
		t.Fatal("MFALogin success did not clear the failure counter")
	}
}

// compile-time check that the fake satisfies the service interface used by
// the handlers.
var _ service.IAuthService = (*fakeAuthService)(nil)
