package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/1Panel-dev/1Panel/backend/app/model"
	"github.com/1Panel-dev/1Panel/backend/constant"
	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/1Panel-dev/1Panel/backend/i18n"
	"github.com/1Panel-dev/1Panel/backend/init/cache/badger_db"
	"github.com/1Panel-dev/1Panel/backend/init/session/psession"
	"github.com/1Panel-dev/1Panel/backend/utils/common"
	"github.com/dgraph-io/badger/v4"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

func setupSessionAuthTest(t *testing.T) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open in-memory sqlite failed: %v", err)
	}
	if err := db.AutoMigrate(&model.Setting{}); err != nil {
		t.Fatalf("migrate settings failed: %v", err)
	}
	if err := db.Create(&model.Setting{Key: "SessionTimeout", Value: "60"}).Error; err != nil {
		t.Fatalf("seed SessionTimeout failed: %v", err)
	}
	global.DB = db

	cache, err := badger.Open(badger.DefaultOptions("").WithInMemory(true))
	if err != nil {
		t.Fatalf("open in-memory badger failed: %v", err)
	}
	t.Cleanup(func() { _ = cache.Close() })
	global.SESSION = psession.NewPSession(badger_db.NewCacheDB(cache))
}

func doSessionAuthRequest(t *testing.T, cookies []*http.Cookie) (int, bool, []byte) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	handled := false
	r := gin.New()
	r.Use(SessionAuth())
	r.GET("/protected", func(c *gin.Context) {
		handled = true
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	for _, ck := range cookies {
		req.AddCookie(ck)
	}
	r.ServeHTTP(w, req)
	return w.Code, handled, w.Body.Bytes()
}

func TestSessionAuthNoCookie(t *testing.T) {
	setupSessionAuthTest(t)
	code, handled, body := doSessionAuthRequest(t, nil)
	if handled {
		t.Fatal("handler ran without a session cookie")
	}
	var resp struct {
		Code int `json:"code"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("response is not valid json: %v, body: %s", err, body)
	}
	if resp.Code != constant.CodeErrUnauthorized {
		t.Fatalf("code = %d, want %d", resp.Code, constant.CodeErrUnauthorized)
	}
	_ = code
}

func TestSessionAuthLoggedIn(t *testing.T) {
	setupSessionAuthTest(t)
	if err := global.SESSION.Set("valid-sid", psession.SessionUser{ID: 1, Name: "admin", LoggedIn: true}, 60); err != nil {
		t.Fatal(err)
	}
	code, handled, _ := doSessionAuthRequest(t, []*http.Cookie{{Name: constant.SessionName, Value: "valid-sid"}})
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if !handled {
		t.Fatal("handler did not run for a logged-in session")
	}
}

func TestSessionAuthNotLoggedInFlag(t *testing.T) {
	setupSessionAuthTest(t)
	// a session value without the LoggedIn flag (e.g. stale data written
	// before this fix) must not be treated as authenticated
	if err := global.SESSION.Set("stale-sid", psession.SessionUser{ID: 1, Name: "admin"}, 60); err != nil {
		t.Fatal(err)
	}
	code, handled, body := doSessionAuthRequest(t, []*http.Cookie{{Name: constant.SessionName, Value: "stale-sid"}})
	if handled {
		t.Fatal("handler ran for a session with LoggedIn=false")
	}
	var resp struct {
		Code int `json:"code"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("response is not valid json: %v, body: %s", err, body)
	}
	if resp.Code != constant.CodeErrUnauthorized {
		t.Fatalf("code = %d, want %d", resp.Code, constant.CodeErrUnauthorized)
	}
	_ = code
}

func TestSessionAuthUnknownSID(t *testing.T) {
	setupSessionAuthTest(t)
	code, handled, _ := doSessionAuthRequest(t, []*http.Cookie{{Name: constant.SessionName, Value: "unknown-sid"}})
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (auth middleware returns 401 via helper but HTTP status stays 200)", code)
	}
	if handled {
		t.Fatal("handler ran for an unknown session id")
	}
}

func setupAPIKeyAuthTest(t *testing.T, ipWhiteList string) string {
	t.Helper()
	setupSessionAuthTest(t)

	origLog := global.LOG
	log := logrus.New()
	global.LOG = log
	t.Cleanup(func() { global.LOG = origLog })

	const apiKey = "test-api-key"
	origSystem := global.CONF.System
	global.CONF.System.ApiInterfaceStatus = "enable"
	global.CONF.System.ApiKey = apiKey
	// a positive validity time: the timestamp window must actually be enforced
	// in these tests, so the requests below mint a current timestamp
	global.CONF.System.ApiKeyValidityTime = "15"
	global.CONF.System.IpWhiteList = ipWhiteList
	t.Cleanup(func() { global.CONF.System = origSystem })
	return apiKey
}

// nowTimestamp returns the current unix time as the 1Panel-Timestamp header
// value.
func nowTimestamp() string {
	return strconv.FormatInt(time.Now().Unix(), 10)
}

func doAPIKeyAuthRequest(t *testing.T, apiKey, timestamp, remoteAddr, forwardedFor string) (bool, []byte) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	handled := false
	r := gin.New()
	r.Use(SessionAuth())
	r.GET("/protected", func(c *gin.Context) {
		handled = true
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.RemoteAddr = remoteAddr
	req.Header.Set("1Panel-Token", GenerateMD5("1panel"+apiKey+timestamp))
	req.Header.Set("1Panel-Timestamp", timestamp)
	if forwardedFor != "" {
		req.Header.Set("X-Forwarded-For", forwardedFor)
	}
	r.ServeHTTP(w, req)
	return handled, w.Body.Bytes()
}

func TestGetRealClientIPIgnoresForwardedFor(t *testing.T) {
	gin.SetMode(gin.TestMode)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "9.9.9.9:1234"
	req.Header.Set("X-Forwarded-For", "192.168.1.1")
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = req

	if got := common.GetRealClientIP(c); got != "9.9.9.9" {
		t.Fatalf("GetRealClientIP = %q, want 9.9.9.9 (X-Forwarded-For must be ignored)", got)
	}
}

func TestSessionAuthAPIKeyWhitelistUsesRealIP(t *testing.T) {
	apiKey := setupAPIKeyAuthTest(t, "9.9.9.9")
	handled, body := doAPIKeyAuthRequest(t, apiKey, nowTimestamp(), "9.9.9.9:1234", "192.168.1.1")
	if !handled {
		var resp struct {
			Code int `json:"code"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			t.Fatalf("response is not valid json: %v, body: %s", err, body)
		}
		t.Fatalf("handler did not run for whitelisted peer 9.9.9.9 (code %d); whitelist check likely matched the spoofed X-Forwarded-For", resp.Code)
	}
}

func TestSessionAuthAPIKeyWhitelistRejectsUnknownIP(t *testing.T) {
	apiKey := setupAPIKeyAuthTest(t, "9.9.9.9")
	handled, body := doAPIKeyAuthRequest(t, apiKey, nowTimestamp(), "203.0.113.5:443", "")
	if handled {
		t.Fatal("handler ran for a peer outside the API-key whitelist")
	}
	var resp struct {
		Code int `json:"code"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("response is not valid json: %v, body: %s", err, body)
	}
	if resp.Code != constant.CodeErrUnauthorized {
		t.Fatalf("code = %d, want %d", resp.Code, constant.CodeErrUnauthorized)
	}
}

// TestIsValid1PanelTimestamp pins the ApiKeyValidityTime handling: only a
// positive numeric validity time lets a fresh timestamp through, and the
// window itself is enforced. ApiKeyValidityTime=0 used to skip timestamp
// validation entirely, letting a captured signature be replayed forever.
func TestIsValid1PanelTimestamp(t *testing.T) {
	origLog := global.LOG
	log := logrus.New()
	global.LOG = log
	t.Cleanup(func() { global.LOG = origLog })

	origSystem := global.CONF.System
	t.Cleanup(func() { global.CONF.System = origSystem })

	now := nowTimestamp()
	cases := []struct {
		name      string
		validity  string
		timestamp string
		want      bool
	}{
		{"positive validity with fresh timestamp", "15", now, true},
		{"positive validity with stale timestamp", "15", "1700000000", false},
		{"future timestamp beyond tolerance", "15", strconv.FormatInt(time.Now().Add(10*time.Minute).Unix(), 10), false},
		{"zero validity rejects fresh timestamp", "0", now, false},
		{"negative validity", "-1", now, false},
		{"non-numeric validity", "abc", now, false},
		{"empty validity", "", now, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			global.CONF.System.ApiKeyValidityTime = tc.validity
			if got := isValid1PanelTimestamp(tc.timestamp); got != tc.want {
				t.Fatalf("isValid1PanelTimestamp(%q) with validity %q = %v, want %v", tc.timestamp, tc.validity, got, tc.want)
			}
		})
	}
}

// TestSessionAuthAPIKeyZeroValidityRejected drives the middleware end to end:
// with ApiKeyValidityTime=0 the request must be refused with the timestamp
// error, not waved through without a timestamp check.
func TestSessionAuthAPIKeyZeroValidityRejected(t *testing.T) {
	apiKey := setupAPIKeyAuthTest(t, "9.9.9.9")
	global.CONF.System.ApiKeyValidityTime = "0"

	handled, body := doAPIKeyAuthRequest(t, apiKey, nowTimestamp(), "9.9.9.9:1234", "")
	if handled {
		t.Fatal("handler ran with ApiKeyValidityTime=0, want timestamp rejection")
	}
	var resp struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("response is not valid json: %v, body: %s", err, body)
	}
	if resp.Code != constant.CodeErrUnauthorized {
		t.Fatalf("code = %d, want %d", resp.Code, constant.CodeErrUnauthorized)
	}
	// the message is the i18n rendering of the timestamp error key
	if want := i18n.GetMsgWithMap(constant.ErrApiConfigKeyTimeInvalid, nil); resp.Message != want {
		t.Fatalf("message = %q, want %q", resp.Message, want)
	}
}
