package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/app/model"
	"github.com/1Panel-dev/1Panel/backend/constant"
	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/1Panel-dev/1Panel/backend/init/cache/badger_db"
	"github.com/1Panel-dev/1Panel/backend/init/session/psession"
	"github.com/dgraph-io/badger/v4"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
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
