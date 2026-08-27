package service

import (
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

func setupAuthServiceTest(t *testing.T) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open in-memory sqlite failed: %v", err)
	}
	if err := db.AutoMigrate(&model.Setting{}); err != nil {
		t.Fatalf("migrate settings failed: %v", err)
	}
	seeds := []model.Setting{
		{Key: "SessionTimeout", Value: "60"},
		{Key: "SSL", Value: "disable"},
	}
	for i := range seeds {
		if err := db.Create(&seeds[i]).Error; err != nil {
			t.Fatalf("seed setting %s failed: %v", seeds[i].Key, err)
		}
	}
	global.DB = db

	cache, err := badger.Open(badger.DefaultOptions("").WithInMemory(true))
	if err != nil {
		t.Fatalf("open in-memory badger failed: %v", err)
	}
	t.Cleanup(func() { _ = cache.Close() })
	global.SESSION = psession.NewPSession(badger_db.NewCacheDB(cache))
}

func newAuthTestContext(t *testing.T) (*gin.Context, *httptest.ResponseRecorder) {
	t.Helper()
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("GET", "/", nil)
	return c, w
}

// TestGenerateSessionAlwaysIssuesNewSID guards against session fixation:
// even when the request carries an attacker-known session cookie, login must
// mint a brand new session id instead of reusing the presented one.
func TestGenerateSessionAlwaysIssuesNewSID(t *testing.T) {
	setupAuthServiceTest(t)
	u := &AuthService{}

	attackerSID := "attacker-known-sid"
	if err := global.SESSION.Set(attackerSID, psession.SessionUser{ID: 1, Name: "admin", LoggedIn: true}, 60); err != nil {
		t.Fatal(err)
	}

	c, w := newAuthTestContext(t)
	// present the attacker-known cookie the same way a browser would
	c.Request.Header.Set("Cookie", constant.SessionName+"="+attackerSID)

	if _, err := u.generateSession(c, "admin", constant.AuthMethodSession); err != nil {
		t.Fatal(err)
	}

	newSID := ""
	for _, ck := range w.Result().Cookies() {
		if ck.Name == constant.SessionName {
			newSID = ck.Value
		}
	}
	if newSID == "" {
		t.Fatal("no session cookie was set on login")
	}
	if newSID == attackerSID {
		t.Fatal("login reused the attacker-provided session id (session fixation)")
	}
	sessionUser, err := global.SESSION.Get(newSID)
	if err != nil {
		t.Fatalf("new session %q not found in store: %v", newSID, err)
	}
	if !sessionUser.LoggedIn {
		t.Fatal("new session does not carry LoggedIn=true")
	}
	if sessionUser.Name != "admin" {
		t.Fatalf("new session user name = %q, want admin", sessionUser.Name)
	}
}

func TestGenerateSessionLoggedInFlag(t *testing.T) {
	setupAuthServiceTest(t)
	u := &AuthService{}
	c, w := newAuthTestContext(t)

	if _, err := u.generateSession(c, "admin", constant.AuthMethodSession); err != nil {
		t.Fatal(err)
	}
	newSID := ""
	for _, ck := range w.Result().Cookies() {
		if ck.Name == constant.SessionName {
			newSID = ck.Value
		}
	}
	if newSID == "" {
		t.Fatal("no session cookie was set on login")
	}
	sessionUser, err := global.SESSION.Get(newSID)
	if err != nil {
		t.Fatalf("new session %q not found in store: %v", newSID, err)
	}
	if !sessionUser.LoggedIn {
		t.Fatal("session stored without LoggedIn=true")
	}
}

func TestGenerateSessionJWTNoSessionCookie(t *testing.T) {
	setupAuthServiceTest(t)
	u := &AuthService{}
	c, w := newAuthTestContext(t)

	info, err := u.generateSession(c, "admin", constant.AuthMethodJWT)
	if err != nil {
		t.Fatal(err)
	}
	if info.Token == "" {
		t.Fatal("jwt login returned no token")
	}
	if len(w.Result().Cookies()) != 0 {
		t.Fatal("jwt login must not set a session cookie")
	}
}

func TestLogOutDeletesSession(t *testing.T) {
	setupAuthServiceTest(t)
	u := &AuthService{}
	sid := "to-logout"
	if err := global.SESSION.Set(sid, psession.SessionUser{ID: 1, Name: "admin", LoggedIn: true}, 60); err != nil {
		t.Fatal(err)
	}
	c, _ := newAuthTestContext(t)
	c.Request.Header.Set("Cookie", constant.SessionName+"="+sid)

	if err := u.LogOut(c); err != nil {
		t.Fatal(err)
	}
	if _, err := global.SESSION.Get(sid); err == nil {
		t.Fatal("session still present after LogOut")
	}
}

func TestIsLoginRequiresLoggedIn(t *testing.T) {
	setupAuthServiceTest(t)
	u := &AuthService{}

	cStale, _ := newAuthTestContext(t)
	if err := global.SESSION.Set("stale-sid", psession.SessionUser{ID: 1, Name: "admin"}, 60); err != nil {
		t.Fatal(err)
	}
	cStale.Request.Header.Set("Cookie", constant.SessionName+"=stale-sid")
	if u.IsLogin(cStale) {
		t.Fatal("IsLogin = true for session without LoggedIn flag")
	}

	cValid, _ := newAuthTestContext(t)
	if err := global.SESSION.Set("valid-sid", psession.SessionUser{ID: 1, Name: "admin", LoggedIn: true}, 60); err != nil {
		t.Fatal(err)
	}
	cValid.Request.Header.Set("Cookie", constant.SessionName+"=valid-sid")
	if !u.IsLogin(cValid) {
		t.Fatal("IsLogin = false for logged-in session")
	}

	cMissing, _ := newAuthTestContext(t)
	if u.IsLogin(cMissing) {
		t.Fatal("IsLogin = true without any session cookie")
	}
}
