package service

import (
	"strconv"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/app/model"
	"github.com/1Panel-dev/1Panel/backend/constant"
	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/1Panel-dev/1Panel/backend/init/cache/badger_db"
	"github.com/1Panel-dev/1Panel/backend/init/session/psession"
	jwtUtils "github.com/1Panel-dev/1Panel/backend/utils/jwt"
	"github.com/dgraph-io/badger/v4"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

// setupJWTRevocationTest wires the full production shape used by the JWT
// revocation flow: in-memory sqlite settings (signing key + version row),
// badger session store, the process-local version tracker and the clean hook
// that binds SESSION.Clean to the version bump (mirroring session.Init).
func setupJWTRevocationTest(t *testing.T) {
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
		{Key: "JWTSigningKey", Value: "unit-test-jwt-signing-key"},
		{Key: global.JWTVersionSettingKey, Value: "1"},
		{Key: "SecurityEntrance", Value: "entrance-1"},
		{Key: "UserName", Value: "admin"},
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
	global.JWTVER = &global.JWTRefreshVersion{}
	// same wiring as init/session/session.go
	global.SESSION.SetCleanHook(func() {
		_ = global.JWTVER.Bump(global.DB)
	})
	t.Cleanup(func() { global.JWTVER = nil })
}

func storedJWTRefreshVersion(t *testing.T) int64 {
	t.Helper()
	setting, err := settingRepo.Get(settingRepo.WithByKey(global.JWTVersionSettingKey))
	if err != nil {
		t.Fatalf("read JWT refresh version failed: %v", err)
	}
	version, err := strconv.ParseInt(setting.Value, 10, 64)
	if err != nil {
		t.Fatalf("parse JWT refresh version %q failed: %v", setting.Value, err)
	}
	return version
}

func jwtLoginToken(t *testing.T, u *AuthService) string {
	t.Helper()
	c, _ := newAuthTestContext(t)
	info, err := u.generateSession(c, "admin", constant.AuthMethodJWT)
	if err != nil {
		t.Fatalf("generateSession(jwt) failed: %v", err)
	}
	if info.Token == "" {
		t.Fatal("generateSession(jwt) returned no token")
	}
	return info.Token
}

// TestJWTLoginTokenCarriesCurrentVersion: a token minted by the real login
// path must embed the current JWT session version in its claims, so the
// middleware revocation check operates on the stored row's value.
func TestJWTLoginTokenCarriesCurrentVersion(t *testing.T) {
	setupJWTRevocationTest(t)
	token := jwtLoginToken(t, &AuthService{})
	claims, err := jwtUtils.NewJWT().ParseToken(token)
	if err != nil {
		t.Fatalf("freshly issued token rejected: %v", err)
	}
	if claims.SV != 1 {
		t.Fatalf("token SV = %d, want 1 (seeded version)", claims.SV)
	}
	// after a clean, a new login must embed the bumped version
	if err := global.SESSION.Clean(); err != nil {
		t.Fatal(err)
	}
	token = jwtLoginToken(t, &AuthService{})
	claims, err = jwtUtils.NewJWT().ParseToken(token)
	if err != nil {
		t.Fatalf("token issued after clean rejected: %v", err)
	}
	if claims.SV != 2 {
		t.Fatalf("token SV after clean = %d, want 2", claims.SV)
	}
}

// TestJWTRevocationAfterSessionClean pins the core contract: a JWT issued
// before SESSION.Clean stops validating afterwards, the settings row is
// bumped, and a token issued after the clean works again.
func TestJWTRevocationAfterSessionClean(t *testing.T) {
	setupJWTRevocationTest(t)
	u := &AuthService{}

	oldToken := jwtLoginToken(t, u)
	if _, err := jwtUtils.NewJWT().ParseToken(oldToken); err != nil {
		t.Fatalf("freshly issued token rejected: %v", err)
	}

	if err := global.SESSION.Clean(); err != nil {
		t.Fatalf("SESSION.Clean failed: %v", err)
	}
	if got := storedJWTRefreshVersion(t); got != 2 {
		t.Fatalf("stored JWT refresh version after Clean = %d, want 2", got)
	}
	if _, err := jwtUtils.NewJWT().ParseToken(oldToken); err == nil {
		t.Fatal("token issued before SESSION.Clean still validates")
	}

	newToken := jwtLoginToken(t, u)
	if _, err := jwtUtils.NewJWT().ParseToken(newToken); err != nil {
		t.Fatalf("token issued after SESSION.Clean rejected: %v", err)
	}
}

// TestSessionCleanBumpsEveryCall: every Clean revokes again (monotonic), so
// a token issued between two cleans is invalidated by the second one.
func TestSessionCleanBumpsEveryCall(t *testing.T) {
	setupJWTRevocationTest(t)
	u := &AuthService{}

	if err := global.SESSION.Clean(); err != nil {
		t.Fatal(err)
	}
	tokenBetween := jwtLoginToken(t, u)
	if _, err := jwtUtils.NewJWT().ParseToken(tokenBetween); err != nil {
		t.Fatalf("token between cleans rejected: %v", err)
	}
	if err := global.SESSION.Clean(); err != nil {
		t.Fatal(err)
	}
	if got := storedJWTRefreshVersion(t); got != 3 {
		t.Fatalf("stored version after two cleans = %d, want 3", got)
	}
	if _, err := jwtUtils.NewJWT().ParseToken(tokenBetween); err == nil {
		t.Fatal("token issued between cleans still validates after the second clean")
	}
}

// TestSettingUpdateSensitiveKeysBumpVersion drives the real setting-update
// call sites: SecurityEntrance, BindDomain and UserName changes go through
// SESSION.Clean and must bump the JWT version; a neutral setting
// (SessionTimeout) must not.
func TestSettingUpdateSensitiveKeysBumpVersion(t *testing.T) {
	setupJWTRevocationTest(t)
	u := &SettingService{}

	oldToken := jwtLoginToken(t, &AuthService{})

	// neutral update: no session clean, no version bump, token survives
	if err := u.Update("SessionTimeout", "3600"); err != nil {
		t.Fatalf("Update(SessionTimeout) failed: %v", err)
	}
	if got := storedJWTRefreshVersion(t); got != 1 {
		t.Fatalf("neutral update bumped version to %d, want 1", got)
	}
	if _, err := jwtUtils.NewJWT().ParseToken(oldToken); err != nil {
		t.Fatalf("token rejected after neutral setting update: %v", err)
	}

	for _, kv := range []struct{ key, value string }{
		{"SecurityEntrance", "entrance-2"},
		{"BindDomain", "panel.example.com"},
		{"UserName", "admin"},
	} {
		if err := u.Update(kv.key, kv.value); err != nil {
			t.Fatalf("Update(%q) failed: %v", kv.key, err)
		}
		if _, err := jwtUtils.NewJWT().ParseToken(oldToken); err == nil {
			t.Fatalf("token still validates after Update(%q)", kv.key)
		}
	}
	if got := storedJWTRefreshVersion(t); got != 4 {
		t.Fatalf("stored version after three sensitive updates = %d, want 4", got)
	}
}
