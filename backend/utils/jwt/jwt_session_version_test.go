package jwt

import (
	"testing"
	"time"

	"github.com/1Panel-dev/1Panel/backend/app/model"
	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/glebarez/sqlite"
	"github.com/golang-jwt/jwt/v4"
	"gorm.io/gorm"
)

// setupJWTTest prepares an in-memory sqlite DB seeded with the JWT signing
// key and the JWT refresh-version row (version 1), plus the process-local
// version tracker, mirroring the runtime wiring in server.Start +
// session.Init.
func setupJWTTest(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open in-memory sqlite failed: %v", err)
	}
	if err := db.AutoMigrate(&model.Setting{}); err != nil {
		t.Fatalf("migrate settings failed: %v", err)
	}
	seeds := []model.Setting{
		{Key: "JWTSigningKey", Value: "unit-test-jwt-signing-key"},
		{Key: global.JWTVersionSettingKey, Value: "1"},
	}
	for i := range seeds {
		if err := db.Create(&seeds[i]).Error; err != nil {
			t.Fatalf("seed setting %s failed: %v", seeds[i].Key, err)
		}
	}
	global.DB = db
	global.JWTVER = &global.JWTRefreshVersion{}
	t.Cleanup(func() { global.JWTVER = nil })
	return db
}

// mintToken issues a token with an explicit SV, signing with the seeded key.
func mintToken(t *testing.T, sv int64) string {
	t.Helper()
	j := NewJWT()
	claims := j.CreateClaims(BaseClaims{Name: "admin"})
	claims.SV = sv
	token, err := j.CreateToken(claims)
	if err != nil {
		t.Fatalf("CreateToken failed: %v", err)
	}
	return token
}

// TestParseTokenAcceptsMatchingVersion: a token whose SV equals the current
// version must validate.
func TestParseTokenAcceptsMatchingVersion(t *testing.T) {
	setupJWTTest(t)
	token := mintToken(t, 1)
	if _, err := NewJWT().ParseToken(token); err != nil {
		t.Fatalf("ParseToken rejected a token with the current version: %v", err)
	}
}

// TestParseTokenRejectsStaleVersion: after the version bumps, a token minted
// under the previous version must be rejected.
func TestParseTokenRejectsStaleVersion(t *testing.T) {
	setupJWTTest(t)
	token := mintToken(t, 1)
	// bump the version the same way SESSION.Clean does
	if err := global.JWTVER.Bump(global.DB); err != nil {
		t.Fatalf("Bump failed: %v", err)
	}
	if _, err := NewJWT().ParseToken(token); err == nil {
		t.Fatal("ParseToken accepted a token minted before the version bump")
	}
	// a token minted under the new version validates again
	if _, err := NewJWT().ParseToken(mintToken(t, 2)); err != nil {
		t.Fatal("ParseToken rejected a token minted under the current version")
	}
}

// TestParseTokenRejectsLegacyTokenWithoutSV: tokens signed by releases
// before the SV claim existed carry no version (0). With the row seeded at
// version 1 they must be rejected — upgrading invalidates every outstanding
// JWT, which is the safe direction (the frontend never uses JWT).
func TestParseTokenRejectsLegacyTokenWithoutSV(t *testing.T) {
	setupJWTTest(t)
	j := NewJWT()
	claims := j.CreateClaims(BaseClaims{Name: "admin"})
	claims.SV = 0 // simulates a pre-upgrade token (no sv claim)
	token, err := j.CreateToken(claims)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.ParseToken(token); err == nil {
		t.Fatal("ParseToken accepted a legacy token without an SV claim")
	}
}

// TestParseTokenStillRejectsExpired: the pre-existing expiry behavior must
// be preserved for tokens that carry a matching version.
func TestParseTokenStillRejectsExpired(t *testing.T) {
	setupJWTTest(t)
	j := NewJWT()
	claims := j.CreateClaims(BaseClaims{Name: "admin"})
	// force expiry in the past while keeping a matching SV
	claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Hour))
	token, err := j.CreateToken(claims)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.ParseToken(token); err == nil {
		t.Fatal("ParseToken accepted an expired token")
	}
}
