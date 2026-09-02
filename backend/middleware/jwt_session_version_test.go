package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/app/model"
	"github.com/1Panel-dev/1Panel/backend/constant"
	"github.com/1Panel-dev/1Panel/backend/global"
	jwtUtils "github.com/1Panel-dev/1Panel/backend/utils/jwt"
	"github.com/gin-gonic/gin"
)

// setupJwtAuthTest wires the process-local JWT version tracker and a seeded
// version row so the JwtAuth revocation check runs against a real version
// (not the nil-tracker default).
func setupJwtAuthTest(t *testing.T) {
	t.Helper()
	setupSessionAuthTest(t)
	if err := global.DB.Create(&model.Setting{Key: global.JWTVersionSettingKey, Value: "1"}).Error; err != nil {
		t.Fatalf("seed JWT refresh version failed: %v", err)
	}
	if err := global.DB.Create(&model.Setting{Key: "JWTSigningKey", Value: "unit-test-jwt-signing-key"}).Error; err != nil {
		t.Fatalf("seed JWT signing key failed: %v", err)
	}
	global.JWTVER = &global.JWTRefreshVersion{}
	t.Cleanup(func() { global.JWTVER = nil })
}

func mintSignedToken(t *testing.T, sv int64) string {
	t.Helper()
	j := jwtUtils.NewJWT()
	claims := j.CreateClaims(jwtUtils.BaseClaims{Name: "admin"})
	claims.SV = sv
	token, err := j.CreateToken(claims)
	if err != nil {
		t.Fatalf("mint token failed: %v", err)
	}
	return token
}

func doJwtAuthRequest(t *testing.T, header string) (handled bool, body []byte) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	handled = false
	r := gin.New()
	r.Use(JwtAuth())
	r.GET("/protected", func(c *gin.Context) {
		handled = true
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	if header != "" {
		req.Header.Set(constant.JWTHeaderName, header)
	}
	r.ServeHTTP(w, req)
	return handled, w.Body.Bytes()
}

// TestJwtAuthRejectsStaleVersionToken drives the middleware end to end: a
// token carrying the previous session version must be refused with 401 even
// though its signature is valid, while a current-version token passes.
func TestJwtAuthRejectsStaleVersionToken(t *testing.T) {
	setupJwtAuthTest(t)

	// valid token at the current version: passes
	if handled, _ := doJwtAuthRequest(t, mintSignedToken(t, 1)); !handled {
		t.Fatal("handler did not run for a current-version token")
	}

	// bump the version the way SESSION.Clean does
	if err := global.JWTVER.Bump(global.DB); err != nil {
		t.Fatal(err)
	}

	oldToken := mintSignedToken(t, 1)
	handled, body := doJwtAuthRequest(t, oldToken)
	if handled {
		t.Fatal("handler ran for a token minted before the version bump")
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

	// a token minted under the new version passes again
	if handled, _ := doJwtAuthRequest(t, mintSignedToken(t, 2)); !handled {
		t.Fatal("handler did not run for a current-version token after bump")
	}
}

// TestJwtAuthRejectsLegacyToken: a token without any SV claim (pre-upgrade
// format) must be refused once the version row exists.
func TestJwtAuthRejectsLegacyToken(t *testing.T) {
	setupJwtAuthTest(t)
	handled, _ := doJwtAuthRequest(t, mintSignedToken(t, 0))
	if handled {
		t.Fatal("handler ran for a legacy token without an SV claim")
	}
}

// TestJwtAuthNoHeaderPassesThrough: requests without the JWT header must be
// untouched by JwtAuth (the session path downstream handles them).
func TestJwtAuthNoHeaderPassesThrough(t *testing.T) {
	setupJwtAuthTest(t)
	handled, _ := doJwtAuthRequest(t, "")
	if !handled {
		t.Fatal("handler did not run for a request without the JWT header")
	}
}
