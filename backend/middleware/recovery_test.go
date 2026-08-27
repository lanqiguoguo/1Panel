package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/constant"

	"github.com/gin-gonic/gin"
)

func TestRecoveryCatchesPanic(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(Recovery())
	r.GET("/panic", func(c *gin.Context) {
		var m map[string]string
		m["key"] = "value" // nil map write panics
		c.JSON(http.StatusOK, m)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/panic", nil)

	r.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusInternalServerError)
	}
}

func TestRecoveryResponseHasNoPanicDetails(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(Recovery())
	r.GET("/panic", func(c *gin.Context) {
		panic("secret-internal-detail")
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/panic", nil)

	r.ServeHTTP(w, req)

	body := w.Body.String()
	if strings.Contains(body, "secret-internal-detail") {
		t.Fatalf("response leaks panic detail: %s", body)
	}
	if strings.Contains(body, "panic recovered") || strings.Contains(body, "runtime/debug") {
		t.Fatalf("response leaks panic stack trace: %s", body)
	}

	var resp struct {
		Code int `json:"code"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response is not valid json: %v, body: %s", err, body)
	}
	if resp.Code != constant.CodeErrInternalServer {
		t.Fatalf("response code = %d, want %d", resp.Code, constant.CodeErrInternalServer)
	}
}

func TestRecoveryAllowsNormalRequests(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(Recovery())
	r.GET("/ok", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"code": 200})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/ok", nil)

	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
}
