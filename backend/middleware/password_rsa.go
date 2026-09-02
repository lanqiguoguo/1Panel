package middleware

import (
	"encoding/base64"

	"github.com/1Panel-dev/1Panel/backend/app/service"
	"github.com/gin-gonic/gin"
)

// getPasswordPublicKeyPEM loads the PASSWORD_PUBLIC_KEY the frontend encrypts
// login passwords against, materialising it from the private key when the row
// is missing so the login page always gets a key that pairs with the private
// key the login handler can decrypt (see service/password_rsa_store.go).
func getPasswordPublicKeyPEM() string {
	return service.LoadPasswordPublicKeyPEM()
}

func SetPasswordPublicKey() gin.HandlerFunc {
	return func(c *gin.Context) {
		cookieKey, _ := c.Cookie("panel_public_key")
		key := getPasswordPublicKeyPEM()
		base64Key := base64.StdEncoding.EncodeToString([]byte(key))
		if base64Key == cookieKey {
			c.Next()
			return
		}
		c.SetCookie("panel_public_key", base64Key, 7*24*60*60, "/", "", c.Request.TLS != nil, false)
		c.Next()
	}
}
