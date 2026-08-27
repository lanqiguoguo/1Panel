package middleware

import (
	"net/http"
	"runtime/debug"

	"github.com/1Panel-dev/1Panel/backend/constant"
	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/1Panel-dev/1Panel/backend/i18n"

	"github.com/gin-gonic/gin"
)

// Recovery catches panics thrown by handlers and middlewares so that a single
// request can never take down the whole panel process. The full stack trace is
// written to the log for diagnosis, while the client only receives a generic
// 500 response with no panic details (stack traces may leak file paths,
// variable values and memory contents).
func Recovery() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				if global.LOG != nil {
					global.LOG.Errorf("panic recovered, path: %s, err: %v\n%s", c.Request.URL.Path, err, string(debug.Stack()))
				}
				message := i18n.GetMsgByKeyForCmd(constant.ErrTypeInternalServer)
				if message == "" {
					message = constant.ErrTypeInternalServer
				}
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
					"code":    constant.CodeErrInternalServer,
					"message": message,
					"data":    nil,
				})
			}
		}()
		c.Next()
	}
}
