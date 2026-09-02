package session

import (
	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/1Panel-dev/1Panel/backend/init/session/psession"
)

func Init() {
	global.SESSION = psession.NewPSession(global.CACHE)
	// Every SESSION.Clean (password/user-name/MFA/security-entrance changes)
	// also bumps the JWT refresh version, so session cookies and already
	// issued JWTs are revoked together. global.JWTVER is created before this
	// init runs (see db.Init).
	if global.JWTVER != nil {
		global.SESSION.SetCleanHook(func() {
			_ = global.JWTVER.Bump(global.DB)
		})
	}
	global.LOG.Info("init session successfully")
}
