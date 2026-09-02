package constant

import "github.com/1Panel-dev/1Panel/backend/global"

const (
	AuthMethodSession = "session"
	SessionName       = "psession"

	AuthMethodJWT = "jwt"
	JWTHeaderName = "PanelAuthorization"
	JWTBufferTime = 3600
	JWTIssuer     = "1Panel"

	// JWTVersionSettingKey and DefaultJWTRefreshVersion are aliases of the
	// canonical values in global (global cannot import constant — constant/
	// dir.go imports global). Service and migration code addresses the JWT
	// session version through these names.
	JWTVersionSettingKey     = global.JWTVersionSettingKey
	DefaultJWTRefreshVersion = global.DefaultJWTRefreshVersion
	PasswordExpiredName      = "expired"
)
