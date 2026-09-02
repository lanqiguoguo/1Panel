package jwt

import (
	"time"

	"github.com/1Panel-dev/1Panel/backend/app/repo"
	"github.com/1Panel-dev/1Panel/backend/constant"
	"github.com/1Panel-dev/1Panel/backend/global"

	"github.com/golang-jwt/jwt/v4"
)

type JWT struct {
	SigningKey []byte
}

type JwtRequest struct {
	BaseClaims
	BufferTime int64
	// SV mirrors CustomClaims.SV so ParseToken (which unmarshals into
	// JwtRequest) can compare the token's baked-in session version against
	// the current one.
	SV int64 `json:"sv"`
	jwt.RegisteredClaims
}

type CustomClaims struct {
	BaseClaims
	BufferTime int64
	// SV is the JWT session version baked into the token at issue time.
	// Tokens whose SV does not match the current JWTRefreshVersion setting
	// are rejected by ParseToken, which is what makes revocation possible:
	// bumping the setting (every SESSION.Clean does) invalidates every token
	// minted before the bump. Tokens issued by releases before this field
	// existed carry no SV and parse as 0.
	SV int64 `json:"sv"`
	jwt.RegisteredClaims
}

type BaseClaims struct {
	ID   uint
	Name string
}

func NewJWT() *JWT {
	settingRepo := repo.NewISettingRepo()
	jwtSign, err := settingRepo.Get(settingRepo.WithByKey("JWTSigningKey"))
	if err != nil || jwtSign.Value == "" {
		// HS256 with an empty key would let anyone forge valid tokens. The
		// key is created by the init migration, so a missing row means a
		// broken database: refuse to boot into an insecure state instead of
		// failing open (same fail-fast style as RandStrSecure).
		panic("jwt signing key is missing")
	}
	return &JWT{
		[]byte(jwtSign.Value),
	}
}

func (j *JWT) CreateClaims(baseClaims BaseClaims) CustomClaims {
	claims := CustomClaims{
		BaseClaims: baseClaims,
		BufferTime: constant.JWTBufferTime,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Second * time.Duration(constant.JWTBufferTime))),
			Issuer:    constant.JWTIssuer,
		},
	}
	// Embed the current JWT session version. The version row may not exist
	// yet on very old installations whose migration never ran; reading it as
	// DefaultJWTRefreshVersion keeps the token comparable to the version a
	// later bump starts from.
	if global.JWTVER != nil {
		claims.SV = global.JWTVER.Version(global.DB)
	}
	if claims.SV <= 0 {
		claims.SV = constant.DefaultJWTRefreshVersion
	}
	return claims
}

func (j *JWT) CreateToken(request CustomClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, &request)
	return token.SignedString(j.SigningKey)
}

func (j *JWT) ParseToken(tokenStr string) (*JwtRequest, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &JwtRequest{}, func(token *jwt.Token) (interface{}, error) {
		return j.SigningKey, nil
	})
	if err != nil || token == nil {
		return nil, constant.ErrTokenParse
	}
	if claims, ok := token.Claims.(*JwtRequest); ok && token.Valid {
		// Revocation check: a token minted before the current JWT session
		// version (e.g. before a password/user-name/MFA/entrance change, or
		// before this release shipped) must be rejected. The read is served
		// from an in-process cache with a short TTL, so no per-request query
		// is issued.
		var current int64 = constant.DefaultJWTRefreshVersion
		if global.JWTVER != nil {
			current = global.JWTVER.Version(global.DB)
		}
		if claims.SV != current {
			return nil, constant.ErrTokenParse
		}
		return claims, nil
	}
	return nil, constant.ErrTokenParse
}
