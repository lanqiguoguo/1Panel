package v1

import (
	"encoding/base64"

	"github.com/1Panel-dev/1Panel/backend/app/api/v1/helper"
	"github.com/1Panel-dev/1Panel/backend/app/dto"
	"github.com/1Panel-dev/1Panel/backend/app/model"
	"github.com/1Panel-dev/1Panel/backend/constant"
	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/1Panel-dev/1Panel/backend/utils/captcha"
	"github.com/1Panel-dev/1Panel/backend/utils/common"
	"github.com/gin-gonic/gin"
)

type BaseApi struct{}

// @Tags Auth
// @Summary User login
// @Accept json
// @Param EntranceCode header string true "Secure entrance base64 encrypted string"
// @Param request body dto.Login true "request"
// @Success 200 {object} dto.UserLoginInfo
// @Router /auth/login [post]
func (b *BaseApi) Login(c *gin.Context) {
	var req dto.Login
	if err := helper.CheckBindAndValidate(&req, c); err != nil {
		return
	}

	ip := common.GetRealClientIP(c)
	needCaptcha := global.IPTracker.NeedCaptcha(ip)
	if needCaptcha {
		if err := captcha.VerifyCode(req.CaptchaID, req.Captcha); err != nil {
			helper.ErrorWithDetail(c, constant.CodeErrInternalServer, constant.ErrTypeInternalServer, err)
			return
		}
	}

	entranceItem := c.Request.Header.Get("EntranceCode")
	var entrance []byte
	if len(entranceItem) != 0 {
		entrance, _ = base64.StdEncoding.DecodeString(entranceItem)
	}
	if len(entrance) == 0 {
		cookieValue, err := c.Cookie("SecurityEntrance")
		if err == nil {
			entrance, _ = base64.StdEncoding.DecodeString(cookieValue)
		}
	}

	user, err := authService.Login(c, req, string(entrance))
	go saveLoginLogs(c, err)
	if err != nil {
		global.IPTracker.RecordFailure(ip)
		helper.ErrorWithDetail(c, constant.CodeErrInternalServer, constant.ErrTypeInternalServer, err)
		return
	}
	// Only a fully completed login (no pending MFA step) may clear the IP
	// tracker. When MFA is pending, no session was issued yet and the TOTP
	// step still needs rate limiting, so the failure counter must survive.
	if shouldClearTracker(user.MfaStatus) {
		global.IPTracker.Clear(ip)
	}
	helper.SuccessWithData(c, user)
}

// @Tags Auth
// @Summary User login with mfa
// @Accept json
// @Param request body dto.MFALogin true "request"
// @Success 200 {object} dto.UserLoginInfo
// @Router /auth/mfalogin [post]
// @Header 200 {string} EntranceCode
func (b *BaseApi) MFALogin(c *gin.Context) {
	var req dto.MFALogin
	if err := helper.CheckBindAndValidate(&req, c); err != nil {
		return
	}

	ip := common.GetRealClientIP(c)
	// When the IP is flagged by the failure tracker (e.g. 5 failed TOTP codes),
	// the user must solve a captcha to proceed. A correct captcha is itself the
	// unlock mechanism: it lets the request continue to the TOTP check instead
	// of locking the IP out for the whole ExpireDuration (30 min). Semantics
	// mirror the stage-1 Login handler; a failed captcha does not add to the
	// failure counter.
	if global.IPTracker.NeedCaptcha(ip) {
		if err := captcha.VerifyCode(req.CaptchaID, req.Captcha); err != nil {
			helper.ErrorWithDetail(c, constant.CodeErrInternalServer, constant.ErrTypeInternalServer, constant.ErrCaptchaCode)
			return
		}
	}

	entranceItem := c.Request.Header.Get("EntranceCode")
	var entrance []byte
	if len(entranceItem) != 0 {
		entrance, _ = base64.StdEncoding.DecodeString(entranceItem)
	}

	user, err := authService.MFALogin(c, req, string(entrance))
	if err != nil {
		global.IPTracker.RecordFailure(ip)
		helper.ErrorWithDetail(c, constant.CodeErrInternalServer, constant.ErrTypeInternalServer, err)
		return
	}
	global.IPTracker.Clear(ip)
	helper.SuccessWithData(c, user)
}

// @Tags Auth
// @Summary User logout
// @Success 200
// @Security ApiKeyAuth
// @Security Timestamp
// @Router /auth/logout [post]
func (b *BaseApi) LogOut(c *gin.Context) {
	if err := authService.LogOut(c); err != nil {
		helper.ErrorWithDetail(c, constant.CodeErrInternalServer, constant.ErrTypeInternalServer, err)
		return
	}
	helper.SuccessWithData(c, nil)
}

// @Tags Auth
// @Summary Load captcha
// @Success 200 {object} dto.CaptchaResponse
// @Router /auth/captcha [get]
func (b *BaseApi) Captcha(c *gin.Context) {
	captcha, err := captcha.CreateCaptcha()
	if err != nil {
		helper.ErrorWithDetail(c, constant.CodeErrInternalServer, constant.ErrTypeInternalServer, err)
		return
	}
	helper.SuccessWithData(c, captcha)
}

func (b *BaseApi) GetResponsePage(c *gin.Context) {
	pageCode, err := authService.GetResponsePage()
	if err != nil {
		helper.ErrorWithDetail(c, constant.CodeErrInternalServer, constant.ErrTypeInternalServer, err)
		return
	}
	helper.SuccessWithData(c, pageCode)
}

// @Tags Auth
// @Summary Check System isDemo
// @Success 200 {boolean} isDemo
// @Router /auth/demo [get]
func (b *BaseApi) CheckIsDemo(c *gin.Context) {
	helper.SuccessWithData(c, global.CONF.System.IsDemo)
}

// @Tags Auth
// @Summary Check System isIntl
// @Success 200 {boolean} isIntl
// @Router /auth/intl [get]
func (b *BaseApi) CheckIsIntl(c *gin.Context) {
	helper.SuccessWithData(c, global.CONF.System.IsIntl)
}

// @Tags Auth
// @Summary Load System Setting for login
// @Success 200 {object} dto.LoginSetting
// @Router /auth/setting [get]
func (b *BaseApi) GetAuthSetting(c *gin.Context) {
	settingInfo, err := settingService.GetSettingInfo()
	if err != nil {
		helper.ErrorWithDetail(c, constant.CodeErrInternalServer, constant.ErrTypeInternalServer, err)
		return
	}
	ip := common.GetRealClientIP(c)
	needCaptcha := global.IPTracker.NeedCaptcha(ip)
	helper.SuccessWithData(c, dto.LoginSetting{
		NeedCaptcha: needCaptcha,
		Language:    settingInfo.Language,
	})
}

func saveLoginLogs(c *gin.Context, err error) {
	var logs model.LoginLog
	if err != nil {
		logs.Status = constant.StatusFailed
		logs.Message = err.Error()
	} else {
		logs.Status = constant.StatusSuccess
	}
	logs.IP = c.ClientIP()
	logs.Agent = c.GetHeader("User-Agent")
	_ = logService.CreateLoginLog(logs)
}

// shouldClearTracker reports whether a successful stage-1 login finished the
// whole authentication. authService.Login returns a non-empty MfaStatus when
// the credentials were accepted but no session was issued yet (MFA pending).
// In that case the IP tracker state must be kept so the pending TOTP step
// stays rate limited; otherwise attackers could reset their failure counter
// by repeating stage-1 login.
func shouldClearTracker(mfaStatus string) bool {
	return mfaStatus == ""
}
