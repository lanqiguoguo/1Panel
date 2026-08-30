package helper

import (
	"context"
	"fmt"
	"github.com/1Panel-dev/1Panel/cmd/server/res"
	"net/http"
	"strconv"

	"github.com/1Panel-dev/1Panel/backend/global"
	"gorm.io/gorm"

	"github.com/1Panel-dev/1Panel/backend/app/dto"
	"github.com/1Panel-dev/1Panel/backend/buserr"
	"github.com/1Panel-dev/1Panel/backend/constant"
	"github.com/1Panel-dev/1Panel/backend/i18n"
	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
)

// logError writes the raw error to the global logger only. The logger is not
// initialized in unit tests, so a nil guard keeps the helper callable from
// test code; nil errors (call sites that pass no err) are not logged.
func logError(err error) {
	if err == nil || global.LOG == nil {
		return
	}
	global.LOG.Errorf("%v", err)
}

func ErrorWithDetail(ctx *gin.Context, code int, msgKey string, err error) {
	res := dto.Response{
		Code:    code,
		Message: "",
	}
	if msgKey == constant.ErrTypeInternalServer {
		switch {
		case errors.Is(err, constant.ErrRecordExist):
			res.Message = i18n.GetMsgWithMap("ErrRecordExist", nil)
		case errors.Is(err, constant.ErrRecordNotFound):
			res.Message = i18n.GetMsgWithMap("ErrRecordNotFound", nil)
		case errors.Is(err, constant.ErrInvalidParams):
			res.Message = i18n.GetMsgWithMap("ErrInvalidParams", nil)
		case errors.Is(err, constant.ErrStructTransform):
			// The raw error (it usually wraps copier.Copy/json errors that
			// can embed file paths) only goes to the log; the response stays
			// on the generic template without the detail.
			logError(err)
			res.Message = i18n.GetMsgWithMap("ErrStructTransform", nil)
		case errors.Is(err, constant.ErrCaptchaCode):
			res.Code = constant.CodeAuth
			res.Message = "ErrCaptchaCode"
		case errors.Is(err, constant.ErrAuth):
			res.Code = constant.CodeAuth
			res.Message = "ErrAuth"
		case errors.Is(err, constant.ErrInitialPassword):
			logError(err)
			res.Message = i18n.GetMsgWithMap("ErrInitialPassword", nil)
		case errors.As(err, &buserr.BusinessError{}):
			res.Message = err.Error()
		default:
			// Generic internal-server error: the raw err (file paths, SQL,
			// command output) goes to the log only, never into the response.
			logError(err)
			res.Message = i18n.GetMsgWithMap(msgKey, nil)
		}
	} else {
		// Non-internal message keys (e.g. ErrTypeInvalidParams): the raw err
		// can echo request content (malformed JSON bodies, validation
		// values), so it is logged instead of being spliced into the message.
		logError(err)
		res.Message = i18n.GetMsgWithMap(msgKey, nil)
	}
	ctx.JSON(http.StatusOK, res)
	ctx.Abort()
}

func SuccessWithData(ctx *gin.Context, data interface{}) {
	if data == nil {
		data = gin.H{}
	}
	res := dto.Response{
		Code: constant.CodeSuccess,
		Data: data,
	}
	ctx.JSON(http.StatusOK, res)
	ctx.Abort()
}

func SuccessWithOutData(ctx *gin.Context) {
	res := dto.Response{
		Code:    constant.CodeSuccess,
		Message: "success",
	}
	ctx.JSON(http.StatusOK, res)
	ctx.Abort()
}

func SuccessWithMsg(ctx *gin.Context, msg string) {
	res := dto.Response{
		Code:    constant.CodeSuccess,
		Message: msg,
	}
	ctx.JSON(http.StatusOK, res)
	ctx.Abort()
}

func GetParamID(c *gin.Context) (uint, error) {
	idParam, ok := c.Params.Get("id")
	if !ok {
		return 0, errors.New("error id in path")
	}
	intNum, err := strconv.Atoi(idParam)
	if err != nil {
		return 0, fmt.Errorf("invalid id param %q: %w", idParam, err)
	}
	return uint(intNum), nil
}

func GetIntParamByKey(c *gin.Context, key string) (uint, error) {
	idParam, ok := c.Params.Get(key)
	if !ok {
		return 0, fmt.Errorf("error %s in path", key)
	}
	intNum, err := strconv.Atoi(idParam)
	if err != nil {
		return 0, fmt.Errorf("invalid %s param %q: %w", key, idParam, err)
	}
	return uint(intNum), nil
}

func GetStrParamByKey(c *gin.Context, key string) (string, error) {
	idParam, ok := c.Params.Get(key)
	if !ok {
		return "", fmt.Errorf("error %s in path", key)
	}
	return idParam, nil
}

func GetTxAndContext() (tx *gorm.DB, ctx context.Context) {
	tx = global.DB.Begin()
	ctx = context.WithValue(context.Background(), constant.DB, tx)
	return
}

func CheckBindAndValidate(req interface{}, c *gin.Context) error {
	if err := c.ShouldBindJSON(req); err != nil {
		ErrorWithDetail(c, constant.CodeErrBadRequest, constant.ErrTypeInvalidParams, err)
		return err
	}
	if err := global.VALID.Struct(req); err != nil {
		ErrorWithDetail(c, constant.CodeErrBadRequest, constant.ErrTypeInvalidParams, err)
		return err
	}
	return nil
}

func CheckBind(req interface{}, c *gin.Context) error {
	if err := c.ShouldBindJSON(&req); err != nil {
		ErrorWithDetail(c, constant.CodeErrBadRequest, constant.ErrTypeInvalidParams, err)
		return err
	}
	return nil
}

func ErrWithHtml(ctx *gin.Context, code int, scope string) {
	if code == 444 {
		ctx.String(444, "")
		ctx.Abort()
		return
	}
	file := fmt.Sprintf("html/%d.html", code)
	if code == 200 && scope != "" {
		file = fmt.Sprintf("html/200_%s.html", scope)
	}
	data, err := res.ErrorMsg.ReadFile(file)
	if err != nil {
		ctx.String(http.StatusInternalServerError, "Internal Server Error")
		ctx.Abort()
		return
	}
	ctx.Data(code, "text/html; charset=utf-8", data)
	ctx.Abort()
}
