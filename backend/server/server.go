package server

import (
	"crypto/tls"
	"encoding/gob"
	"fmt"
	"net"
	"net/http"
	"os"
	"path"

	"github.com/1Panel-dev/1Panel/backend/constant"
	"github.com/1Panel-dev/1Panel/backend/i18n"

	"github.com/1Panel-dev/1Panel/backend/init/app"
	"github.com/1Panel-dev/1Panel/backend/init/auth"
	"github.com/1Panel-dev/1Panel/backend/init/business"
	"github.com/1Panel-dev/1Panel/backend/init/lang"

	"github.com/1Panel-dev/1Panel/backend/cron"
	"github.com/1Panel-dev/1Panel/backend/init/cache"
	"github.com/1Panel-dev/1Panel/backend/init/session"
	"github.com/1Panel-dev/1Panel/backend/init/session/psession"

	"github.com/1Panel-dev/1Panel/backend/app/service"
	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/1Panel-dev/1Panel/backend/init/db"
	"github.com/1Panel-dev/1Panel/backend/init/hook"
	"github.com/1Panel-dev/1Panel/backend/init/log"
	"github.com/1Panel-dev/1Panel/backend/init/migration"
	"github.com/1Panel-dev/1Panel/backend/init/router"
	"github.com/1Panel-dev/1Panel/backend/init/validator"
	"github.com/1Panel-dev/1Panel/backend/init/viper"

	"github.com/gin-gonic/gin"
)

func Start() {
	viper.Init()
	i18n.Init()
	i18n.UseI18nForCmd("")
	log.Init()
	db.Init()
	migration.Init()
	// JWT session-version tracker: must exist before session.Init() wires it
	// into SESSION.Clean (every clean bumps the JWT version). It only touches
	// the database lazily through global.DB, which db.Init has set.
	global.JWTVER = &global.JWTRefreshVersion{}
	if err := viper.CleanupInitialPassword(global.CONF.System.BaseDir); err != nil {
		global.LOG.Warnf("cleanup initial panel password failed: %v", err)
	}
	app.Init()
	service.InitProxyConfig()
	lang.Init()
	validator.Init()
	gob.Register(psession.SessionUser{})
	cache.Init()
	session.Init()
	if global.CONF.System.Mode == "dev" {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}
	cron.Run()
	hook.Init()
	InitOthers()
	business.Init()

	rootRouter := router.Routers()
	global.IPTracker = auth.NewIPTracker()

	tcpItem := "tcp4"
	if global.CONF.System.Ipv6 == "enable" {
		tcpItem = "tcp"
		global.CONF.System.BindAddress = fmt.Sprintf("[%s]", global.CONF.System.BindAddress)
	}
	server := &http.Server{
		Addr:    global.CONF.System.BindAddress + ":" + global.CONF.System.Port,
		Handler: rootRouter,
	}
	ln, err := net.Listen(tcpItem, server.Addr)
	if err != nil {
		panic(err)
	}
	type tcpKeepAliveListener struct {
		*net.TCPListener
	}
	if global.CONF.System.SSL == "enable" {
		certPath := path.Join(global.CONF.System.BaseDir, "1panel/secret/server.crt")
		keyPath := path.Join(global.CONF.System.BaseDir, "1panel/secret/server.key")
		certificate, err := os.ReadFile(certPath)
		if err != nil {
			panic(err)
		}
		key, err := os.ReadFile(keyPath)
		if err != nil {
			panic(err)
		}
		cert, err := tls.X509KeyPair(certificate, key)
		if err != nil {
			panic(err)
		}
		constant.CertStore.Store(&cert)

		server.TLSConfig = &tls.Config{
			GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
				return constant.CertStore.Load().(*tls.Certificate), nil
			},
		}
		global.LOG.Infof("listen at https://%s:%s [%s]", global.CONF.System.BindAddress, global.CONF.System.Port, tcpItem)

		if err := server.ServeTLS(tcpKeepAliveListener{ln.(*net.TCPListener)}, "", ""); err != nil {
			panic(err)
		}
	} else {
		global.LOG.Infof("listen at http://%s:%s [%s]", global.CONF.System.BindAddress, global.CONF.System.Port, tcpItem)
		if err := server.Serve(tcpKeepAliveListener{ln.(*net.TCPListener)}); err != nil {
			panic(err)
		}
	}
}
