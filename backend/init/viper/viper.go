package viper

import (
	"bytes"
	"fmt"
	"os"
	"path"
	"strings"
	"syscall"

	"github.com/1Panel-dev/1Panel/backend/configs"
	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/1Panel-dev/1Panel/backend/utils/cmd"
	"github.com/1Panel-dev/1Panel/backend/utils/files"
	"github.com/1Panel-dev/1Panel/cmd/server/conf"
	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

func Init() {
	baseDir := "/opt"
	port := "9999"
	mode := ""
	version := "v1.0.0"
	username, password, entrance, language := "", "", "", "zh"
	fileOp := files.NewFileOp()
	v := viper.NewWithOptions()
	v.SetConfigType("yaml")

	config := configs.ServerConfig{}
	if err := yaml.Unmarshal(conf.AppYaml, &config); err != nil {
		panic(err)
	}
	if config.System.Mode != "" {
		mode = config.System.Mode
	}
	if mode == "dev" && fileOp.Stat("/opt/1panel/conf/app.yaml") {
		v.SetConfigName("app")
		v.AddConfigPath(path.Join("/opt/1panel/conf"))
		if err := v.ReadInConfig(); err != nil {
			panic(fmt.Errorf("Fatal error config file: %s \n", err))
		}
	} else {
		baseDir = loadParams("BASE_DIR")
		port = loadParams("ORIGINAL_PORT")
		version = loadParams("ORIGINAL_VERSION")
		username = loadParams("ORIGINAL_USERNAME")
		password = loadOptionalParam("ORIGINAL_PASSWORD")
		if initialPassword, err := loadInitialPassword(baseDir); err != nil {
			panic(err)
		} else if initialPassword != "" {
			password = initialPassword
		}
		if password == "" {
			if err := ensureExistingDatabase(baseDir); err != nil {
				panic(err)
			}
		}
		entrance = loadParams("ORIGINAL_ENTRANCE")
		language = loadParams("LANGUAGE")

		reader := bytes.NewReader(conf.AppYaml)
		if err := v.ReadConfig(reader); err != nil {
			panic(fmt.Errorf("Fatal error config file: %s \n", err))
		}
	}
	v.OnConfigChange(func(e fsnotify.Event) {
		if err := v.Unmarshal(&global.CONF); err != nil {
			panic(err)
		}
	})
	serverConfig := configs.ServerConfig{}
	if err := v.Unmarshal(&serverConfig); err != nil {
		panic(err)
	}
	if mode == "dev" && fileOp.Stat("/opt/1panel/conf/app.yaml") {
		if serverConfig.System.BaseDir != "" {
			baseDir = serverConfig.System.BaseDir
		}
		if serverConfig.System.Port != "" {
			port = serverConfig.System.Port
		}
		if serverConfig.System.Version != "" {
			version = serverConfig.System.Version
		}
		if serverConfig.System.Username != "" {
			username = serverConfig.System.Username
		}
		if serverConfig.System.Password != "" {
			password = serverConfig.System.Password
		}
		if serverConfig.System.Entrance != "" {
			entrance = serverConfig.System.Entrance
		}
		if serverConfig.System.IsIntl {
			language = "en"
		}
	}

	global.CONF = serverConfig
	global.CONF.System.BaseDir = baseDir
	global.CONF.System.IsDemo = v.GetBool("system.is_demo")
	global.CONF.System.IsIntl = v.GetBool("system.is_intl")
	global.CONF.System.DataDir = path.Join(global.CONF.System.BaseDir, "1panel")
	global.CONF.System.Cache = path.Join(global.CONF.System.DataDir, "cache")
	global.CONF.System.Backup = path.Join(global.CONF.System.DataDir, "backup")
	global.CONF.System.DbPath = path.Join(global.CONF.System.DataDir, "db")
	global.CONF.System.LogPath = path.Join(global.CONF.System.DataDir, "log")
	global.CONF.System.TmpDir = path.Join(global.CONF.System.DataDir, "tmp")
	global.CONF.System.Port = port
	global.CONF.System.Version = version
	global.CONF.System.Username = username
	global.CONF.System.Password = password
	global.CONF.System.Entrance = entrance
	global.CONF.System.Language = language
	global.CONF.System.ChangeUserInfo = loadChangeInfo()
	global.Viper = v
}

func loadParams(param string) string {
	stdout, err := cmd.Execf("grep '^%s=' /usr/local/bin/1pctl | cut -d'=' -f2", param)
	if err != nil {
		panic(err)
	}
	info := strings.ReplaceAll(stdout, "\n", "")
	if len(info) == 0 || info == `""` {
		panic(fmt.Sprintf("error `%s` find in /usr/local/bin/1pctl", param))
	}
	return info
}

func loadOptionalParam(param string) string {
	stdout, err := cmd.Execf("grep '^%s=' /usr/local/bin/1pctl | cut -d'=' -f2", param)
	if err != nil {
		return ""
	}
	return strings.ReplaceAll(stdout, "\n", "")
}

// loadInitialPassword reads the bootstrap credential written by install.sh.
// It is deliberately accepted only from a root-owned 0600 regular file.
func loadInitialPassword(baseDir string) (string, error) {
	secretPath := path.Join(baseDir, "1panel", "conf", "initial-password")
	info, err := os.Lstat(secretPath)
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("stat initial panel password failed: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return "", fmt.Errorf("initial panel password has insecure file mode: %s", secretPath)
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && stat.Uid != 0 {
		return "", fmt.Errorf("initial panel password is not owned by root: %s", secretPath)
	}
	data, err := os.ReadFile(secretPath)
	if err != nil {
		return "", fmt.Errorf("read initial panel password failed: %w", err)
	}
	password := strings.TrimSuffix(string(data), "\n")
	if password == "" {
		return "", fmt.Errorf("initial panel password is empty: %s", secretPath)
	}
	return password, nil
}

func ensureExistingDatabase(baseDir string) error {
	dbPath := path.Join(baseDir, "1panel", "db", "1Panel.db")
	info, err := os.Stat(dbPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("initial panel password is missing: %s", path.Join(baseDir, "1panel", "conf", "initial-password"))
		}
		return fmt.Errorf("stat panel database failed: %w", err)
	}
	if info.IsDir() || info.Size() == 0 {
		return fmt.Errorf("panel database is not initialized: %s", dbPath)
	}
	return nil
}

// CleanupInitialPassword removes the one-time bootstrap credential after the
// database migration has persisted its encrypted form.
func CleanupInitialPassword(baseDir string) error {
	secretPath := path.Join(baseDir, "1panel", "conf", "initial-password")
	if err := os.Remove(secretPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove initial panel password failed: %w", err)
	}
	return nil
}

func loadChangeInfo() string {
	stdout, err := cmd.Exec("grep '^CHANGE_USER_INFO=' /usr/local/bin/1pctl | cut -d'=' -f2")
	if err != nil {
		return ""
	}
	return strings.ReplaceAll(stdout, "\n", "")
}
