package compose

import (
	"sync"

	"github.com/1Panel-dev/1Panel/backend/utils/cmd"
)

var (
	mu           sync.Mutex
	composeCmdV2 bool
	resolved     bool
)

// command returns the compose invocation matching the host docker edition:
// modern releases bundle the v2 plugin (`docker compose`), while older or
// standalone setups only ship the legacy `docker-compose` binary. Probe once
// per process and cache the result; default to the v2 plugin, falling back to
// the legacy binary when the plugin is missing.
//
// The probe only inspects the error's identity (nil or not) — never its text.
// buserr's Error() renders through i18n, whose localizer is only wired up by
// the HTTP middleware, so calling it from a background goroutine panics.
func command() string {
	mu.Lock()
	defer mu.Unlock()
	if resolved {
		if composeCmdV2 {
			return "docker compose"
		}
		return "docker-compose"
	}
	if _, err := cmd.Exec("docker compose version"); err == nil {
		composeCmdV2 = true
	} else if _, err := cmd.Exec("docker-compose version"); err == nil {
		composeCmdV2 = false
	} else {
		// neither works right now (docker restarting, fresh host); prefer the
		// modern plugin so the error surfaced to the user tracks current docker
		composeCmdV2 = true
	}
	resolved = true
	if composeCmdV2 {
		return "docker compose"
	}
	return "docker-compose"
}

func Pull(filePath string) (string, error) {
	stdout, err := cmd.Execf("%s -f %s pull", command(), filePath)
	return stdout, err
}

func Up(filePath string) (string, error) {
	stdout, err := cmd.Execf("%s -f %s up -d", command(), filePath)
	return stdout, err
}

func Down(filePath string) (string, error) {
	stdout, err := cmd.Execf("%s -f %s down --remove-orphans", command(), filePath)
	return stdout, err
}

func Start(filePath string) (string, error) {
	stdout, err := cmd.Execf("%s -f %s start", command(), filePath)
	return stdout, err
}

func Stop(filePath string) (string, error) {
	stdout, err := cmd.Execf("%s -f %s stop", command(), filePath)
	return stdout, err
}

func Restart(filePath string) (string, error) {
	stdout, err := cmd.Execf("%s -f %s restart", command(), filePath)
	return stdout, err
}

func Operate(filePath, operation string) (string, error) {
	stdout, err := cmd.Execf("%s -f %s %s", command(), filePath, operation)
	return stdout, err
}
