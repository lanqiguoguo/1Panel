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

// resolve probes the host docker edition once per process and caches the
// result: modern releases bundle the v2 plugin (`docker compose`), while
// older or standalone setups only ship the legacy `docker-compose` binary.
// Default to the v2 plugin, falling back to the legacy binary when the
// plugin is missing.
func resolve() {
	mu.Lock()
	defer mu.Unlock()
	if resolved {
		return
	}
	// Probe success/failure only; never inspect err.Error() here: buserr
	// errors render through i18n and panic in background goroutines without an
	// HTTP localizer, and calling Error() on a nil error crashes outright.
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
}

// Command returns the compose invocation string matching the host docker
// edition, e.g. "docker compose" (v2 plugin) or "docker-compose" (legacy
// binary). It is safe to call concurrently.
func Command() string {
	resolve()
	mu.Lock()
	defer mu.Unlock()
	if composeCmdV2 {
		return "docker compose"
	}
	return "docker-compose"
}

// CommandArgs returns the arguments to run compose via its base binary: the
// v2 plugin needs "docker compose <args>" while the legacy binary is invoked
// directly, so it yields ["compose"] or [] respectively. Base binary is
// "docker" for v2, "docker-compose" for legacy; e.g. for logging:
//
//	bin, args := compose.CommandBase()   // or Command() + CommandArgs()
//	exec.Command(bin, append(args, "-f", path, "logs")...)
//
// Both results are cached after the first probe.
func CommandArgs() []string {
	resolve()
	mu.Lock()
	defer mu.Unlock()
	if composeCmdV2 {
		return []string{"compose"}
	}
	return []string{}
}

// CommandBase returns the binary to invoke compose with, "docker" (v2
// plugin) or "docker-compose" (legacy).
func CommandBase() string {
	resolve()
	mu.Lock()
	defer mu.Unlock()
	if composeCmdV2 {
		return "docker"
	}
	return "docker-compose"
}

func Pull(filePath string) (string, error) {
	stdout, err := cmd.Execf("%s -f %s pull", Command(), filePath)
	return stdout, err
}

func Up(filePath string) (string, error) {
	stdout, err := cmd.Execf("%s -f %s up -d", Command(), filePath)
	return stdout, err
}

func Down(filePath string) (string, error) {
	stdout, err := cmd.Execf("%s -f %s down --remove-orphans", Command(), filePath)
	return stdout, err
}

func Start(filePath string) (string, error) {
	stdout, err := cmd.Execf("%s -f %s start", Command(), filePath)
	return stdout, err
}

func Stop(filePath string) (string, error) {
	stdout, err := cmd.Execf("%s -f %s stop", Command(), filePath)
	return stdout, err
}

func Restart(filePath string) (string, error) {
	stdout, err := cmd.Execf("%s -f %s restart", Command(), filePath)
	return stdout, err
}

func Operate(filePath, operation string) (string, error) {
	stdout, err := cmd.Execf("%s -f %s %s", Command(), filePath, operation)
	return stdout, err
}
