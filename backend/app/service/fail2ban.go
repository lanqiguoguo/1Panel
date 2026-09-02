package service

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/1Panel-dev/1Panel/backend/app/dto"
	"github.com/1Panel-dev/1Panel/backend/buserr"
	"github.com/1Panel-dev/1Panel/backend/constant"
	"github.com/1Panel-dev/1Panel/backend/utils/cmd"
	"github.com/1Panel-dev/1Panel/backend/utils/firewall"
	"github.com/1Panel-dev/1Panel/backend/utils/toolbox"
)

const defaultFail2BanPath = "/etc/fail2ban/jail.local"

type Fail2BanService struct{}

type IFail2BanService interface {
	LoadBaseInfo() (dto.Fail2BanBaseInfo, error)
	Search(search dto.Fail2BanSearch) ([]string, error)
	Operate(operation string) error
	OperateSSHD(req dto.Fail2BanSet) error
	UpdateConf(req dto.Fail2BanUpdate) error
	UpdateConfByFile(req dto.UpdateByFile) error
}

func NewIFail2BanService() IFail2BanService {
	return &Fail2BanService{}
}

func (u *Fail2BanService) LoadBaseInfo() (dto.Fail2BanBaseInfo, error) {
	var baseInfo dto.Fail2BanBaseInfo
	client, err := toolbox.NewFail2Ban()
	if err != nil {
		return baseInfo, err
	}
	baseInfo.IsEnable, baseInfo.IsActive, baseInfo.IsExist = client.Status()
	if !baseInfo.IsActive {
		baseInfo.Version = "-"
	} else {
		baseInfo.Version = client.Version()
	}
	conf, err := os.ReadFile(defaultFail2BanPath)
	if err != nil {
		if baseInfo.IsActive {
			return baseInfo, fmt.Errorf("read fail2ban conf of %s failed, err: %v", defaultFail2BanPath, err)
		} else {
			return baseInfo, nil
		}
	}
	lines := strings.Split(string(conf), "\n")

	block := ""
	for _, line := range lines {
		if strings.HasPrefix(strings.ToLower(line), "[default]") {
			block = "default"
			continue
		}
		if strings.HasPrefix(line, "[sshd]") {
			block = "sshd"
			continue
		}
		if strings.HasPrefix(line, "[") {
			block = ""
			continue
		}
		if block != "default" && block != "sshd" {
			continue
		}
		loadFailValue(line, &baseInfo)
	}

	return baseInfo, nil
}

func (u *Fail2BanService) Search(req dto.Fail2BanSearch) ([]string, error) {
	var list []string
	client, err := toolbox.NewFail2Ban()
	if err != nil {
		return nil, err
	}
	if req.Status == "banned" {
		list, err = client.ListBanned()

	} else {
		list, err = client.ListIgnore()
	}
	if err != nil {
		return nil, err
	}

	return list, nil
}

func (u *Fail2BanService) Operate(operation string) error {
	client, err := toolbox.NewFail2Ban()
	if err != nil {
		return err
	}
	return client.Operate(operation)
}

// writeFileAtomicWithBackup persists content to path with 0640 (keeping an
// existing file's owner), returning the previous bytes so the caller can
// restore them if the follow-up restart fails. A missing file is a valid old
// state: it yields a nil oldContent (and restore then removes the file
// again), mirroring the historical O_CREAT|O_TRUNC semantics of the callers.
func writeFileAtomicWithBackup(path string, content []byte) (oldContent []byte, err error) {
	oldContent, readErr := os.ReadFile(path)
	if readErr != nil && !os.IsNotExist(readErr) {
		return nil, fmt.Errorf("read %s failed before update, err: %v", path, readErr)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".jail.local-*.tmp")
	if err != nil {
		return nil, err
	}
	tmpName := tmp.Name()
	defer func() {
		_ = tmp.Close()
		if err != nil {
			_ = os.Remove(tmpName)
		}
	}()
	if err = tmp.Chmod(0640); err != nil {
		return nil, err
	}
	// Copy the original owner (root-owned files keep root after an atomic
	// rename; root is also the only user allowed to write this file).
	if info, statErr := os.Stat(path); statErr == nil {
		if sys, ok := info.Sys().(*syscall.Stat_t); ok {
			_ = tmp.Chown(int(sys.Uid), int(sys.Gid))
		}
	}
	if _, err = tmp.Write(content); err != nil {
		return nil, err
	}
	if err = tmp.Sync(); err != nil {
		return nil, err
	}
	if err = tmp.Close(); err != nil {
		return nil, err
	}
	if err = os.Rename(tmpName, path); err != nil {
		return nil, err
	}
	return oldContent, nil
}

// restoreFileContent puts the previous state of path back: writing oldContent
// when it is non-nil, removing the file when it is nil (the file was created
// by the failed update from a missing original).
func restoreFileContent(path string, oldContent []byte) error {
	if oldContent == nil {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	return os.WriteFile(path, oldContent, 0640)
}

// restoreFileAfterFailedRestart puts the previous state back after a restart
// failure and makes one best-effort restart attempt with the restored
// configuration. A single combined error is returned.
func restoreFileAfterFailedRestart(path string, oldContent []byte, restartErr error) error {
	var errs []string
	if restartErr != nil {
		errs = append(errs, restartErr.Error())
	}
	if err := restoreFileContent(path, oldContent); err != nil {
		errs = append(errs, fmt.Sprintf("restore original file failed: %v", err))
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	client, err := toolbox.NewFail2Ban()
	if err != nil {
		errs = append(errs, fmt.Sprintf("reload fail2ban after restore failed: %v", err))
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	if err := client.Operate("restart"); err != nil {
		errs = append(errs, fmt.Sprintf("restart fail2ban after restoring original file failed: %v", err))
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

// testFail2BanConf runs `fail2ban-client -t` against the already-written file
// (which is jail.local itself, included by jail.conf) so a syntactically
// broken config is rejected before any restart is attempted.
func testFail2BanConf() error {
	stdout, err := cmd.Exec("fail2ban-client -t")
	if err != nil {
		return fmt.Errorf("fail2ban config test failed: %v, output: %s", err, stdout)
	}
	return nil
}

func (u *Fail2BanService) UpdateConf(req dto.Fail2BanUpdate) error {
	// A newline or '#' in Value could inject extra ini directives into the
	// [sshd] jail; reject them up front for every key. The remaining shape
	// checks below match what the frontend sends for each key.
	if strings.ContainsAny(req.Value, "\n\r#") {
		return buserr.New(constant.ErrCmdIllegal)
	}
	switch req.Key {
	case "bantime", "findtime", "maxretry":
		if _, err := strconv.Atoi(req.Value); err != nil {
			return buserr.New(constant.ErrCmdIllegal)
		}
	case "port":
		for _, p := range strings.Split(req.Value, "-") {
			if _, err := strconv.Atoi(p); err != nil {
				return buserr.New(constant.ErrCmdIllegal)
			}
		}
	case "banaction":
		if req.Value == "firewallcmd-ipset" || req.Value == "ufw" {
			itemName := "ufw"
			if req.Value == "firewallcmd-ipset" {
				itemName = "firewalld"
			}
			client, err := firewall.NewFirewallClient()
			if err != nil {
				return err
			}
			if client.Name() != itemName {
				return buserr.WithName("ErrBanAction", itemName)
			}
			status, _ := client.Status()
			if status != "running" {
				return buserr.WithName("ErrBanAction", itemName)
			}
		}
	case "logpath":
		if strings.Contains(req.Value, "..") {
			return buserr.New(constant.ErrCmdIllegal)
		}
		if _, err := os.Stat(req.Value); err != nil {
			return err
		}
	}
	conf, err := os.ReadFile(defaultFail2BanPath)
	if err != nil {
		return fmt.Errorf("read fail2ban conf of %s failed, err: %v", defaultFail2BanPath, err)
	}
	lines := strings.Split(string(conf), "\n")

	isStart, isEnd, hasKey := false, false, false
	newFile := ""
	for index, line := range lines {
		if !isStart && strings.HasPrefix(line, "[sshd]") {
			isStart = true
			newFile += fmt.Sprintf("%s\n", line)
			continue
		}
		if !isStart || isEnd {
			newFile += fmt.Sprintf("%s\n", line)
			continue
		}
		if strings.HasPrefix(line, req.Key) {
			hasKey = true
			newFile += fmt.Sprintf("%s = %s\n", req.Key, req.Value)
			continue
		}
		if strings.HasPrefix(line, "[") || index == len(lines)-1 {
			isEnd = true
			if !hasKey {
				newFile += fmt.Sprintf("%s = %s\n", req.Key, req.Value)
			}
		}
		newFile += line
		if index != len(lines)-1 {
			newFile += "\n"
		}
	}
	// Persist the merged config atomically (keeping the previous content in
	// memory for rollback), then let fail2ban validate it before the restart.
	// If the restart still fails, the original file is restored and fail2ban
	// is restarted again with the old configuration, so a bad write never
	// leaves the host with an invalid jail.local.
	oldContent, err := writeFileAtomicWithBackup(defaultFail2BanPath, []byte(newFile))
	if err != nil {
		return err
	}
	client, err := toolbox.NewFail2Ban()
	if err != nil {
		_ = os.WriteFile(defaultFail2BanPath, oldContent, 0640)
		return err
	}
	if err := testFail2BanConf(); err != nil {
		return restoreFileAfterFailedRestart(defaultFail2BanPath, oldContent, err)
	}
	if err := client.Operate("restart"); err != nil {
		return restoreFileAfterFailedRestart(defaultFail2BanPath, oldContent, err)
	}
	return nil
}

func (u *Fail2BanService) UpdateConfByFile(req dto.UpdateByFile) error {
	// Same rollback discipline as UpdateConf: persist atomically (keeping the
	// previous content), run `fail2ban-client -t` against the written file,
	// and on any failure restore the previous file plus a best-effort
	// restart, so a bad write never leaves an unloadable jail.local behind.
	oldContent, err := writeFileAtomicWithBackup(defaultFail2BanPath, []byte(req.File))
	if err != nil {
		return err
	}
	client, err := toolbox.NewFail2Ban()
	if err != nil {
		_ = os.WriteFile(defaultFail2BanPath, oldContent, 0640)
		return err
	}
	if err := testFail2BanConf(); err != nil {
		return restoreFileAfterFailedRestart(defaultFail2BanPath, oldContent, err)
	}
	if err := client.Operate("restart"); err != nil {
		return restoreFileAfterFailedRestart(defaultFail2BanPath, oldContent, err)
	}
	return nil
}

func (u *Fail2BanService) OperateSSHD(req dto.Fail2BanSet) error {
	if req.Operate == "ignore" {
		if err := u.UpdateConf(dto.Fail2BanUpdate{Key: "ignoreip", Value: strings.Join(req.IPs, ",")}); err != nil {
			return err
		}
		return nil
	}
	client, err := toolbox.NewFail2Ban()
	if err != nil {
		return err
	}
	if err := client.ReBanIPs(req.IPs); err != nil {
		return err
	}
	return nil
}

func loadFailValue(line string, baseInfo *dto.Fail2BanBaseInfo) {
	if strings.HasPrefix(line, "port") {
		itemValue := strings.ReplaceAll(line, "port", "")
		itemValue = strings.ReplaceAll(itemValue, "=", "")
		baseInfo.Port, _ = strconv.Atoi(strings.TrimSpace(itemValue))
	}
	if strings.HasPrefix(line, "maxretry") {
		itemValue := strings.ReplaceAll(line, "maxretry", "")
		itemValue = strings.ReplaceAll(itemValue, "=", "")
		baseInfo.MaxRetry, _ = strconv.Atoi(strings.TrimSpace(itemValue))
	}
	if strings.HasPrefix(line, "findtime") {
		itemValue := strings.ReplaceAll(line, "findtime", "")
		itemValue = strings.ReplaceAll(itemValue, "=", "")
		baseInfo.FindTime = strings.TrimSpace(itemValue)
	}
	if strings.HasPrefix(line, "bantime") {
		itemValue := strings.ReplaceAll(line, "bantime", "")
		itemValue = strings.ReplaceAll(itemValue, "=", "")
		baseInfo.BanTime = strings.TrimSpace(itemValue)
	}
	if strings.HasPrefix(line, "banaction") {
		itemValue := strings.ReplaceAll(line, "banaction", "")
		itemValue = strings.ReplaceAll(itemValue, "=", "")
		baseInfo.BanAction = strings.TrimSpace(itemValue)
	}
	if strings.HasPrefix(line, "logpath") {
		itemValue := strings.ReplaceAll(line, "logpath", "")
		itemValue = strings.ReplaceAll(itemValue, "=", "")
		baseInfo.LogPath = strings.TrimSpace(itemValue)
	}
}
