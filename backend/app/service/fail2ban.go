package service

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/1Panel-dev/1Panel/backend/app/dto"
	"github.com/1Panel-dev/1Panel/backend/buserr"
	"github.com/1Panel-dev/1Panel/backend/constant"
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
	file, err := os.OpenFile(defaultFail2BanPath, os.O_WRONLY|os.O_TRUNC, 0640)
	if err != nil {
		return err
	}
	defer file.Close()
	write := bufio.NewWriter(file)
	_, _ = write.WriteString(newFile)
	write.Flush()

	client, err := toolbox.NewFail2Ban()
	if err != nil {
		return err
	}
	if err := client.Operate("restart"); err != nil {
		return err
	}
	return nil
}

func (u *Fail2BanService) UpdateConfByFile(req dto.UpdateByFile) error {
	file, err := os.OpenFile(defaultFail2BanPath, os.O_WRONLY|os.O_TRUNC, 0640)
	if err != nil {
		return err
	}
	defer file.Close()
	write := bufio.NewWriter(file)
	_, _ = write.WriteString(req.File)
	write.Flush()

	client, err := toolbox.NewFail2Ban()
	if err != nil {
		return err
	}
	if err := client.Operate("restart"); err != nil {
		return err
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
