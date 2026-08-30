package toolbox

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/1Panel-dev/1Panel/backend/buserr"
	"github.com/1Panel-dev/1Panel/backend/constant"
	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/1Panel-dev/1Panel/backend/utils/cmd"
	"github.com/1Panel-dev/1Panel/backend/utils/systemctl"
)

type Ftp struct {
	DefaultUser  string
	DefaultGroup string
}

type FtpList struct {
	User   string
	Path   string
	Status string
}

type FtpLog struct {
	IP        string `json:"ip"`
	User      string `json:"user"`
	Time      string `json:"time"`
	Operation string `json:"operation"`
	Status    string `json:"status"`
	Size      string `json:"size"`
}

type FtpClient interface {
	Status() (bool, bool)
	Operate(operate string) error
	LoadList() ([]FtpList, error)
	UserAdd(username, path, passwd string) error
	UserDel(username string) error
	SetPasswd(username, passwd string) error
	Reload() error
	LoadLogs() ([]FtpLog, error)
}

func NewFtpClient() (*Ftp, error) {
	userItem, err := user.LookupId("1000")
	if err == nil {
		groupItem, err := user.LookupGroupId(userItem.Gid)
		if err != nil {
			return nil, err
		}
		return &Ftp{DefaultUser: userItem.Username, DefaultGroup: groupItem.Name}, err
	}
	if err.Error() != user.UnknownUserIdError(1000).Error() {
		return nil, err
	}

	groupItem, err := user.LookupGroupId("1000")
	if err == nil {
		stdout2, err := cmd.Execf("useradd -u 1000 -g %s %s", groupItem.Name, "1panel")
		if err != nil {
			return nil, errors.New(stdout2)
		}
		return &Ftp{DefaultUser: "1panel", DefaultGroup: groupItem.Name}, nil
	}
	if err.Error() != user.UnknownGroupIdError("1000").Error() {
		return nil, err
	}
	stdout, err := cmd.Exec("groupadd -g 1000 1panel")
	if err != nil {
		return nil, errors.New(string(stdout))
	}
	stdout2, err := cmd.Exec("useradd -u 1000 -g 1panel 1panel")
	if err != nil {
		return nil, errors.New(stdout2)
	}
	return &Ftp{DefaultUser: "1panel", DefaultGroup: "1panel"}, nil
}

func (f *Ftp) Status() (bool, bool) {
	isActive, _ := systemctl.IsActive("pure-ftpd.service")
	isExist, _ := systemctl.IsExist("pure-ftpd.service")

	return isActive, isExist
}

func (f *Ftp) Operate(operate string) error {
	switch operate {
	case "start", "restart", "stop":
		stdout, err := systemctl.CustomAction(operate, "pure-ftpd")
		if err != nil {
			return fmt.Errorf("%s the pure-ftpd service failed, err: %s", operate, stdout.Output)
		}
		return nil
	default:
		return fmt.Errorf("not support such operation: %v", operate)
	}
}

func (f *Ftp) UserAdd(username, passwd, path string) error {
	// Defense in depth: reject shell metacharacters even for values that a
	// future caller might not have validated. UserAdd writes the entry into
	// /etc/pure-ftpd/pureftpd.passwd and chowns the directory; the user and
	// path also reach a host shell command below.
	if cmd.CheckIllegal(username, passwd, path) {
		return buserr.New(constant.ErrCmdIllegal)
	}
	entry, err := generatePureFtpEntrySimple(username, passwd, path)
	if err != nil {
		return err
	}
	pwdFile, err := os.OpenFile("/etc/pure-ftpd/pureftpd.passwd", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer pwdFile.Close()

	_, err = pwdFile.WriteString("\n" + entry + "\n")
	if err != nil {
		return err
	}
	_ = f.Reload()
	std2, err := cmd.ExecWithCheck("chown", "-R", f.DefaultUser+":"+f.DefaultGroup, path)
	if err != nil {
		return errors.New(std2)
	}
	return nil
}

func (f *Ftp) UserDel(username string) error {
	// Defense in depth: the username lands in the host shell command below.
	if cmd.CheckIllegal(username) {
		return buserr.New(constant.ErrCmdIllegal)
	}
	std, err := cmd.ExecWithCheck("pure-pw", "userdel", username)
	if err != nil {
		return errors.New(std)
	}
	_ = f.Reload()
	return nil
}

func (f *Ftp) SetPasswd(username, passwd string) error {
	// Defense in depth: the username is compared against passwd file entries
	// and never reaches a shell command, but reject metacharacters anyway so
	// a malformed record cannot be created for a future caller. The password
	// is bcrypt-hashed and written into the passwd file only; special
	// characters in the password are legal (no shell interpolation).
	if cmd.CheckIllegal(username) {
		return buserr.New(constant.ErrCmdIllegal)
	}
	hashedPassword, err := hashPassword(passwd)
	if err != nil {
		return err
	}
	// read now
	pwdFile, err := os.Open("/etc/pure-ftpd/pureftpd.passwd")
	if err != nil {
		return err
	}
	defer pwdFile.Close()

	var entrys []string
	scanner := bufio.NewScanner(pwdFile)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		userEntry := strings.Split(line, ":")
		if len(userEntry) < 2 {
			continue
		}
		if userEntry[0] == username {
			userEntry[1] = string(hashedPassword)
			line = strings.Join(userEntry, ":")
		}
		entrys = append(entrys, line)
	}

	if err := scanner.Err(); err != nil {
		return err
	}
	pwdFile.Close()

	// write new
	pwdFile, err = os.Create("/etc/pure-ftpd/pureftpd.passwd")
	if err != nil {
		return err
	}
	defer pwdFile.Close()

	for _, entry := range entrys {
		_, err := pwdFile.WriteString(entry + "\n")
		if err != nil {
			return err
		}
	}

	return nil
}

func (f *Ftp) SetPath(username, path string) error {
	// Defense in depth: username and path land in host shell commands
	// (pure-pw usermod, chown -R) below, so reject shell metacharacters even
	// if the caller did not validate them.
	if cmd.CheckIllegal(username, path) {
		return buserr.New(constant.ErrCmdIllegal)
	}
	std, err := cmd.ExecWithCheck("pure-pw", "usermod", username, "-d", path)
	if err != nil {
		return errors.New(std)
	}
	std2, err := cmd.ExecWithCheck("chown", "-R", f.DefaultUser+":"+f.DefaultGroup, path)
	if err != nil {
		return errors.New(std2)
	}
	return nil
}

func (f *Ftp) SetStatus(username, status string) error {
	// Defense in depth: the username lands in the host shell command below.
	if cmd.CheckIllegal(username) {
		return buserr.New(constant.ErrCmdIllegal)
	}
	statusItem := ""
	if status == constant.StatusDisable {
		statusItem = "1"
	}
	std, err := cmd.ExecWithCheck("pure-pw", "usermod", username, "-r", statusItem)
	if err != nil {
		return errors.New(std)
	}
	return nil
}

func (f *Ftp) LoadList() ([]FtpList, error) {
	std, err := cmd.Exec("pure-pw list")
	if err != nil {
		return nil, errors.New(std)
	}
	var lists []FtpList
	lines := strings.Split(std, "\n")
	for _, line := range lines {
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		// The account name comes from the passwd file; even though entries
		// are written through validated paths, skip anything that carries
		// shell metacharacters instead of interpolating it into a command.
		if cmd.CheckIllegal(parts[0]) {
			global.LOG.Errorf("skip pure-ftpd account %q with illegal characters", parts[0])
			continue
		}
		std2, err := cmd.ExecWithCheck("pure-pw", "show", parts[0])
		if err != nil {
			global.LOG.Errorf("handle pure-pw show %s failed, err: %v", parts[0], std2)
			continue
		}
		status := constant.StatusDisable
		for _, itemLine := range strings.Split(std2, "\n") {
			if !strings.Contains(itemLine, "Allowed client IPs :") {
				continue
			}
			itemStd := strings.TrimSpace(strings.SplitN(itemLine, ":", 2)[1])
			if len(itemStd) == 0 {
				status = constant.StatusEnable
			}
			break
		}
		lists = append(lists, FtpList{User: parts[0], Path: strings.ReplaceAll(parts[1], "/./", ""), Status: status})
	}
	return lists, nil
}

func (f *Ftp) Reload() error {
	std, err := cmd.Exec("pure-pw mkdb")
	if err != nil {
		return errors.New(std)
	}
	return nil
}

func (f *Ftp) LoadLogs(user, operation string) ([]FtpLog, error) {
	var logs []FtpLog
	logItem := ""
	if _, err := os.Stat("/etc/pure-ftpd/conf"); err != nil && os.IsNotExist(err) {
		std, err := cmd.Exec("cat /etc/pure-ftpd/pure-ftpd.conf | grep AltLog | grep clf:")
		logItem = "/var/log/pureftpd.log"
		if err == nil && !strings.HasPrefix(logItem, "#") {
			logItem = std
		}
	} else {
		if err != nil {
			return logs, err
		}
		std, err := cmd.Exec("cat /etc/pure-ftpd/conf/AltLog")
		logItem = "/var/log/pure-ftpd/transfer.log"
		if err != nil && !strings.HasPrefix(logItem, "#") {
			logItem = std
		}
	}

	logItem = strings.ReplaceAll(logItem, "AltLog", "")
	logItem = strings.ReplaceAll(logItem, "clf:", "")
	logItem = strings.ReplaceAll(logItem, "\n", "")
	logPath := strings.Trim(logItem, " ")

	fileName := path.Base(logPath)
	var fileList []string
	if err := filepath.Walk(path.Dir(logPath), func(pathItem string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasPrefix(info.Name(), fileName) {
			fileList = append(fileList, pathItem)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	logs = loadLogsByFiles(fileList, user, operation)
	return logs, nil
}

func loadLogsByFiles(fileList []string, user, operation string) []FtpLog {
	var logs []FtpLog
	layout := "02/Jan/2006:15:04:05-0700"
	for _, file := range fileList {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			parts := strings.Fields(line)
			if len(parts) < 9 {
				continue
			}
			if (len(user) != 0 && parts[2] != user) || (len(operation) != 0 && parts[5] != fmt.Sprintf("\"%s", operation)) {
				continue
			}
			timeStr := parts[3] + parts[4]
			timeStr = strings.ReplaceAll(timeStr, "[", "")
			timeStr = strings.ReplaceAll(timeStr, "]", "")
			timeItem, err := time.Parse(layout, timeStr)
			if err == nil {
				timeStr = timeItem.Format(constant.DateTimeLayout)
			}
			operateStr := parts[5] + parts[6]
			logs = append(logs, FtpLog{
				IP:        parts[0],
				User:      parts[2],
				Time:      timeStr,
				Operation: operateStr,
				Status:    parts[7],
				Size:      parts[8],
			})
		}
	}
	return logs
}

func hashPassword(password string) ([]byte, error) {
	// Hash the password using bcrypt with a cost of 10
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	return hashedPassword, nil
}

func generatePureFtpEntrySimple(username, password, path string) (string, error) {
	return generatePureFtpEntry(username, password, 1000, 1000, "", path+"/./",
		"", "", "", "", "",
		"", "", "", "", "", "", "")
}

func generatePureFtpEntry(username, password string, uid, gid int, gecos, homedir,
	uploadBandwidth, downloadBandwidth, uploadRatio, downloadRatio, maxConnections, filesQuota, sizeQuota,
	authorizedLocalIPs, refusedLocalIPs, authorizedClientIPs, refusedClientIPs, timeRestrictions string) (string, error) {

	hashedPassword, err := hashPassword(password)
	if err != nil {
		return "", err
	}

	// Format the entry
	entry := fmt.Sprintf("%s:%s:%d:%d:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s",
		username,
		hashedPassword,
		uid,
		gid,
		gecos,
		homedir,
		uploadBandwidth,
		downloadBandwidth,
		uploadRatio,
		downloadRatio,
		maxConnections,
		filesQuota,
		sizeQuota,
		authorizedLocalIPs,
		refusedLocalIPs,
		authorizedClientIPs,
		refusedClientIPs,
		timeRestrictions,
	)

	return entry, nil
}
