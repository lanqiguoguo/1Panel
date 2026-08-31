package files

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/1Panel-dev/1Panel/backend/buserr"
	"github.com/1Panel-dev/1Panel/backend/constant"
	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/1Panel-dev/1Panel/backend/utils/cmd"
)

type TarGzArchiver struct {
}

func NewTarGzArchiver() ShellArchiver {
	return &TarGzArchiver{}
}

func (t TarGzArchiver) Extract(filePath, dstDir string, secret string) error {
	if !ValidShellArgs(filePath, dstDir) || (len(secret) != 0 && !ValidShellArgs(secret)) {
		return buserr.New(constant.ErrCmdIllegal)
	}
	srcFile := filePath
	if len(secret) != 0 {
		// The secret must never reach a command line: decrypt with
		// `-pass fd:3` (buildDecryptCmd) into a temp file first, then extract
		// it through the plain path below. This is the same openssl
		// invocation the Decompress compatibility path uses, so its error
		// semantics and the fallback order there are untouched.
		decryptedPath, err := decryptTarGz(filePath, secret)
		if err != nil {
			return err
		}
		defer os.Remove(decryptedPath)
		srcFile = decryptedPath
	}
	commands := fmt.Sprintf("tar -zxvf '%s' -C '%s' > /dev/null 2>&1", srcFile, dstDir)
	global.LOG.Debug(commands)
	if err := cmd.ExecCmd(commands); err != nil {
		return err
	}
	return nil
}

func (t TarGzArchiver) Compress(sourcePaths []string, dstFile string, secret string) error {
	if len(sourcePaths) == 0 {
		return buserr.New(constant.ErrCmdIllegal)
	}
	for _, item := range sourcePaths {
		if !ValidShellArgs(filepath.Base(item)) {
			return buserr.New(constant.ErrCmdIllegal)
		}
	}
	if !ValidShellArgs(filepath.Dir(sourcePaths[0]), dstFile) || (len(secret) != 0 && !ValidShellArgs(secret)) {
		return buserr.New(constant.ErrCmdIllegal)
	}
	var itemDirs []string
	for _, item := range sourcePaths {
		itemDirs = append(itemDirs, fmt.Sprintf("\"%s\"", filepath.Base(item)))
	}
	itemDir := strings.Join(itemDirs, " ")
	aheadDir := filepath.Dir(sourcePaths[0])
	if len(aheadDir) == 0 {
		aheadDir = "/"
	}
	if len(secret) != 0 {
		// The secret travels on inherited fd 3 instead of the command line:
		// openssl is started by bash as a pipeline member and keeps the
		// descriptor the ExtraFiles-aware exec helper handed to bash, so
		// `-pass fd:3` reads the password without it ever appearing in argv
		// (/proc/<pid>/cmdline is world-readable).
		extraCmd := "| openssl enc -aes-256-cbc -salt -pass fd:3 -out '" + dstFile + "'"
		commands := fmt.Sprintf("tar -zcf - -C \"%s\" %s %s", aheadDir, itemDir, extraCmd)
		global.LOG.Debug(commands)
		secretReader, err := cmd.SecretPassReader(secret)
		if err != nil {
			return err
		}
		defer secretReader.Close()
		return cmd.ExecCmdWithExtraFiles(commands, []*os.File{secretReader})
	}
	commands := fmt.Sprintf("tar -zcf \"%s\" -C \"%s\" %s", dstFile, aheadDir, itemDir)
	global.LOG.Debug(commands)
	if err := cmd.ExecCmd(commands); err != nil {
		return err
	}
	return nil
}
