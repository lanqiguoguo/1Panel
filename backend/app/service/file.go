package service

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/1Panel-dev/1Panel/backend/app/dto/request"
	"github.com/1Panel-dev/1Panel/backend/app/dto/response"
	"github.com/1Panel-dev/1Panel/backend/buserr"
	"github.com/1Panel-dev/1Panel/backend/constant"
	"golang.org/x/net/html/charset"
	"golang.org/x/sys/unix"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"

	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/1Panel-dev/1Panel/backend/utils/common"
	"github.com/1Panel-dev/1Panel/backend/utils/files"
	"github.com/pkg/errors"
)

type FileService struct {
}

type IFileService interface {
	GetFileList(op request.FileOption) (response.FileInfo, error)
	SearchUploadWithPage(req request.SearchUploadWithPage) (int64, interface{}, error)
	GetFileTree(op request.FileOption) ([]response.FileTree, error)
	Create(op request.FileCreate) error
	Delete(op request.FileDelete) error
	BatchDelete(op request.FileBatchDelete) error
	Compress(c request.FileCompress) error
	DeCompress(c request.FileDeCompress) error
	GetContent(op request.FileContentReq) (response.FileInfo, error)
	SaveContent(edit request.FileEdit) error
	FileDownload(d request.FileDownload) (string, error)
	DirSize(req request.DirSizeReq) (response.DirSizeRes, error)
	ChangeName(req request.FileRename) error
	Wget(w request.FileWget) (string, error)
	MvFile(m request.FileMove) error
	ChangeOwner(req request.FileRoleUpdate) error
	ChangeMode(op request.FileCreate) error
	BatchChangeModeAndOwner(op request.FileRoleReq) error
	ReadLogByLine(req request.FileReadByLineReq) (*response.FileLineContent, error)
	BatchCheckFiles(req request.FilePathsCheck) []response.ExistFileInfo
}

var filteredPaths = []string{
	"/.1panel_clash",
}

func NewIFileService() IFileService {
	return &FileService{}
}

func (f *FileService) GetFileList(op request.FileOption) (response.FileInfo, error) {
	var fileInfo response.FileInfo
	data, err := os.Stat(op.Path)
	if err != nil && os.IsNotExist(err) {
		return fileInfo, nil
	}
	if !data.IsDir() {
		op.FileOption.Path = filepath.Dir(op.FileOption.Path)
	}
	info, err := files.NewFileInfo(op.FileOption)
	if err != nil {
		return fileInfo, err
	}
	fileInfo.FileInfo = *info
	return fileInfo, nil
}

func (f *FileService) SearchUploadWithPage(req request.SearchUploadWithPage) (int64, interface{}, error) {
	var (
		files    []response.UploadInfo
		backData []response.UploadInfo
	)
	_ = filepath.Walk(req.Path, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() {
			files = append(files, response.UploadInfo{
				CreatedAt: info.ModTime().Format(constant.DateTimeLayout),
				Size:      int(info.Size()),
				Name:      info.Name(),
			})
		}
		return nil
	})
	total, start, end := len(files), (req.Page-1)*req.PageSize, req.Page*req.PageSize
	if start > total {
		backData = make([]response.UploadInfo, 0)
	} else {
		if end >= total {
			end = total
		}
		backData = files[start:end]
	}
	return int64(total), backData, nil
}

func (f *FileService) GetFileTree(op request.FileOption) ([]response.FileTree, error) {
	var treeArray []response.FileTree
	if _, err := os.Stat(op.Path); err != nil && os.IsNotExist(err) {
		return treeArray, nil
	}
	info, err := files.NewFileInfo(op.FileOption)
	if err != nil {
		return nil, err
	}
	node := response.FileTree{
		ID:        common.GetUuid(),
		Name:      info.Name,
		Path:      info.Path,
		IsDir:     info.IsDir,
		Extension: info.Extension,
	}
	err = f.buildFileTree(&node, info.Items, op, 2)
	if err != nil {
		return nil, err
	}
	return append(treeArray, node), nil
}

func shouldFilterPath(path string) bool {
	cleanedPath := filepath.Clean(path)
	for _, filteredPath := range filteredPaths {
		cleanedFilteredPath := filepath.Clean(filteredPath)
		if cleanedFilteredPath == cleanedPath || strings.HasPrefix(cleanedPath, cleanedFilteredPath+"/") {
			return true
		}
	}
	return false
}

// systemProtectedDirs 系统关键目录，禁止删除或移入回收站
var systemProtectedDirs = []string{
	"/etc", "/usr", "/var", "/bin", "/sbin", "/lib", "/boot", "/dev", "/proc", "/sys", "/root", "/home",
}

// resolveProtectedPathMaxLinks 限制符号链接展开的层数,防止恶意链接环把
// 保护检查拖入无限递归(正常解析由 EvalSymlinks 完成,该上限只影响悬空链
// 的文本展开路径)。
const resolveProtectedPathMaxLinks = 40

// isProtectedPath 判断路径是否位于受保护目录内（根目录、系统关键目录、
// 面板数据目录、回收站目录）。
//
// 除原有的词法前缀比较外,还解析路径上的符号链接:攻击者可在非保护目录下
// 布置指向受保护目录的链接(如 /www/lnk -> /etc/ssh),一切以 /www/lnk/...
// 为目标的写/删/移动接口都会跟随链接触达受保护目录,仅靠词法比较无法拦截。
// 因此先做词法判定(已存在/不存在的路径都维持原有语义),未命中时把路径按
// "已存在的最近前缀"解析符号链接后再按同一清单比较一次。
func isProtectedPath(pathName string) bool {
	cleanedPath := filepath.Clean(pathName)
	if protectedCleanPath(cleanedPath) {
		return true
	}
	resolved, ok := resolveExistingPath(cleanedPath)
	if ok && resolved != cleanedPath && protectedCleanPath(resolved) {
		return true
	}
	return false
}

// protectedCleanPath 是保护判定的词法部分:路径本身(或其前缀)命中黑名单
// 即受保护。与既有语义完全一致。
func protectedCleanPath(cleanedPath string) bool {
	if cleanedPath == "/" {
		return true
	}
	for _, dir := range systemProtectedDirs {
		if cleanedPath == dir || strings.HasPrefix(cleanedPath, dir+"/") {
			return true
		}
	}
	if baseDir := global.CONF.System.BaseDir; baseDir != "" {
		panelDataDir := path.Join(baseDir, "1panel")
		if cleanedPath == panelDataDir || strings.HasPrefix(cleanedPath, panelDataDir+"/") {
			return true
		}
	}
	if cleanedPath == constant.RecycleBinDir || strings.HasPrefix(cleanedPath, constant.RecycleBinDir+"/") {
		return true
	}
	return false
}

// resolveExistingPath 返回路径沿符号链接展开后的"真实路径"与是否成功解析:
//   - 相对路径不做处理(维持既有词法语义:非绝对路径永远不在黑名单内);
//   - 路径整体已存在时,filepath.EvalSymlinks 一次调用得到规范路径;
//   - 路径尚不存在(即将被创建)时,向上剥离到"已存在的最近前缀"并解析该
//     前缀,再把不存在后缀按词法拼回——不存在部分不可能是符号链接;
//   - 已存在前缀以悬空符号链接结尾(其目标链尚不存在)时,EvalSymlinks 会
//     失败,此时读取链接的文本目标并对其递归执行同样解析。这样
//     lnk -> /etc/尚未创建的子目录 这类"先布置链接、再借面板接口建目录"
//     的逃逸路径仍能被识别为受保护。
//
// 解析失败(权限不足、链接环超过上限等)时返回原路径与 false:这些情况下
// 后续文件操作大概率同样失败,维持宽松的词法判定,避免误伤合法路径。
func resolveExistingPath(pathName string) (string, bool) {
	return resolveExistingPathDepth(pathName, 0)
}

func resolveExistingPathDepth(pathName string, depth int) (string, bool) {
	cleanedPath := filepath.Clean(pathName)
	if depth > resolveProtectedPathMaxLinks || !filepath.IsAbs(cleanedPath) {
		return cleanedPath, false
	}
	if resolved, err := filepath.EvalSymlinks(cleanedPath); err == nil {
		return resolved, true
	}
	// 向上寻找已存在的最近前缀
	prefix := cleanedPath
	suffix := ""
	for {
		if _, err := os.Lstat(prefix); err == nil {
			break
		}
		parent := filepath.Dir(prefix)
		if parent == prefix {
			return cleanedPath, false
		}
		if suffix == "" {
			suffix = filepath.Base(prefix)
		} else {
			suffix = filepath.Join(filepath.Base(prefix), suffix)
		}
		prefix = parent
	}
	if resolved, err := filepath.EvalSymlinks(prefix); err == nil {
		if suffix == "" {
			return resolved, true
		}
		return filepath.Join(resolved, suffix), true
	}
	// 前缀存在但 EvalSymlinks 失败:通常意味着前缀的最后一个分量本身是
	// 悬空符号链接。读出链接文本目标后继续解析(目标自身也可能带链接)。
	info, err := os.Lstat(prefix)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		return cleanedPath, false
	}
	target, err := os.Readlink(prefix)
	if err != nil {
		return cleanedPath, false
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(filepath.Dir(prefix), target)
	}
	if suffix != "" {
		target = filepath.Join(target, suffix)
	}
	return resolveExistingPathDepth(target, depth+1)
}

// IsProtectedPath 供 API 层（如上传入口）校验路径是否位于受保护目录内
func IsProtectedPath(pathName string) bool {
	return isProtectedPath(pathName)
}

// 递归构建文件树(只取当前目录以及当前目录下的第一层子节点)
func (f *FileService) buildFileTree(node *response.FileTree, items []*files.FileInfo, op request.FileOption, level int) error {
	for _, v := range items {
		if shouldFilterPath(v.Path) {
			global.LOG.Infof("File Tree: Skipping %s due to filter\n", v.Path)
			continue
		}
		childNode := response.FileTree{
			ID:        common.GetUuid(),
			Name:      v.Name,
			Path:      v.Path,
			IsDir:     v.IsDir,
			Extension: v.Extension,
		}
		if level > 1 && v.IsDir {
			if err := f.buildChildNode(&childNode, v, op, level); err != nil {
				return err
			}
		}

		node.Children = append(node.Children, childNode)
	}
	return nil
}

func (f *FileService) buildChildNode(childNode *response.FileTree, fileInfo *files.FileInfo, op request.FileOption, level int) error {
	op.Path = fileInfo.Path
	subInfo, err := files.NewFileInfo(op.FileOption)
	if err != nil {
		if os.IsPermission(err) || errors.Is(err, unix.EACCES) {
			global.LOG.Infof("File Tree: Skipping %s due to permission denied\n", fileInfo.Path)
			return nil
		}
		global.LOG.Errorf("File Tree: Skipping %s due to error: %s\n", fileInfo.Path, err.Error())
		return nil
	}

	return f.buildFileTree(childNode, subInfo.Items, op, level-1)
}

func (f *FileService) Create(op request.FileCreate) error {
	if files.IsInvalidChar(op.Path) {
		return buserr.New("ErrInvalidChar")
	}
	// 创建/链接都会在目标路径落盘新条目，与 Delete/MvFile 同风格，
	// 目标路径以及链接源路径都必须位于非保护目录内
	if isProtectedPath(op.Path) {
		return buserr.New(constant.ErrPathNotDelete)
	}
	if op.IsLink && op.LinkPath != "" && isProtectedPath(op.LinkPath) {
		return buserr.New(constant.ErrPathNotDelete)
	}
	fo := files.NewFileOp()
	if fo.Stat(op.Path) {
		return buserr.New(constant.ErrFileIsExist)
	}
	mode := op.Mode
	if mode == 0 {
		fileInfo, err := os.Stat(filepath.Dir(op.Path))
		if err == nil {
			mode = int64(fileInfo.Mode().Perm())
		} else {
			mode = 0755
		}
	}
	if op.IsDir {
		return fo.CreateDirWithMode(op.Path, fs.FileMode(mode))
	}
	if op.IsLink {
		if !fo.Stat(op.LinkPath) {
			return buserr.New(constant.ErrLinkPathNotFound)
		}
		return fo.LinkFile(op.LinkPath, op.Path, op.IsSymlink)
	}
	// 与 ChangeMode 一致：服务端强制剥离 setuid/setgid/sticky 等高位权限位
	return fo.CreateFileWithMode(op.Path, fs.FileMode(mode)&0o777)
}

func (f *FileService) Delete(op request.FileDelete) error {
	if isProtectedPath(op.Path) {
		return buserr.New(constant.ErrPathNotDelete)
	}
	if op.IsDir {
		excludeDir := global.CONF.System.DataDir
		if filepath.Base(op.Path) == ".1panel_clash" || op.Path == excludeDir {
			return buserr.New(constant.ErrPathNotDelete)
		}
	}
	fo := files.NewFileOp()
	recycleBinStatus, _ := settingRepo.Get(settingRepo.WithByKey("FileRecycleBin"))
	if recycleBinStatus.Value == "disable" {
		op.ForceDelete = true
	}
	if op.ForceDelete {
		if op.IsDir {
			return fo.DeleteDir(op.Path)
		} else {
			return fo.DeleteFile(op.Path)
		}
	}
	if err := NewIRecycleBinService().Create(request.RecycleBinCreate{SourcePath: op.Path}); err != nil {
		return err
	}
	return favoriteRepo.Delete(favoriteRepo.WithByPath(op.Path))
}

func (f *FileService) BatchDelete(op request.FileBatchDelete) error {
	for _, file := range op.Paths {
		if isProtectedPath(file) {
			return buserr.New(constant.ErrPathNotDelete)
		}
	}
	fo := files.NewFileOp()
	if op.IsDir {
		for _, file := range op.Paths {
			if err := fo.DeleteDir(file); err != nil {
				return err
			}
		}
	} else {
		for _, file := range op.Paths {
			if err := fo.DeleteFile(file); err != nil {
				return err
			}
		}
	}
	return nil
}

func (f *FileService) ChangeMode(op request.FileCreate) error {
	if isProtectedPath(op.Path) {
		return buserr.New(constant.ErrPathNotDelete)
	}
	// 面板 UI 只产生 0-0777 权限，服务端强制清掉 setuid/setgid/sticky
	// 等高位权限位，负值直接拒绝。
	if op.Mode < 0 {
		return buserr.New(constant.ErrCmdIllegal)
	}
	fo := files.NewFileOp()
	return fo.ChmodR(op.Path, op.Mode&0o777, op.Sub)
}

func (f *FileService) BatchChangeModeAndOwner(op request.FileRoleReq) error {
	if op.Mode < 0 {
		return buserr.New(constant.ErrCmdIllegal)
	}
	mode := op.Mode & 0o777
	fo := files.NewFileOp()
	for _, path := range op.Paths {
		if isProtectedPath(path) {
			return buserr.New(constant.ErrPathNotDelete)
		}
		if !fo.Stat(path) {
			return buserr.New(constant.ErrPathNotFound)
		}
		if err := fo.ChownR(path, op.User, op.Group, op.Sub); err != nil {
			return err
		}
		if err := fo.ChmodR(path, mode, op.Sub); err != nil {
			return err
		}
	}
	return nil

}

func (f *FileService) ChangeOwner(req request.FileRoleUpdate) error {
	if isProtectedPath(req.Path) {
		return buserr.New(constant.ErrPathNotDelete)
	}
	fo := files.NewFileOp()
	return fo.ChownR(req.Path, req.User, req.Group, req.Sub)
}

func (f *FileService) Compress(c request.FileCompress) error {
	fo := files.NewFileOp()
	if !c.Replace && fo.Stat(filepath.Join(c.Dst, c.Name)) {
		return buserr.New(constant.ErrFileIsExist)
	}
	return fo.Compress(c.Files, c.Dst, c.Name, files.CompressType(c.Type), c.Secret)
}

func (f *FileService) DeCompress(c request.FileDeCompress) error {
	fo := files.NewFileOp()
	if c.Type == "tar" && len(c.Secret) != 0 {
		c.Type = "tar.gz"
	}
	return fo.Decompress(c.Path, c.Dst, files.CompressType(c.Type), c.Secret)
}

func (f *FileService) GetContent(op request.FileContentReq) (response.FileInfo, error) {
	info, err := files.NewFileInfo(files.FileOption{
		Path:     op.Path,
		Expand:   true,
		IsDetail: op.IsDetail,
	})
	if err != nil {
		return response.FileInfo{}, err
	}

	content := []byte(info.Content)
	if len(content) > 1024 {
		content = content[:1024]
	}
	if !utf8.Valid(content) {
		_, decodeName, _ := charset.DetermineEncoding(content, "")
		if decodeName == "windows-1252" {
			reader := strings.NewReader(info.Content)
			item := transform.NewReader(reader, simplifiedchinese.GBK.NewDecoder())
			contents, err := io.ReadAll(item)
			if err != nil {
				return response.FileInfo{}, err
			}
			info.Content = string(contents)
		}
	}
	return response.FileInfo{FileInfo: *info}, nil
}

func (f *FileService) SaveContent(edit request.FileEdit) error {
	if isProtectedPath(edit.Path) {
		return buserr.New(constant.ErrPathNotDelete)
	}
	info, err := files.NewFileInfo(files.FileOption{
		Path:   edit.Path,
		Expand: false,
	})
	if err != nil {
		return err
	}

	fo := files.NewFileOp()
	return fo.WriteFile(edit.Path, strings.NewReader(edit.Content), info.FileMode)
}

func (f *FileService) ChangeName(req request.FileRename) error {
	if files.IsInvalidChar(req.NewName) {
		return buserr.New("ErrInvalidChar")
	}
	// 重命名会移除旧路径条目并创建新路径，两端都必须位于非保护目录内
	if isProtectedPath(req.OldName) || isProtectedPath(req.NewName) {
		return buserr.New(constant.ErrPathNotDelete)
	}
	fo := files.NewFileOp()
	return fo.Rename(req.OldName, req.NewName)
}

func (f *FileService) Wget(w request.FileWget) (string, error) {
	// 下载目标会在该路径落盘新文件，与上传/写入同风格：目录与最终路径
	// 都必须位于非保护目录内，且文件名不得包含路径分隔符或穿越分量。
	if isProtectedPath(w.Path) || isProtectedPath(path.Join(w.Path, w.Name)) {
		return "", buserr.New(constant.ErrPathNotDelete)
	}
	name, err := files.SanitizeFilename(w.Name)
	if err != nil {
		return "", err
	}
	fo := files.NewFileOp()
	key := "file-wget-" + common.GetUuid()
	return key, fo.DownloadFileWithProcess(w.Url, filepath.Join(w.Path, name), key, w.IgnoreCertificate)
}

func init() {
	// Cut 在执行点复核保护路径，files 包无法反向 import service（会成环），
	// 故由本包在初始化时把 isProtectedPath 注入进去：任一路径受保护即中止。
	files.SetCutProtectedPathCheck(func(paths ...string) bool {
		for _, p := range paths {
			if isProtectedPath(p) {
				return true
			}
		}
		return false
	})
}

func (f *FileService) MvFile(m request.FileMove) error {
	// 预检与执行点推导一致的真实落点，而不只是词法拼接的 NewPath/Name：
	//   - cut 且 NewPath/Name 已存在时，实际目标回退为 NewPath 本身；回退后
	//     若 NewPath 是已存在目录（含指向目录的 symlink），每个源的真实落点
	//     是 NewPath/<base(oldPath)>，而不是 NewPath；
	//   - copy 的落点随源类型与 cover 变化，目录形态目标会让 cp 把源放进
	//     目录内部（NewPath/<base(src)> 或 NewPath/Name/<base(src)>）；
	//   - isProtectedPath 会解析路径上的符号链接，词法安全但解析后落入受保护
	//     目录的目标在这里就会被拦下。
	// 执行点（Cut/CopyAndReName 内注入的复核）仍保留，作为 TOCTOU 兜底。
	if isProtectedPath(m.NewPath) || (m.Name != "" && isProtectedPath(path.Join(m.NewPath, m.Name))) {
		return buserr.New(constant.ErrPathNotDelete)
	}
	fo := files.NewFileOp()
	if !fo.Stat(m.NewPath) {
		return buserr.New(constant.ErrPathNotFound)
	}
	// 各源路径（词法层面）同样必须位于非保护目录内
	for _, oldPath := range m.OldPaths {
		if isProtectedPath(oldPath) {
			return buserr.New(constant.ErrPathNotDelete)
		}
		if !fo.Stat(oldPath) {
			return buserr.WithName(constant.ErrFileNotFound, oldPath)
		}
		if oldPath == m.NewPath || strings.Contains(m.NewPath, filepath.Clean(oldPath)+"/") {
			return buserr.New(constant.ErrMovePathFailed)
		}
	}
	checkLanding := func(target string) error {
		if isProtectedPath(target) {
			return buserr.New(constant.ErrPathNotDelete)
		}
		return nil
	}
	// 目标形态：已存在目录（跟随 symlink，与 mv/cp 一致）时源落在目录内部
	landingInside := func(dstArg string) bool {
		info, err := fo.Fs.Stat(dstArg)
		return err == nil && info.IsDir()
	}
	if m.Type == "cut" {
		// Cut 的目的参数：name 非空且 NewPath/Name 已存在时回退为 NewPath
		dstArg := m.NewPath
		if m.Name != "" && !fo.Stat(path.Join(m.NewPath, m.Name)) {
			dstArg = path.Join(m.NewPath, m.Name)
		}
		if err := checkLanding(dstArg); err != nil {
			return err
		}
		if landingInside(dstArg) {
			for _, oldPath := range m.OldPaths {
				if err := checkLanding(path.Join(dstArg, path.Base(oldPath))); err != nil {
					return err
				}
			}
		}
		// cut+cover 的复制分支：CopyAndReName(src, NewPath, "", true) 与上面
		// 同形——NewPath 是已存在目录时落点为 NewPath/<base(src)>
		if landingInside(m.NewPath) {
			for _, src := range m.CoverPaths {
				if err := checkLanding(path.Join(m.NewPath, path.Base(src))); err != nil {
					return err
				}
			}
		}
	} else {
		for _, src := range m.OldPaths {
			// 与 CopyAndReName 逐源推导一致：目录源在 name 非空且非 cover 时
			// 拷到 NewPath/Name（cp -rf src NewPath/Name 会在该路径不存在时
			// 以该名字落盘目录，已存在时拷进其内部），其余分支拷到 NewPath
			info, err := fo.Fs.Stat(src)
			if err != nil {
				return buserr.WithName(constant.ErrFileNotFound, src)
			}
			dstArg := path.Join(m.NewPath, m.Name)
			if (info.IsDir() && (m.Name == "" || m.Cover)) || (!info.IsDir() && m.Cover) {
				dstArg = m.NewPath
			}
			if err := checkLanding(dstArg); err != nil {
				return err
			}
			if landingInside(dstArg) {
				if err := checkLanding(path.Join(dstArg, path.Base(src))); err != nil {
					return err
				}
			}
		}
	}
	var errs []error
	if m.Type == "cut" {
		if len(m.CoverPaths) > 0 {
			for _, src := range m.CoverPaths {
				if err := fo.CopyAndReName(src, m.NewPath, "", true); err != nil {
					errs = append(errs, err)
					global.LOG.Errorf("cut copy file [%s] to [%s] failed, err: %s", src, m.NewPath, err.Error())
				}
			}
		}
		return fo.Cut(m.OldPaths, m.NewPath, m.Name, m.Cover)
	}
	if m.Type == "copy" {
		for _, src := range m.OldPaths {
			if err := fo.CopyAndReName(src, m.NewPath, m.Name, m.Cover); err != nil {
				errs = append(errs, err)
				global.LOG.Errorf("copy file [%s] to [%s] failed, err: %s", src, m.NewPath, err.Error())
			}
		}
	}

	var errString string
	for _, err := range errs {
		errString += err.Error() + "\n"
	}
	if errString != "" {
		return errors.New(errString)
	}
	return nil
}

func (f *FileService) FileDownload(d request.FileDownload) (string, error) {
	filePath := d.Paths[0]
	if d.Compress {
		tempPath := filepath.Join(os.TempDir(), fmt.Sprintf("%d", time.Now().UnixNano()))
		if err := os.MkdirAll(tempPath, os.ModePerm); err != nil {
			return "", err
		}
		fo := files.NewFileOp()
		if err := fo.Compress(d.Paths, tempPath, d.Name, files.CompressType(d.Type), ""); err != nil {
			return "", err
		}
		filePath = filepath.Join(tempPath, d.Name)
	}
	return filePath, nil
}

func (f *FileService) DirSize(req request.DirSizeReq) (response.DirSizeRes, error) {
	var (
		res response.DirSizeRes
	)
	if req.Path == "/proc" {
		return res, nil
	}
	cmd := exec.Command("du", "-s", req.Path)
	output, err := cmd.Output()
	if err == nil {
		fields := strings.Fields(string(output))
		if len(fields) == 2 {
			var cmdSize int64
			_, err = fmt.Sscanf(fields[0], "%d", &cmdSize)
			if err == nil {
				res.Size = float64(cmdSize * 1024)
				return res, nil
			}
		}
	}
	fo := files.NewFileOp()
	size, err := fo.GetDirSize(req.Path)
	if err != nil {
		return res, err
	}
	res.Size = size
	return res, nil
}

func (f *FileService) ReadLogByLine(req request.FileReadByLineReq) (*response.FileLineContent, error) {
	logFilePath := ""
	switch req.Type {
	case constant.TypeWebsite:
		if req.Name != constant.AccessLog && req.Name != constant.ErrorLog {
			return nil, buserr.New(constant.ErrCmdIllegal)
		}
		website, err := websiteRepo.GetFirst(commonRepo.WithByID(req.ID))
		if err != nil {
			return nil, err
		}
		nginx, err := getNginxFull(&website)
		if err != nil {
			return nil, err
		}
		logFilePath, err = safeLogPath(path.Join(nginx.SiteDir, "sites"), website.Alias, "log", req.Name)
		if err != nil {
			return nil, err
		}
	case constant.TypePhp:
		php, err := runtimeRepo.GetFirst(commonRepo.WithByID(req.ID))
		if err != nil {
			return nil, err
		}
		logFilePath, err = safeLogPath(constant.RuntimeDir, php.Type, php.Name, "build.log")
		if err != nil {
			return nil, err
		}
	case constant.TypeSSL:
		ssl, err := websiteSSLRepo.GetFirst(commonRepo.WithByID(req.ID))
		if err != nil {
			return nil, err
		}
		logFilePath, err = safeLogPath(constant.SSLLogDir, fmt.Sprintf("%s-ssl-%d.log", ssl.PrimaryDomain, ssl.ID))
		if err != nil {
			return nil, err
		}
	case constant.TypeSystem:
		fileName := ""
		if len(req.Name) == 0 || req.Name == time.Now().Format("2006-01-02") {
			fileName = "1Panel.log"
		} else {
			if _, err := time.Parse("2006-01-02", req.Name); err != nil {
				return nil, buserr.New(constant.ErrCmdIllegal)
			}
			fileName = "1Panel-" + req.Name + ".log"
		}
		logDir := path.Join(global.CONF.System.DataDir, "log")
		var err error
		logFilePath, err = safeLogPath(logDir, fileName)
		if err != nil {
			return nil, err
		}
		if _, err := os.Stat(logFilePath); err != nil {
			fileGzPath, pathErr := safeLogPath(logDir, fileName+".gz")
			if pathErr != nil {
				return nil, pathErr
			}
			if _, err := os.Stat(fileGzPath); err != nil {
				return nil, buserr.New("ErrHttpReqNotFound")
			}
			if err := handleGunzip(fileGzPath); err != nil {
				return nil, fmt.Errorf("handle ungzip file %s failed, err: %v", fileGzPath, err)
			}
		}
	case "image-pull", "image-push", "image-build", "compose-create":
		if !validDockerLogName(req.Type, req.Name) {
			return nil, buserr.New(constant.ErrCmdIllegal)
		}
		var err error
		logFilePath, err = safeLogPath(path.Join(global.CONF.System.TmpDir, "docker_logs"), req.Name)
		if err != nil {
			return nil, err
		}
	case "ollama-model":
		var err error
		logFilePath, err = safeNestedLogPath(path.Join(global.CONF.System.DataDir, "log", "AITools"), req.Name)
		if err != nil {
			return nil, err
		}
	case "mysql-slow-logs":
		var err error
		logFilePath, err = safeLogPath(path.Join(global.CONF.System.DataDir, "apps", "mysql"), req.Name, "data", "1Panel-slow.log")
		if err != nil {
			return nil, err
		}
	case "mariadb-slow-logs":
		var err error
		logFilePath, err = safeLogPath(path.Join(global.CONF.System.DataDir, "apps", "mariadb"), req.Name, "db", "data", "1Panel-slow.log")
		if err != nil {
			return nil, err
		}
	default:
		return nil, buserr.New(constant.ErrCmdIllegal)
	}

	lines, isEndOfFile, total, err := files.ReadFileByLine(logFilePath, req.Page, req.PageSize, req.Latest)
	if err != nil {
		return nil, err
	}
	if req.Latest && req.Page == 1 && len(lines) < 1000 && total > 1 {
		preLines, _, _, err := files.ReadFileByLine(logFilePath, total-1, req.PageSize, false)
		if err != nil {
			return nil, err
		}
		lines = append(preLines, lines...)
	}

	res := &response.FileLineContent{
		Content: strings.Join(lines, "\n"),
		End:     isEndOfFile,
		Path:    logFilePath,
		Total:   total,
		Lines:   lines,
	}
	return res, nil
}

// safeLogPath builds a log path from server-controlled roots and path
// components. User-provided log names must remain a single filesystem
// component, and the normalized result is checked against the intended root
// so traversal cannot redirect the read to another file.
func safeLogPath(root string, components ...string) (string, error) {
	if root == "" || len(components) == 0 {
		return "", buserr.New(constant.ErrCmdIllegal)
	}

	for _, component := range components {
		if !validLogPathComponent(component) {
			return "", buserr.New(constant.ErrCmdIllegal)
		}
	}

	cleanRoot := filepath.Clean(root)
	candidate := filepath.Clean(filepath.Join(append([]string{cleanRoot}, components...)...))
	rootAbs, err := filepath.Abs(cleanRoot)
	if err != nil {
		return "", buserr.New(constant.ErrCmdIllegal)
	}
	candidateAbs, err := filepath.Abs(candidate)
	if err != nil {
		return "", buserr.New(constant.ErrCmdIllegal)
	}
	rel, err := filepath.Rel(rootAbs, candidateAbs)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", buserr.New(constant.ErrCmdIllegal)
	}

	// The Rel check above is purely lexical: a symlink planted inside the
	// log root (for example docker_logs/image_pull_x.log -> /etc/passwd)
	// stays under the root and would pass, letting the later read follow
	// the link outside the root. Resolve an existing candidate and re-check
	// the resolved target against the (also resolved) root.
	//
	// The check only runs when the path exists: a log file that has not been
	// generated yet must flow through unchanged — the system-log caller
	// depends on the plaintext file being absent to fall back to its .gz
	// archive, and a missing file cannot be read anyway. A dangling link is
	// rejected outright: it cannot be read today, but its target could
	// appear between validation and the actual read, so leaving it open
	// would just defer the failure or race it later.
	if _, err := os.Lstat(candidate); err == nil {
		resolved, err := filepath.EvalSymlinks(candidate)
		if err != nil {
			return "", buserr.New(constant.ErrCmdIllegal)
		}
		resolvedAbs, err := filepath.Abs(resolved)
		if err != nil {
			return "", err
		}
		// Compare against the resolved root as well, so installs whose
		// data/tmp root is itself a symlink keep working while links inside
		// the root pointing anywhere else are rejected.
		relBase := rootAbs
		if resolvedRoot, err := filepath.EvalSymlinks(cleanRoot); err == nil {
			relBase = resolvedRoot
		}
		rel, err = filepath.Rel(relBase, resolvedAbs)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
			return "", buserr.New(constant.ErrCmdIllegal)
		}
	}

	return candidate, nil
}

// safeNestedLogPath is used for Ollama model names. Ollama accepts model
// namespaces (for example, "library/model:tag"), so slash-separated names
// are allowed only when every segment is safe and the normalized path stays
// below the model log root.
func safeNestedLogPath(root, name string) (string, error) {
	if name == "" || filepath.IsAbs(name) || path.IsAbs(name) || strings.Contains(name, `\`) {
		return "", buserr.New(constant.ErrCmdIllegal)
	}
	components := strings.Split(name, "/")
	if len(components) == 0 {
		return "", buserr.New(constant.ErrCmdIllegal)
	}
	return safeLogPath(root, components...)
}

func validDockerLogName(logType, name string) bool {
	prefixes := map[string]string{
		"image-pull":     "image_pull",
		"image-push":     "image_push",
		"image-build":    "image_build",
		"compose-create": "compose_create",
	}
	prefix, ok := prefixes[logType]
	if !ok || !validLogPathComponent(name) || !strings.HasPrefix(name, prefix+"_") || !strings.HasSuffix(name, ".log") {
		return false
	}

	const timestampLength = len("20060102150405")
	stampStart := len(name) - len(".log") - timestampLength
	if stampStart <= len(prefix)+1 || name[stampStart-1] != '_' {
		return false
	}
	for _, value := range name[stampStart : stampStart+timestampLength] {
		if value < '0' || value > '9' {
			return false
		}
	}
	return true
}

func validLogPathComponent(component string) bool {
	if component == "" || component == "." || component == ".." {
		return false
	}
	if filepath.IsAbs(component) || path.IsAbs(component) || strings.ContainsAny(component, `/\\`) || strings.ContainsRune(component, '\x00') {
		return false
	}
	// Reject drive-prefixed names even when this service is running on Unix;
	// this keeps Windows-style paths from becoming valid if the code is reused
	// on Windows and rejects inputs such as "C:passwd" as well as "C:/...".
	if len(component) >= 2 && isASCIIAlpha(component[0]) && component[1] == ':' {
		return false
	}
	for _, r := range component {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}
func (f *FileService) BatchCheckFiles(req request.FilePathsCheck) []response.ExistFileInfo {
	fileList := make([]response.ExistFileInfo, 0, len(req.Paths))
	for _, filePath := range req.Paths {
		if info, err := os.Stat(filePath); err == nil {
			fileList = append(fileList, response.ExistFileInfo{
				Size:    float64(info.Size()),
				Name:    info.Name(),
				Path:    filePath,
				ModTime: info.ModTime(),
				IsDir:   info.IsDir(),
			})
		}
	}
	return fileList
}
