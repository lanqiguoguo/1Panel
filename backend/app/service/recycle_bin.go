package service

import (
	"fmt"
	"math"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/1Panel-dev/1Panel/backend/app/dto"
	"github.com/1Panel-dev/1Panel/backend/app/dto/request"
	"github.com/1Panel-dev/1Panel/backend/app/dto/response"
	"github.com/1Panel-dev/1Panel/backend/buserr"
	"github.com/1Panel-dev/1Panel/backend/constant"
	"github.com/1Panel-dev/1Panel/backend/utils/files"
	"github.com/shirou/gopsutil/v3/disk"
)

type RecycleBinService struct {
}

type IRecycleBinService interface {
	Page(search dto.PageInfo) (int64, []response.RecycleBinDTO, error)
	Create(create request.RecycleBinCreate) error
	Reduce(reduce request.RecycleBinReduce) error
	Clear() error
}

func NewIRecycleBinService() IRecycleBinService {
	return &RecycleBinService{}
}

func (r RecycleBinService) Page(search dto.PageInfo) (int64, []response.RecycleBinDTO, error) {
	partitions, err := disk.Partitions(false)
	if err != nil {
		return 0, nil, err
	}
	result := collectRecycleFiles(partitions)
	startIndex := (search.Page - 1) * search.PageSize
	endIndex := startIndex + search.PageSize

	if startIndex > len(result) {
		return int64(len(result)), result, nil
	}
	if endIndex > len(result) {
		endIndex = len(result)
	}
	return int64(len(result)), result[startIndex:endIndex], nil
}

// collectRecycleFiles enumerates every recycle dir across the given
// partitions. Several mountpoints may alias the same physical directory
// (e.g. WSL2 bind mounts), so the dirs are deduplicated by file identity to
// avoid listing the same recycled item twice.
func collectRecycleFiles(partitions []disk.PartitionStat) []response.RecycleBinDTO {
	var (
		result   []response.RecycleBinDTO
		seenDirs []os.FileInfo
	)
	for _, p := range partitions {
		dir := path.Join(p.Mountpoint, ".1panel_clash")
		dirInfo, err := os.Stat(dir)
		if err != nil {
			continue
		}
		duplicate := false
		for _, seen := range seenDirs {
			if os.SameFile(dirInfo, seen) {
				duplicate = true
				break
			}
		}
		if duplicate {
			continue
		}
		seenDirs = append(seenDirs, dirInfo)
		clashFiles, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, file := range clashFiles {
			if strings.HasPrefix(file.Name(), "_1p_") {
				recycleDTO, err := getRecycleBinDTOFromName(file.Name())
				recycleDTO.IsDir = file.IsDir()
				recycleDTO.From = dir
				if err == nil {
					result = append(result, *recycleDTO)
				}
			}
		}
	}
	return result
}

func (r RecycleBinService) Create(create request.RecycleBinCreate) error {
	op := files.NewFileOp()
	if !op.Stat(create.SourcePath) {
		return buserr.New(constant.ErrLinkPathNotFound)
	}
	if isProtectedPath(create.SourcePath) {
		return buserr.New(constant.ErrPathNotDelete)
	}
	clashDir, err := getClashDir(create.SourcePath)
	if err != nil {
		return err
	}
	paths := strings.Split(create.SourcePath, "/")
	rNamePre := strings.Join(paths, "_1p_")
	deleteTime := time.Now()
	openFile, err := op.OpenFile(create.SourcePath)
	if err != nil {
		return err
	}
	fileInfo, err := openFile.Stat()
	if err != nil {
		return err
	}
	size := 0
	if fileInfo.IsDir() {
		sizeF, err := op.GetDirSize(create.SourcePath)
		if err != nil {
			return err
		}
		size = int(sizeF)
	} else {
		size = int(fileInfo.Size())
	}

	rName := fmt.Sprintf("_1p_%s%s_p_%d_%d", "file", rNamePre, size, deleteTime.Unix())
	return op.Mv(create.SourcePath, path.Join(clashDir, rName))
}

func (r RecycleBinService) Reduce(reduce request.RecycleBinReduce) error {
	// RName must be a plain file name: path separators or traversal
	// elements would let path.Join escape the recycle bin directory.
	if reduce.RName == "." || reduce.RName == ".." || strings.ContainsAny(reduce.RName, `/\`) {
		return buserr.New(constant.ErrCmdIllegal)
	}
	// From 必须是真实存在的回收站目录：它会被 path.Join 直接拼进操作
	// 路径，任意目录会让还原操作读写攻击者指定的位置。
	partitions, err := disk.Partitions(false)
	if err != nil {
		return err
	}
	if !isValidRecycleFrom(reduce.From, partitions) {
		return buserr.New(constant.ErrCmdIllegal)
	}
	filePath := path.Join(reduce.From, reduce.RName)
	op := files.NewFileOp()
	if !op.Stat(filePath) {
		return buserr.New(constant.ErrLinkPathNotFound)
	}
	recycleBinDTO, err := getRecycleBinDTOFromName(reduce.RName)
	if err != nil {
		return err
	}
	// A crafted name can encode ".." segments which resolve outside the
	// location checked below once handled by the OS, so reject them and
	// normalize the source path before any check or operation.
	for _, seg := range strings.Split(recycleBinDTO.SourcePath, "/") {
		if seg == ".." {
			return buserr.New(constant.ErrCmdIllegal)
		}
	}
	sourcePath := filepath.Clean(recycleBinDTO.SourcePath)
	if isProtectedPath(sourcePath) {
		return buserr.New(constant.ErrPathNotDelete)
	}
	// Never restore (or pre-delete) a path inside the very recycle dir the
	// entry lives in: that would RmRf the recycle dir itself with every other
	// recycled entry still inside. (The root recycle dir is already rejected
	// by isProtectedPath above; this covers per-mount clash dirs too.)
	if sourcePath == reduce.From || strings.HasPrefix(sourcePath, strings.TrimSuffix(reduce.From, "/")+"/") {
		return buserr.New(constant.ErrCmdIllegal)
	}
	// The encoded SourcePath must lie on the same filesystem as the recycle
	// dir the entry is being restored from. Create (getClashDir) moves every
	// deleted path into the clash dir of its own mount, so a name encoding a
	// path on another mount (or, for the root clash dir, a path under a
	// dedicated mountpoint) was never produced by a real recycle: an attacker
	// could otherwise plant one entry and have Reduce RmRf an arbitrary
	// same-named directory on a foreign mount. Each mount's clash dirs are
	// root-owned 0755, so planting requires breaking out of the file API.
	if !sourcePathConsistentWithFrom(sourcePath, reduce.From, partitions) {
		return buserr.New(constant.ErrCmdIllegal)
	}
	// sourcePath and filePath are interpolated into shell commands by
	// RmRf/Mv, so reject shell metacharacters beforehand.
	if !files.ValidShellArgs(sourcePath, filePath) {
		return buserr.New(constant.ErrCmdIllegal)
	}
	if !op.Stat(path.Dir(sourcePath)) {
		return buserr.New("ErrSourcePathNotFound")
	}
	if op.Stat(sourcePath) {
		if err = op.RmRf(sourcePath); err != nil {
			return err
		}
	}
	return op.Mv(filePath, sourcePath)
}

func (r RecycleBinService) Clear() error {
	partitions, err := disk.Partitions(false)
	if err != nil {
		return err
	}
	op := files.NewFileOp()
	for _, p := range partitions {
		dir := path.Join(p.Mountpoint, ".1panel_clash")
		if !op.Stat(dir) {
			continue
		}
		newDir := path.Join(p.Mountpoint, "1panel_clash")
		if err := op.Mv(dir, newDir); err != nil {
			return err
		}
		go func() {
			_ = op.DeleteDir(newDir)
		}()
	}
	return nil
}

// isValidRecycleFrom 判断 From 是否为回收站目录之一：各挂载点下的
// .1panel_clash 或根回收站目录 constant.RecycleBinDir。partitions 由
// 调用方传入以便测试。
func isValidRecycleFrom(from string, partitions []disk.PartitionStat) bool {
	cleaned := filepath.Clean(from)
	if cleaned == constant.RecycleBinDir {
		return true
	}
	for _, p := range partitions {
		if cleaned == path.Join(p.Mountpoint, ".1panel_clash") {
			return true
		}
	}
	return false
}

// pathUnderMount 判断 realPath 是否为挂载点本身或位于挂载点之下。
// 简单前缀比较会把兄弟目录（如挂载点 /data 对应的 /data-evil）误判为
// 位于挂载点内，因此必须带上分隔符比较；挂载点为根 "/" 时天然覆盖所有
// 绝对路径。
func pathUnderMount(realPath, mountpoint string) bool {
	if realPath == mountpoint {
		return true
	}
	if mountpoint == "/" {
		return strings.HasPrefix(realPath, string(filepath.Separator))
	}
	return strings.HasPrefix(realPath, mountpoint+string(filepath.Separator))
}

// sourcePathConsistentWithFrom 校验还原条目编码的 SourcePath 与该条目所在
// 回收站目录 (from) 的文件系统归属一致。getClashDir 总是把删除文件移入其
// 所在挂载点的回收站（根挂载之外无匹配挂载点时才用根回收站），因此合法条目
// 必须满足：SourcePath 位于 from 所在挂载点上；根回收站条目还必须不在任何
// 独立挂载点之下（否则它本应进入该挂载点的回收站）。语义与 isValidRecycleFrom
// 完全对称，partitions 由调用方传入以便测试。
func sourcePathConsistentWithFrom(sourcePath, from string, partitions []disk.PartitionStat) bool {
	cleaned := filepath.Clean(sourcePath)
	if cleaned == constant.RecycleBinDir {
		return false
	}
	// A source path inside any recycle dir is never legitimate (getClashDir
	// never recycles a recycle dir; Create refuses protected paths anyway,
	// and the root clash dir is protected).
	for _, p := range partitions {
		clashDir := filepath.Clean(path.Join(p.Mountpoint, ".1panel_clash"))
		if cleaned == clashDir || pathUnderMount(cleaned, clashDir) {
			return false
		}
	}
	// Mirror getClashDir exactly: the first non-root mountpoint the source
	// path lies under owns the entry; otherwise the root clash dir owns it.
	fromMount := "/"
	for _, p := range partitions {
		if p.Mountpoint == "/" {
			continue
		}
		if pathUnderMount(cleaned, p.Mountpoint) {
			fromMount = p.Mountpoint
			break
		}
	}
	if filepath.Clean(from) == constant.RecycleBinDir {
		return fromMount == "/"
	}
	for _, p := range partitions {
		if p.Mountpoint == "/" {
			continue
		}
		if filepath.Clean(from) == filepath.Clean(path.Join(p.Mountpoint, ".1panel_clash")) {
			return fromMount == p.Mountpoint
		}
	}
	return false
}

func getClashDir(realPath string) (string, error) {
	partitions, err := disk.Partitions(false)
	if err != nil {
		return "", err
	}
	for _, p := range partitions {
		if p.Mountpoint == "/" {
			continue
		}
		if pathUnderMount(realPath, p.Mountpoint) {
			clashDir := path.Join(p.Mountpoint, ".1panel_clash")
			if err = createClashDir(path.Join(p.Mountpoint, ".1panel_clash")); err != nil {
				return "", err
			}
			return clashDir, nil
		}
	}
	return constant.RecycleBinDir, createClashDir(constant.RecycleBinDir)
}

func createClashDir(clashDir string) error {
	op := files.NewFileOp()
	if !op.Stat(clashDir) {
		if err := op.CreateDir(clashDir, 0755); err != nil {
			return err
		}
	}
	return nil
}

func getRecycleBinDTOFromName(filename string) (*response.RecycleBinDTO, error) {
	r := regexp.MustCompile(`_1p_file_1p_(.+)_p_(\d+)_(\d+)`)
	matches := r.FindStringSubmatch(filename)
	if len(matches) != 4 {
		return nil, fmt.Errorf("invalid filename format")
	}
	sourcePath := "/" + strings.ReplaceAll(matches[1], "_1p_", "/")
	size, err := strconv.ParseInt(matches[2], 10, 64)
	if err != nil {
		return nil, err
	}
	if size < math.MinInt || size > math.MaxInt {
		return nil, fmt.Errorf("size out of int range")
	}

	deleteTime, err := strconv.ParseInt(matches[3], 10, 64)
	if err != nil {
		return nil, err
	}
	return &response.RecycleBinDTO{
		Name:       path.Base(sourcePath),
		Size:       int(size),
		Type:       "file",
		DeleteTime: time.Unix(deleteTime, 0),
		SourcePath: sourcePath,
		RName:      filename,
	}, nil
}
