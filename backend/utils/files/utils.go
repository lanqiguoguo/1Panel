package files

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

func IsSymlink(mode os.FileMode) bool {
	return mode&os.ModeSymlink != 0
}

func IsBlockDevice(mode os.FileMode) bool {
	return mode&os.ModeDevice != 0 && mode&os.ModeCharDevice == 0
}

func GetMimeType(path string) string {
	file, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer file.Close()

	buffer := make([]byte, 512)
	_, err = file.Read(buffer)
	if err != nil {
		return ""
	}
	mimeType := http.DetectContentType(buffer)
	return mimeType
}

func GetSymlink(path string) string {
	linkPath, err := os.Readlink(path)
	if err != nil {
		return ""
	}
	return linkPath
}

func GetUsername(uid uint32) string {
	usr, err := user.LookupId(strconv.Itoa(int(uid)))
	if err != nil {
		return ""
	}
	return usr.Username
}

func GetGroup(gid uint32) string {
	usr, err := user.LookupGroupId(strconv.Itoa(int(gid)))
	if err != nil {
		return ""
	}
	return usr.Name
}

const dotCharacter = 46

func IsHidden(path string) bool {
	return path[0] == dotCharacter
}

func countLines(path string) (int, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer file.Close()
	reader := bufio.NewReader(file)
	count := 0
	for {
		_, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				if count > 0 {
					count++
				}
				return count, nil
			}
			return count, err
		}
		count++
	}
}

func ReadFileByLine(filename string, page, pageSize int, latest bool) (lines []string, isEndOfFile bool, total int, err error) {
	if !NewFileOp().Stat(filename) {
		return
	}
	file, err := os.Open(filename)
	if err != nil {
		return
	}
	defer file.Close()

	totalLines, err := countLines(filename)
	if err != nil {
		return
	}
	total = (totalLines + pageSize - 1) / pageSize
	reader := bufio.NewReaderSize(file, 8192)

	if latest {
		page = total
	}
	currentLine := 0
	startLine := (page - 1) * pageSize
	endLine := startLine + pageSize

	for {
		line, _, err := reader.ReadLine()
		if err == io.EOF {
			break
		}
		if currentLine >= startLine && currentLine < endLine {
			lines = append(lines, string(line))
		}
		currentLine++
		if currentLine >= endLine {
			break
		}
	}

	isEndOfFile = currentLine < endLine
	return
}

func GetParentMode(path string) (os.FileMode, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return 0, err
	}

	for {
		fileInfo, err := os.Stat(absPath)
		if err == nil {
			return fileInfo.Mode() & os.ModePerm, nil
		}
		if !os.IsNotExist(err) {
			return 0, err
		}

		parentDir := filepath.Dir(absPath)
		if parentDir == absPath {
			return 0, fmt.Errorf("no existing directory found in the path: %s", path)
		}
		absPath = parentDir
	}
}

func IsInvalidChar(name string) bool {
	return strings.Contains(name, "&")
}

// ValidNameComponent reports whether name is safe to embed into a
// filesystem path (and, for image names, into a docker build tag) without
// escaping the intended root directory.
//
// The check is a whitelist: every slash-separated component must be
// non-empty and must not be "." or "..", the name may not start with "/"
// or a leading dot (which would make it hidden or absolute), and every
// character must be in the printable set used by image names
// (repo/namespace slashes, tag colons) and path components
// ([a-zA-Z0-9_.-]).
//
// The character set intentionally keeps both cases and is looser than the
// docker reference spec (lowercase-only repository names) so that names
// previously accepted by the API keep working; docker itself reports the
// invalid tag error at build time. The goal here is preventing path
// traversal, not re-implementing the docker reference grammar.
func ValidNameComponent(name string) bool {
	if name == "" || len(name) > 255 {
		return false
	}
	if strings.HasPrefix(name, ".") || strings.HasPrefix(name, "/") {
		return false
	}
	for _, comp := range strings.Split(name, "/") {
		if comp == "" || comp == "." || comp == ".." {
			return false
		}
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z') && !(r >= 'A' && r <= 'Z') && !(r >= '0' && r <= '9') &&
			r != '_' && r != '-' && r != '.' && r != '/' && r != ':' {
			return false
		}
	}
	return true
}

// imageRefRegexp whitelists docker image references of the form
// [registry-host:port/][path-component/]...path-component[:tag][@sha256:hex64].
//
// Grammar pieces (loosened from the distribution/reference spec only by
// accepting both cases, matching ValidNameComponent's approach):
//   - path component: alphanumerics, separators . _ - in runs that must be
//     followed by more alphanumerics (no leading/trailing separator)
//   - registry host: an explicit host[:port]/ prefix, e.g. reg.example.com:5000/
//   - tag: [a-zA-Z0-9_] then [a-zA-Z0-9._-], at most 128 chars (docker limit)
//   - digest: sha256 followed by exactly 64 lowercase hex chars
//
// The first component of a reference without an explicit port (e.g. the
// ghcr.io of ghcr.io/owner/img) parses as a plain path component, which is
// fine for a safety whitelist: every accepted string is drawn from the same
// safe charset regardless of which piece is the registry.
//
// The goal is preventing shell/option injection: references coming from
// remote docker-compose.yml content must never carry shell metacharacters
// ($ ` ( ) & | ; quotes spaces newlines), leading "-" (option injection
// against the docker CLI), or anything outside the grammar above.
var imageRefRegexp = regexp.MustCompile(`^` +
	// optional registry host with port, e.g. reg.example.com:5000/
	`(?:[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?:[0-9]+/)?` +
	// zero or more repository path components, then the final one
	`(?:[a-zA-Z0-9]+(?:[._-]+[a-zA-Z0-9]+)*/)*[a-zA-Z0-9]+(?:[._-]+[a-zA-Z0-9]+)*` +
	// optional tag
	`(?::[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127})?` +
	// optional digest
	`(?:@sha256:[a-f0-9]{64})?` +
	`$`)

// ValidImageRef reports whether ref is a syntactically safe docker image
// reference ([registry/]name[:tag][@sha256:digest]). It is a pure whitelist
// check, aligned in style with ValidNameComponent: anything outside the
// docker reference grammar - shell metacharacters, leading "-" options,
// empty strings, whitespace - is rejected.
func ValidImageRef(ref string) bool {
	if ref == "" || len(ref) > 512 {
		return false
	}
	return imageRefRegexp.MatchString(ref)
}

func IsEmptyDir(dir string) bool {
	f, err := os.Open(dir)
	if err != nil {
		return false
	}
	defer f.Close()
	_, err = f.Readdirnames(1)
	return err == io.EOF
}
