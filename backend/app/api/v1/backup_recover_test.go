package v1

import (
	"testing"

	"github.com/1Panel-dev/1Panel/backend/app/service"
)

// TestRecoverByUploadDataDirContainment pins the containment rule used by
// RecoverByUpload: the uploaded recovery archive must resolve strictly inside
// the panel data dir. The Rel-based check (service.PathInsideDir, sharing the
// primitive pinned by service's own tests) replaces the deprecated
// filepath.HasPrefix and rejects sibling-prefix names such as
// "<DataDir>Evil" that a lexical prefix match could confuse; a path equal to
// DataDir itself is not an uploaded archive and stays rejected, so the
// behavior is not loosened.
func TestRecoverByUploadDataDirContainment(t *testing.T) {
	dataDir := "/opt/1panel/data"

	valid := []string{
		"/opt/1panel/data/uploads/x.tar.gz",
		"/opt/1panel/data/uploads/sub/x.tar.gz",
		"/opt/1panel/data/./uploads/x.tar.gz", // Clean folds the redundant component
	}
	for _, p := range valid {
		if !service.PathInsideDir(p, dataDir, false) {
			t.Errorf("PathInsideDir(%q, %q) = false, want true", p, dataDir)
		}
	}

	invalid := []string{
		"",                              // empty
		"uploads/x.tar.gz",              // relative
		"../x.tar.gz",                   // relative escape
		"/opt/1panel/data",              // the dir itself is not a recover file
		"/opt",                          // parent
		"/etc/passwd",                   // system file
		"/opt/1panel/dataEvil/x.tar.gz", // sibling prefix (HasPrefix confusion case)
		"/opt/1panel/data/../x.tar.gz",  // ".." folds out of the data dir
	}
	for _, p := range invalid {
		if service.PathInsideDir(p, dataDir, false) {
			t.Errorf("PathInsideDir(%q, %q) = true, want false", p, dataDir)
		}
	}
}
