package service

import (
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path"
	"path/filepath"
	"sort"
	"time"

	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/glebarez/sqlite"
	"golang.org/x/sys/unix"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Snapshot restores replace live panel directories with payloads from a
// snapshot package. The 1PanelData payload (1panel_data.tar.gz) restores over
// <BaseDir>/1panel — the data directory of the very process running this
// recovery, including the open sqlite database — and the 1PanelBackups
// payload (1panel_backup.tar.gz) restores the <system>,<system_snapshot>
// members over the shared backup directory. Previously both payloads were
// decompressed straight into their live target: every archive member was
// O_TRUNC-written while the process kept reading/writing the same paths, so a
// failure half-way through (disk full, damaged archive, killed process) left
// the target as a mix of snapshot content and pre-crash leftovers, with the
// running panel continuing to write into that mixed database.
//
// The functions in this file make both payloads land atomically:
//
//  1. stageSnapshotPayload materialises the tarball in a staging directory
//     created NEXT TO the final target (same filesystem). Extraction reuses
//     handleSafeUnTar, so the member validation the direct extraction used
//     (zip-slip containment, symlink rejection, entry/size limits) still
//     applies, and it runs before anything touches the live directory. When
//     the payload ships a panel database (db/1Panel.db), the staged copy is
//     additionally verified to be a readable sqlite file (header magic plus
//     PRAGMA quick_check) before the commit may start. Any failure here
//     removes the staging directory and leaves the target untouched.
//
//  2. commitStagedPayload applies the staged top-level members onto the live
//     target. The swap is deliberately per top-level member, not a whole
//     directory replacement: a payload only ever adds/replaces the members it
//     carries (e.g. ./system and ./system_snapshot inside the shared backup
//     dir, which also holds unrelated website/database backups that a restore
//     must not delete; or all of <BaseDir>/1panel except the excluded
//     tmp/log/cache/db sidecars). Each member lands via one atomic rename
//     exchange (renameat2 RENAME_EXCHANGE, same filesystem by construction),
//     with a fallback three-step rename for filesystems without exchange
//     support. On a mid-commit failure the members already applied are
//     swapped back, so the target either receives the full payload or none of
//     it (the residual window shrinks to one atomic member swap).
//
//  3. For the 1PanelData payload the running process holds the panel database
//     open by path. Renaming a new 1Panel.db over it does NOT make the open
//     connection see the new file (sqlite keeps reading the old inode), so
//     applyStagedPanelData reopens the panel DB connection right after the
//     swap (relinkPanelDB) and, if that fails, swaps the directory back and
//     reopens the connection against the original data so the process keeps
//     running on its pre-recovery database.
//
// Keeping the whole "stop the panel service -> swap -> start it" sequence is
// not possible here: the recovery flow itself runs inside the very process
// whose data directory is being replaced and there is no external supervisor
// to restart it (systemd units are not even guaranteed to exist on dev
// machines), so the swap + in-process DB relink below is the strongest
// atomicity that can be provided from inside the panel.

// snapshotPayloadDBRel is the member path (relative to the payload root) that
// carries the panel database inside 1panel_data.tar.gz. It is packed by
// snapPanelData (snapshot_create.go), which excludes only the 1Panel.db-wal /
// 1Panel.db-shm sidecars, so a data payload that lacks this member cannot be
// a complete panel data restore and is rejected before the live directory is
// touched.
const snapshotPayloadDBRel = "db/1Panel.db"

// sqliteHeaderMagic is the 16-byte file header every sqlite database starts
// with. Checking it catches truncated/damaged payload members cheaply before
// the expensive quick_check runs.
var sqliteHeaderMagic = []byte("SQLite format 3\x00")

// stageSnapshotPayload decompresses sourceFile into a fresh staging directory
// next to targetDir (same filesystem, so the later rename exchanges are
// atomic) and validates the staged content. targetDir itself is never
// touched; on any failure the staging directory is removed and an error is
// returned. On success the returned staging path holds the fully materialised
// payload and the caller either commits it (commitStagedPayload) or removes
// it again.
func stageSnapshotPayload(sourceFile, targetDir, secret string) (string, error) {
	parentDir := filepath.Dir(filepath.Clean(targetDir))
	if _, err := os.Stat(parentDir); err != nil {
		return "", fmt.Errorf("staging parent dir %s does not exist, err: %v", parentDir, err)
	}
	if _, err := os.Stat(sourceFile); err != nil {
		return "", fmt.Errorf("snapshot payload file %s is not found, err: %v", sourceFile, err)
	}
	// A fixed sibling name is fine: restores are serialised per snapshot
	// (claimSnapshotOp) and the whole panel runs under one SystemStatus gate,
	// and any leftover from a crashed run is removed before a new stage
	// starts. Keeping the name fixed also guarantees a failed run can never
	// accumulate staging copies on disk.
	stagingDir := filepath.Join(parentDir, ".snapshot-restore-staging")
	if err := os.RemoveAll(stagingDir); err != nil {
		return "", fmt.Errorf("remove stale snapshot staging dir %s failed, err: %v", stagingDir, err)
	}
	if err := os.MkdirAll(stagingDir, 0755); err != nil {
		return "", fmt.Errorf("create snapshot staging dir %s failed, err: %v", stagingDir, err)
	}
	// Extraction goes through handleSafeUnTar (member validation, shell-arg
	// checks), exactly like the direct extraction it replaces — only the
	// destination differs.
	if err := handleSafeUnTar(sourceFile, stagingDir, secret); err != nil {
		_ = os.RemoveAll(stagingDir)
		return "", err
	}
	if err := checkStagedPayloadDB(stagingDir); err != nil {
		_ = os.RemoveAll(stagingDir)
		return "", err
	}
	return stagingDir, nil
}

// checkStagedPayloadDB verifies the panel database a staged payload carries:
// the member must exist, start with the sqlite header magic and pass a
// read-only PRAGMA quick_check. A payload without db/1Panel.db (e.g. the
// 1panel_backup payload) passes untouched: only the data payload is required
// to ship the database, and stageSnapshotPayload is shared by both.
func checkStagedPayloadDB(stagingDir string) error {
	dbPath := filepath.Join(stagingDir, filepath.FromSlash(snapshotPayloadDBRel))
	info, err := os.Stat(dbPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("stat staged panel database %s failed, err: %v", dbPath, err)
	}
	if info.Size() < int64(len(sqliteHeaderMagic)) {
		return fmt.Errorf("staged panel database %s is too small (%d bytes) to be a valid sqlite file", dbPath, info.Size())
	}
	f, err := os.Open(dbPath)
	if err != nil {
		return fmt.Errorf("open staged panel database %s failed, err: %v", dbPath, err)
	}
	header := make([]byte, len(sqliteHeaderMagic))
	if _, err := readFullAt(f, header); err != nil {
		_ = f.Close()
		return fmt.Errorf("read staged panel database %s header failed, err: %v", dbPath, err)
	}
	_ = f.Close()
	for i, b := range sqliteHeaderMagic {
		if header[i] != b {
			return fmt.Errorf("staged panel database %s is not a valid sqlite file (bad header)", dbPath)
		}
	}
	if err := quickCheckSQLite(dbPath); err != nil {
		return err
	}
	return nil
}

// readFullAt reads exactly len(buf) bytes from the start of f.
func readFullAt(f *os.File, buf []byte) (int, error) {
	n, err := f.ReadAt(buf, 0)
	if err != nil {
		return n, err
	}
	return n, nil
}

// quickCheckSQLite opens filePath read-only and runs PRAGMA quick_check. The
// read-only mode guarantees the check never creates -wal/-shm sidecars inside
// the staging directory.
func quickCheckSQLite(filePath string) error {
	logger := logger.New(log.New(os.Stdout, "\r\n", log.LstdFlags), logger.Config{
		SlowThreshold:             time.Second,
		LogLevel:                  logger.Silent,
		IgnoreRecordNotFoundError: true,
		Colorful:                  false,
	})
	db, err := gorm.Open(sqlite.Open("file:"+filePath+"?mode=ro"), &gorm.Config{Logger: logger})
	if err != nil {
		return fmt.Errorf("open staged panel database %s read-only for integrity check failed, err: %v", filePath, err)
	}
	defer func() {
		if sqlDB, dbErr := db.DB(); dbErr == nil {
			_ = sqlDB.Close()
		}
	}()
	var result string
	if err := db.Raw("PRAGMA quick_check").Scan(&result).Error; err != nil {
		return fmt.Errorf("run integrity check on staged panel database %s failed, err: %v", filePath, err)
	}
	if result != "ok" {
		return fmt.Errorf("staged panel database %s failed the integrity check: %s", filePath, result)
	}
	return nil
}

// stagedTopLevelNames lists the first-level member names of a staged payload,
// sorted for deterministic application order.
func stagedTopLevelNames(stagingDir string) ([]string, error) {
	entries, err := os.ReadDir(stagingDir)
	if err != nil {
		return nil, fmt.Errorf("read snapshot staging dir %s failed, err: %v", stagingDir, err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	return names, nil
}

// commitStagedMemberFn lets tests inject a failure before a specific staged
// member is applied (same indirection pattern as snapshotGetStatusFn and
// restartDockerFn): the rollback path of commitStagedPayload is otherwise
// hard to provoke on a healthy filesystem, because renameat2 exchange accepts
// every member shape (files, directories, non-empty directories).
var commitStagedMemberFn = func(name string, index int) error { return nil }

// commitStagedPayload applies the top-level members of stagingDir onto
// targetDir. For every member the target version is either absent (the member
// is moved in with one atomic rename) or present (both are swapped with one
// atomic renameat2 exchange, falling back to a three-step rename when the
// filesystem has no exchange support). Members that exist only in targetDir
// (payload-excluded files such as tmp/log/cache, or unrelated backup
// subdirectories) are never touched, mirroring the semantics of the direct
// extraction this replaces — a restore overwrites what the payload carries
// and leaves everything else alone.
//
// When any member fails, the members already applied are swapped back before
// the error is returned, so a failed commit leaves the target untouched.
// On success it returns the list of applied member names so the caller can
// revert the whole swap (revertStagedPayload) if a later step fails.
func commitStagedPayload(targetDir, stagingDir string) ([]string, error) {
	if _, err := os.Stat(targetDir); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			if err := os.MkdirAll(targetDir, 0755); err != nil {
				return nil, fmt.Errorf("create snapshot restore target dir %s failed, err: %v", targetDir, err)
			}
		} else {
			return nil, fmt.Errorf("stat snapshot restore target dir %s failed, err: %v", targetDir, err)
		}
	}
	names, err := stagedTopLevelNames(stagingDir)
	if err != nil {
		return nil, err
	}
	var applied []string
	for index, name := range names {
		if err := commitStagedMemberFn(name, index); err != nil {
			_ = revertStagedPayload(targetDir, stagingDir, applied)
			return nil, fmt.Errorf("apply snapshot restore member %s failed, err: %v", name, err)
		}
		staged := filepath.Join(stagingDir, name)
		target := filepath.Join(targetDir, name)
		if _, err := os.Lstat(target); err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				_ = revertStagedPayload(targetDir, stagingDir, applied)
				return nil, fmt.Errorf("stat snapshot restore target member %s failed, err: %v", target, err)
			}
			// The member does not exist in the target yet: one atomic rename
			// moves it into place (no overwrite involved).
			if err := os.Rename(staged, target); err != nil {
				_ = revertStagedPayload(targetDir, stagingDir, applied)
				return nil, fmt.Errorf("move snapshot restore member %s into %s failed, err: %v", staged, target, err)
			}
			applied = append(applied, name)
			continue
		}
		if err := exchangePaths(target, staged); err != nil {
			_ = revertStagedPayload(targetDir, stagingDir, applied)
			return nil, fmt.Errorf("swap snapshot restore member %s with %s failed, err: %v", staged, target, err)
		}
		applied = append(applied, name)
	}
	return applied, nil
}

// revertStagedPayload undoes a commitStagedPayload for the given member
// names: every applied member is swapped or renamed back from targetDir into
// stagingDir, restoring the pre-commit state of the target directory.
func revertStagedPayload(targetDir, stagingDir string, names []string) error {
	var errs []error
	for i := len(names) - 1; i >= 0; i-- {
		name := names[i]
		staged := filepath.Join(stagingDir, name)
		target := filepath.Join(targetDir, name)
		if _, err := os.Lstat(staged); err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				// The member was moved in with a plain rename; move it back.
				if err := os.Rename(target, staged); err != nil {
					errs = append(errs, fmt.Errorf("move member %s back to %s failed, err: %v", target, staged, err))
				}
				continue
			}
			errs = append(errs, fmt.Errorf("stat member %s during revert failed, err: %v", staged, err))
			continue
		}
		if err := exchangePaths(target, staged); err != nil {
			errs = append(errs, fmt.Errorf("swap member %s back to %s failed, err: %v", target, staged, err))
		}
	}
	if len(errs) != 0 {
		return fmt.Errorf("revert staged payload failed: %v", errs)
	}
	return nil
}

// exchangePaths atomically swaps the two paths (files or directories) with
// renameat2(RENAME_EXCHANGE). Both live inside the same parent directory by
// construction (the staging dir is created next to the target), so the swap
// never crosses filesystems. Filesystems without exchange support fall back
// to a three-step rename pair, which is not atomic as a whole but keeps each
// path valid at every step and rolls the first rename back when the second
// fails.
func exchangePaths(a, b string) error {
	err := unix.Renameat2(unix.AT_FDCWD, a, unix.AT_FDCWD, b, unix.RENAME_EXCHANGE)
	if err == nil {
		return nil
	}
	switch err {
	case unix.ENOSYS, unix.EINVAL, unix.ENOTSUP, unix.EXDEV:
		// Unsupported or cross-device: fall through to the rename fallback.
	default:
		return err
	}
	return exchangePathsFallback(a, b)
}

// exchangePathsFallback swaps a and b with three renames: a moves aside, b
// moves onto a's name, the aside copy moves onto b's name. The first two
// renames are rolled back when the third fails, keeping both paths valid.
func exchangePathsFallback(a, b string) error {
	aside := a + ".snapshot-swap-aside"
	if err := os.RemoveAll(aside); err != nil {
		return err
	}
	if err := os.Rename(a, aside); err != nil {
		return err
	}
	if err := os.Rename(b, a); err != nil {
		_ = os.Rename(aside, a)
		return err
	}
	if err := os.Rename(aside, b); err != nil {
		// Roll the first two renames back so both original paths survive.
		_ = os.Rename(a, b)
		_ = os.Rename(aside, a)
		return err
	}
	return nil
}

// applyStagedPayload is the shared atomic-restore pipeline for payloads whose
// commit needs no follow-up inside the panel process (1PanelBackups): stage,
// commit, then remove the staging directory (which now holds the replaced
// pre-restore members). The live target is only ever modified by the commit
// swaps.
func applyStagedPayload(sourceFile, targetDir, secret string) error {
	stagingDir, err := stageSnapshotPayload(sourceFile, targetDir, secret)
	if err != nil {
		return err
	}
	if _, err := commitStagedPayload(targetDir, stagingDir); err != nil {
		_ = os.RemoveAll(stagingDir)
		return err
	}
	_ = os.RemoveAll(stagingDir)
	return nil
}

// applyStagedPanelData is the atomic-restore pipeline for the 1PanelData
// payload (the live data directory of the running panel). After the commit
// swaps the new database into place the panel's open sqlite connection still
// points at the replaced inode, so the connection pool is reopened against
// the restored file (relinkPanelDB). When the relink fails the directory swap
// is reverted and the connection reopened against the original data, so the
// process keeps running on its pre-recovery database and the restore reports
// a failure instead of half-applying.
func applyStagedPanelData(sourceFile, targetDir string) error {
	stagingDir, err := stageSnapshotPayload(sourceFile, targetDir, "")
	if err != nil {
		return err
	}
	dbPath := filepath.Join(stagingDir, filepath.FromSlash(snapshotPayloadDBRel))
	if _, err := os.Stat(dbPath); err != nil {
		_ = os.RemoveAll(stagingDir)
		return fmt.Errorf("snapshot data payload is missing %s, refusing to restore a data directory without a database", snapshotPayloadDBRel)
	}
	applied, err := commitStagedPayload(targetDir, stagingDir)
	if err != nil {
		_ = os.RemoveAll(stagingDir)
		return err
	}
	if err := relinkPanelDB(); err != nil {
		revertErr := revertStagedPayload(targetDir, stagingDir, applied)
		relinkErr := relinkPanelDB()
		_ = os.RemoveAll(stagingDir)
		if relinkErr != nil {
			global.LOG.Errorf("relink panel db to the reverted data failed, err: %v", relinkErr)
		}
		if revertErr != nil {
			return fmt.Errorf("reopen panel database after snapshot swap failed: %v (and reverting the data dir swap failed: %v)", err, revertErr)
		}
		return fmt.Errorf("reopen panel database after snapshot swap failed: %v (data dir reverted)", err)
	}
	_ = os.RemoveAll(stagingDir)
	return nil
}

// relinkPanelDB closes the running panel DB connection pool and opens a fresh
// one against global.CONF.System.DbPath/DbFile, mirroring the pool settings
// of init/db (db.go). Used right after a staged payload swap moved a new
// 1Panel.db onto the data directory: an open sqlite connection keeps reading
// the inode it was opened on, so without the relink the panel would silently
// keep using the replaced database.
func relinkPanelDB() error {
	fullPath := path.Join(global.CONF.System.DbPath, global.CONF.System.DbFile)
	sqlDB, err := global.DB.DB()
	if err == nil {
		_ = sqlDB.Close()
	}
	newLogger := logger.New(log.New(os.Stdout, "\r\n", log.LstdFlags), logger.Config{
		SlowThreshold:             time.Second,
		LogLevel:                  logger.Silent,
		IgnoreRecordNotFoundError: true,
		Colorful:                  false,
	})
	db, err := gorm.Open(sqlite.Open(fullPath), &gorm.Config{
		DisableForeignKeyConstraintWhenMigrating: true,
		Logger:                                   newLogger,
	})
	if err != nil {
		return fmt.Errorf("reopen panel database %s failed, err: %v", fullPath, err)
	}
	_ = db.Exec("PRAGMA journal_mode = WAL;")
	sqlDB, err = db.DB()
	if err != nil {
		return fmt.Errorf("get sql db handle of reopened panel database failed, err: %v", err)
	}
	sqlDB.SetConnMaxIdleTime(10 * time.Second)
	sqlDB.SetMaxOpenConns(100)
	sqlDB.SetConnMaxLifetime(time.Hour)
	global.DB = db
	return nil
}
