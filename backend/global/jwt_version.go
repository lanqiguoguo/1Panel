package global

import (
	"strconv"
	"sync"
	"time"

	"gorm.io/gorm"
)

// JWT session-version constants. They live in global (not constant) because
// constant/dir.go imports global, so global cannot import constant without an
// import cycle; constant/session.go re-exports aliases for callers that use
// the constant package.
const (
	// JWTVersionSettingKey is the settings row tracking the current JWT
	// session version. Every JWT minted at login bakes the value of this row
	// into its claims; whenever sessions are globally revoked (SESSION.Clean,
	// e.g. password / user-name / MFA / security-entrance changes) the row is
	// bumped, so tokens signed before the change stop validating. Tokens
	// without a version (minted by older releases, SV defaults to 0) are
	// treated as version 0 and rejected as soon as the current version is 1.
	JWTVersionSettingKey = "JWTRefreshVersion"
	// DefaultJWTRefreshVersion is the version the settings row is seeded with
	// (fresh installs and upgrades); a missing row is read as this value.
	DefaultJWTRefreshVersion = 1

	// settingsTableName mirrors model.Setting's table; importing app/model
	// here would create an import cycle (model -> constant -> global), so the
	// tracker addresses the table through this local row type.
	settingsTableName = "settings"
)

// JWTRefreshVersionTTL bounds how long the in-process cache of the current
// JWT refresh version may live. The version only changes on security-relevant
// setting updates (password / user-name / MFA / security-entrance changes,
// i.e. everywhere SESSION.Clean runs), which are rare operator actions, and
// every one of them bumps the cache synchronously (see Bump), so the TTL only
// covers the window in which the process itself could not have bumped yet. A
// per-request SQL round-trip on every authenticated JWT call would be the
// alternative; the cached read is the deliberate trade-off.
const JWTRefreshVersionTTL = 3 * time.Second

// jwtVersionRow is a minimal projection of the settings table used to read
// and write the version row without importing app/model (see
// settingsTableName).
type jwtVersionRow struct {
	ID        uint `gorm:"primarykey;AUTO_INCREMENT" json:"id"`
	CreatedAt time.Time
	UpdatedAt time.Time
	Key       string `gorm:"type:varchar(256);not null;"`
	Value     string `gorm:"type:varchar(256)"`
}

func (jwtVersionRow) TableName() string { return settingsTableName }

// JWTRefreshVersion is the process-local authority for the current JWT
// session version. JWT validation runs in middleware, which must not import
// app/service (service imports utils/jwt, so that would be an import cycle),
// hence the tracker lives in global and is wired to a *gorm.DB at call time.
// The zero value is usable: the first Version() call falls through to the
// database and defaults to DefaultJWTRefreshVersion.
//
// 1Panel runs as a single process, so the in-memory tracker is the only
// writer and no cross-process synchronization is required.
type JWTRefreshVersion struct {
	mu       sync.Mutex
	current  int64     // last known version; 0 means "not loaded yet"
	loadedAt time.Time // when current was last refreshed from the database
}

// Version returns the current JWT refresh version, refreshing the cache when
// it is empty or older than JWTRefreshVersionTTL. A missing or unparsable
// settings row reads as DefaultJWTRefreshVersion (fail-safe: never mint or
// accept tokens under an invented version).
func (v *JWTRefreshVersion) Version(db *gorm.DB) int64 {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.current > 0 && time.Since(v.loadedAt) < JWTRefreshVersionTTL {
		return v.current
	}
	version, err := v.readVersion(db)
	if err == nil {
		v.current = version
	} else if v.current == 0 {
		// Transient database failure on first load: fall back to the default
		// so JWT auth keeps working; the next read (after the TTL) retries.
		v.current = DefaultJWTRefreshVersion
	}
	v.loadedAt = time.Now()
	return v.current
}

// Bump persists version+1 in the settings row and refreshes the cache, so
// every JWT minted before the bump stops validating immediately. The stored
// version only ever moves forward (the read is fresh, under the mutex), so a
// token signed under a higher version can never become valid again because
// of a concurrent or stale write.
func (v *JWTRefreshVersion) Bump(db *gorm.DB) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if db == nil {
		// No database (unit tests constructing the session store directly):
		// nothing to persist, but keep the in-memory view consistent so
		// callers still observe a version increase.
		v.current++
		v.loadedAt = time.Now()
		return nil
	}
	if err := v.ensureRow(db); err != nil {
		return err
	}
	version, err := v.readVersion(db)
	if err != nil {
		return err
	}
	next := version + 1
	if err := db.Table(settingsTableName).
		Where("key = ?", JWTVersionSettingKey).
		Update("value", strconv.FormatInt(next, 10)).Error; err != nil {
		return err
	}
	v.current = next
	v.loadedAt = time.Now()
	return nil
}

func (v *JWTRefreshVersion) ensureRow(db *gorm.DB) error {
	if db == nil {
		return nil
	}
	var existing jwtVersionRow
	err := db.Table(settingsTableName).
		Where("key = ?", JWTVersionSettingKey).
		First(&existing).Error
	if err == nil {
		return nil
	}
	if err != gorm.ErrRecordNotFound {
		return err
	}
	row := jwtVersionRow{
		Key:   JWTVersionSettingKey,
		Value: strconv.Itoa(DefaultJWTRefreshVersion),
	}
	return db.Table(settingsTableName).Create(&row).Error
}

// readVersion returns the persisted version. A missing row, a nil database
// or an unparsable value all read as DefaultJWTRefreshVersion (the last case
// also lets the next Bump repair the corrupt value).
func (v *JWTRefreshVersion) readVersion(db *gorm.DB) (int64, error) {
	if db == nil {
		return DefaultJWTRefreshVersion, nil
	}
	var existing jwtVersionRow
	err := db.Table(settingsTableName).
		Where("key = ?", JWTVersionSettingKey).
		First(&existing).Error
	if err == gorm.ErrRecordNotFound {
		return DefaultJWTRefreshVersion, nil
	}
	if err != nil {
		return 0, err
	}
	version, parseErr := strconv.ParseInt(existing.Value, 10, 64)
	if parseErr != nil {
		return DefaultJWTRefreshVersion, nil
	}
	return version, nil
}
