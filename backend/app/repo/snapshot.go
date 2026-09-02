package repo

import (
	"github.com/1Panel-dev/1Panel/backend/app/model"
	"github.com/1Panel-dev/1Panel/backend/constant"
	"github.com/1Panel-dev/1Panel/backend/global"
)

type ISnapshotRepo interface {
	Get(opts ...DBOption) (model.Snapshot, error)
	GetList(opts ...DBOption) ([]model.Snapshot, error)
	Create(snap *model.Snapshot) error
	Update(id uint, vars map[string]interface{}) error
	Page(limit, offset int, opts ...DBOption) (int64, []model.Snapshot, error)
	Delete(opts ...DBOption) error

	// BeginRecover atomically marks the snapshot row as having a recover in
	// flight (recover_status -> Waiting) via a conditional UPDATE. Waiting is
	// the status the recover flow itself persists and the UI/hook understand,
	// so the claim doubles as the in-flight marker. The WHERE clause rejects
	// any row whose recover_status or rollback_status is Waiting or Running:
	// a recover may not start while a recover, a rollback or a delete (see
	// Delete) owns the row. Returns how many rows the update touched: 1 means
	// this caller won the claim (also across panel processes on the same data
	// dir), 0 means another flow already owns the snapshot.
	BeginRecover(id uint) (int64, error)

	// BeginRollback atomically marks the snapshot row as having a rollback in
	// flight (rollback_status -> Waiting), mirroring BeginRecover on the
	// rollback column. Recover and rollback are mutually exclusive because
	// both flows replace the same live data directory: each begin refuses to
	// start while the other column (or its own) is Waiting/Running.
	BeginRollback(id uint) (int64, error)

	GetStatus(snapID uint) (model.SnapshotStatus, error)
	GetStatusList(opts ...DBOption) ([]model.SnapshotStatus, error)
	CreateStatus(snap *model.SnapshotStatus) error
	DeleteStatus(snapID uint) error
	UpdateStatus(id uint, vars map[string]interface{}) error
}

func NewISnapshotRepo() ISnapshotRepo {
	return &SnapshotRepo{}
}

type SnapshotRepo struct{}

func (u *SnapshotRepo) Get(opts ...DBOption) (model.Snapshot, error) {
	var Snapshot model.Snapshot
	db := global.DB
	for _, opt := range opts {
		db = opt(db)
	}
	err := db.First(&Snapshot).Error
	return Snapshot, err
}

func (u *SnapshotRepo) GetList(opts ...DBOption) ([]model.Snapshot, error) {
	var snaps []model.Snapshot
	db := global.DB.Model(&model.Snapshot{})
	for _, opt := range opts {
		db = opt(db)
	}
	err := db.Find(&snaps).Error
	return snaps, err
}

func (u *SnapshotRepo) Page(page, size int, opts ...DBOption) (int64, []model.Snapshot, error) {
	var users []model.Snapshot
	db := global.DB.Model(&model.Snapshot{})
	for _, opt := range opts {
		db = opt(db)
	}
	count := int64(0)
	db = db.Count(&count)
	err := db.Limit(size).Offset(size * (page - 1)).Find(&users).Error
	return count, users, err
}

func (u *SnapshotRepo) Create(Snapshot *model.Snapshot) error {
	return global.DB.Create(Snapshot).Error
}

func (u *SnapshotRepo) Update(id uint, vars map[string]interface{}) error {
	return global.DB.Model(&model.Snapshot{}).Where("id = ?", id).Updates(vars).Error
}

// recoverOpBlockedStatuses are the row states that block a new
// recover/rollback: Waiting/Running on either the recover or the rollback
// column means a flow owns the row (in this process or another). A row with
// a terminal status (Success/Failed) or no history is free to be recovered;
// a row that was rolled back successfully is cleared entirely and free again.
var recoverOpBlockedStatuses = []string{constant.StatusWaiting, constant.StatusRunning}

// BeginRecover implements ISnapshotRepo.BeginRecover. RowsAffected is
// guaranteed by the WHERE clause on the primary key: a single UPDATE row on
// success, none when another flow already owns the snapshot.
func (u *SnapshotRepo) BeginRecover(id uint) (int64, error) {
	result := global.DB.Model(&model.Snapshot{}).
		Where("id = ?", id).
		Where("recover_status NOT IN (?) OR recover_status IS NULL", recoverOpBlockedStatuses).
		Where("rollback_status NOT IN (?) OR rollback_status IS NULL", recoverOpBlockedStatuses).
		Update("recover_status", constant.StatusWaiting)
	return result.RowsAffected, result.Error
}

// BeginRollback implements ISnapshotRepo.BeginRollback: the rollback flow
// owns the rollback_status column and refuses to start while a recover (or
// another rollback) is in flight on either column.
func (u *SnapshotRepo) BeginRollback(id uint) (int64, error) {
	result := global.DB.Model(&model.Snapshot{}).
		Where("id = ?", id).
		Where("recover_status NOT IN (?) OR recover_status IS NULL", recoverOpBlockedStatuses).
		Where("rollback_status NOT IN (?) OR rollback_status IS NULL", recoverOpBlockedStatuses).
		Update("rollback_status", constant.StatusWaiting)
	return result.RowsAffected, result.Error
}

func (u *SnapshotRepo) Delete(opts ...DBOption) error {
	db := global.DB
	for _, opt := range opts {
		db = opt(db)
	}
	return db.Delete(&model.Snapshot{}).Error
}

func (u *SnapshotRepo) GetStatus(snapID uint) (model.SnapshotStatus, error) {
	var data model.SnapshotStatus
	if err := global.DB.Where("snap_id = ?", snapID).First(&data).Error; err != nil {
		return data, err
	}
	return data, nil
}

func (u *SnapshotRepo) GetStatusList(opts ...DBOption) ([]model.SnapshotStatus, error) {
	var status []model.SnapshotStatus
	db := global.DB.Model(&model.SnapshotStatus{})
	for _, opt := range opts {
		db = opt(db)
	}
	err := db.Find(&status).Error
	return status, err
}

func (u *SnapshotRepo) CreateStatus(snap *model.SnapshotStatus) error {
	return global.DB.Create(snap).Error
}

func (u *SnapshotRepo) DeleteStatus(snapID uint) error {
	return global.DB.Where("snap_id = ?", snapID).Delete(&model.SnapshotStatus{}).Error
}

func (u *SnapshotRepo) UpdateStatus(id uint, vars map[string]interface{}) error {
	return global.DB.Model(&model.SnapshotStatus{}).Where("id = ?", id).Updates(vars).Error
}
