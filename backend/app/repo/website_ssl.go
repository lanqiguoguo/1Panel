package repo

import (
	"context"
	"github.com/1Panel-dev/1Panel/backend/app/model"
	"github.com/1Panel-dev/1Panel/backend/constant"
	"gorm.io/gorm"
)

func NewISSLRepo() ISSLRepo {
	return &WebsiteSSLRepo{}
}

type ISSLRepo interface {
	WithByAlias(alias string) DBOption
	WithByAcmeAccountId(acmeAccountId uint) DBOption
	WithByDnsAccountId(dnsAccountId uint) DBOption
	WithByCAID(caID uint) DBOption
	Page(page, size int, opts ...DBOption) (int64, []model.WebsiteSSL, error)
	GetFirst(opts ...DBOption) (*model.WebsiteSSL, error)
	List(opts ...DBOption) ([]model.WebsiteSSL, error)
	Create(ctx context.Context, ssl *model.WebsiteSSL) error
	Save(ssl *model.WebsiteSSL) error
	DeleteBy(opts ...DBOption) error
	SaveByMap(ssl *model.WebsiteSSL, params map[string]interface{}) error
	// TryBeginApply atomically reserves a record for a certificate application
	// (status -> applying), reporting whether this caller won the reservation.
	TryBeginApply(id uint, allowedStatuses []string) (int64, error)
}

type WebsiteSSLRepo struct {
}

func (w WebsiteSSLRepo) WithByAlias(alias string) DBOption {
	return func(db *gorm.DB) *gorm.DB {
		return db.Where("alias = ?", alias)
	}
}

func (w WebsiteSSLRepo) WithByAcmeAccountId(acmeAccountId uint) DBOption {
	return func(db *gorm.DB) *gorm.DB {
		return db.Where("acme_account_id = ?", acmeAccountId)
	}
}

func (w WebsiteSSLRepo) WithByDnsAccountId(dnsAccountId uint) DBOption {
	return func(db *gorm.DB) *gorm.DB {
		return db.Where("dns_account_id = ?", dnsAccountId)
	}
}

func (w WebsiteSSLRepo) WithByCAID(caID uint) DBOption {
	return func(db *gorm.DB) *gorm.DB {
		return db.Where("ca_id = ?", caID)
	}
}
func (w WebsiteSSLRepo) Page(page, size int, opts ...DBOption) (int64, []model.WebsiteSSL, error) {
	var sslList []model.WebsiteSSL
	db := getDb(opts...).Model(&model.WebsiteSSL{})
	count := int64(0)
	db = db.Count(&count)
	err := db.Limit(size).Offset(size * (page - 1)).Preload("AcmeAccount").Preload("DnsAccount").Preload("Websites").Find(&sslList).Error
	return count, sslList, err
}

func (w WebsiteSSLRepo) GetFirst(opts ...DBOption) (*model.WebsiteSSL, error) {
	var website *model.WebsiteSSL
	db := getDb(opts...).Model(&model.WebsiteSSL{})
	if err := db.Preload("AcmeAccount").Preload("DnsAccount").First(&website).Error; err != nil {
		return website, err
	}
	return website, nil
}

func (w WebsiteSSLRepo) List(opts ...DBOption) ([]model.WebsiteSSL, error) {
	var websites []model.WebsiteSSL
	db := getDb(opts...).Model(&model.WebsiteSSL{})
	if err := db.Preload("AcmeAccount").Preload("DnsAccount").Find(&websites).Error; err != nil {
		return websites, err
	}
	return websites, nil
}

func (w WebsiteSSLRepo) Create(ctx context.Context, ssl *model.WebsiteSSL) error {
	return getTx(ctx).Create(ssl).Error
}

// TryBeginApply atomically moves the SSL record with the given id from any of
// the allowed statuses into constant.SSLApply (applying) via a conditional
// UPDATE ... WHERE status IN (...). It returns how many rows the update
// touched (1 = this caller won the race and now owns the only concurrent
// application; 0 = someone else is already applying, or the row is in a state
// an application may not start from). RowsAffected is guaranteed by the WHERE
// clause on the primary key: a single UPDATE row on success, none on failure.
func (w WebsiteSSLRepo) TryBeginApply(id uint, allowedStatuses []string) (int64, error) {
	result := getDb().Model(&model.WebsiteSSL{}).
		Where("id = ?", id).
		Where("status IN (?)", allowedStatuses).
		Update("status", constant.SSLApply)
	return result.RowsAffected, result.Error
}

func (w WebsiteSSLRepo) Save(ssl *model.WebsiteSSL) error {
	return getDb().Model(&model.WebsiteSSL{BaseModel: model.BaseModel{
		ID: ssl.ID,
	}}).Save(&ssl).Error
}

func (w WebsiteSSLRepo) SaveByMap(ssl *model.WebsiteSSL, params map[string]interface{}) error {
	return getDb().Model(&model.WebsiteSSL{BaseModel: model.BaseModel{
		ID: ssl.ID,
	}}).Updates(params).Error
}

func (w WebsiteSSLRepo) DeleteBy(opts ...DBOption) error {
	return getDb(opts...).Delete(&model.WebsiteSSL{}).Error
}
