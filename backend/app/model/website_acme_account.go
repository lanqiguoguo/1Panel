package model

type WebsiteAcmeAccount struct {
	BaseModel
	Email      string `gorm:"not null" json:"email"`
	URL        string `gorm:"not null" json:"url"`
	PrivateKey string `gorm:"not null" json:"-"`
	Type       string `gorm:"not null;default:letsencrypt" json:"type"`
	EabKid     string `gorm:"default:null;" json:"eabKid"`
	// EabHmacKey is a secret; it is only set at account creation and is never
	// echoed back (the ACME account page has no edit form and the renew flow
	// reads the account from the DB, not from JSON).
	EabHmacKey string `gorm:"default:null" json:"-"`
	KeyType    string `gorm:"not null;default:2048" json:"keyType"`
}

func (w WebsiteAcmeAccount) TableName() string {
	return "website_acme_accounts"
}
