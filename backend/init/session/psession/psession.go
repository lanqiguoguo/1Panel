package psession

import (
	"encoding/json"
	"time"

	"github.com/1Panel-dev/1Panel/backend/init/cache/badger_db"
)

type SessionUser struct {
	ID       uint   `json:"id"`
	Name     string `json:"name"`
	LoggedIn bool   `json:"loggedIn"`
}

func (s SessionUser) String() string {
	data, err := json.Marshal(s)
	if err != nil {
		return "{}"
	}
	return string(data)
}

type PSession struct {
	ExpireTime int64 `json:"expire_time"`
	store      *badger_db.Cache
}

func NewPSession(db *badger_db.Cache) *PSession {
	return &PSession{
		store: db,
	}
}

func (p *PSession) Get(sessionID string) (SessionUser, error) {
	var result SessionUser
	item, err := p.store.Get(sessionID)
	if err != nil {
		return result, err
	}
	if err := json.Unmarshal(item, &result); err != nil {
		return result, err
	}
	return result, nil
}

func (p *PSession) Set(sessionID string, user SessionUser, ttlSeconds int) error {
	p.ExpireTime = time.Now().Unix() + int64(ttlSeconds)
	return p.store.SetWithTTL(sessionID, user, time.Second*time.Duration(ttlSeconds))
}

func (p *PSession) Delete(sessionID string) error {
	return p.store.Del(sessionID)
}

func (p *PSession) Clean() error {
	return p.store.Clean()
}
