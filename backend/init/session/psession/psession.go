package psession

import (
	"encoding/json"
	"time"

	"github.com/1Panel-dev/1Panel/backend/init/cache/badger_db"
)

// CleanHook is invoked by Clean after the session store has been dropped.
// session.Init installs the JWT refresh-version bump here: psession itself
// must not import global (global holds the *PSession field type, which would
// be an import cycle), and the hook keeps every Clean call site revoking the
// JWT channel automatically, with no per-call-site bookkeeping.
type CleanHook func()

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
	cleanHook  CleanHook
}

func NewPSession(db *badger_db.Cache) *PSession {
	return &PSession{
		store: db,
	}
}

// SetCleanHook registers the hook invoked by every Clean call.
func (p *PSession) SetCleanHook(h CleanHook) {
	p.cleanHook = h
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

// Clean drops every stored session (badger keys) and then runs the clean
// hook, which bumps the JWT refresh version — so session cookies and
// already-issued JWTs are revoked together. Callers that intend to log out
// every channel (password/user-name/MFA/security-entrance changes) must go
// through Clean, never through Delete.
func (p *PSession) Clean() error {
	err := p.store.Clean()
	if p.cleanHook != nil {
		p.cleanHook()
	}
	return err
}
