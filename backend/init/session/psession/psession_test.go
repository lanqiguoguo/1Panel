package psession

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/init/cache/badger_db"
	"github.com/dgraph-io/badger/v4"
)

func newTestSession(t *testing.T) *PSession {
	t.Helper()
	db, err := badger.Open(badger.DefaultOptions("").WithInMemory(true))
	if err != nil {
		t.Fatalf("open in-memory badger failed: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return NewPSession(badger_db.NewCacheDB(db))
}

func TestSessionUserMarshalIncludesLoggedIn(t *testing.T) {
	data, err := json.Marshal(SessionUser{ID: 1, Name: "admin", LoggedIn: true})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	if loggedIn, ok := m["loggedIn"].(bool); !ok || !loggedIn {
		t.Fatalf("loggedIn = %v, want true", m["loggedIn"])
	}
}

func TestSessionUserStringIncludesLoggedIn(t *testing.T) {
	// the badger cache store persists values with fmt.Sprintf("%v", value),
	// so SessionUser.String() must carry the LoggedIn flag.
	data := SessionUser{ID: 1, Name: "admin", LoggedIn: true}.String()
	if !strings.Contains(data, `"loggedIn":true`) {
		t.Fatalf("String() = %s, want loggedIn:true", data)
	}
}

func TestPSessionSetGetRoundTrip(t *testing.T) {
	p := newTestSession(t)
	user := SessionUser{ID: 1, Name: "admin", LoggedIn: true}
	if err := p.Set("sid-1", user, 60); err != nil {
		t.Fatal(err)
	}
	got, err := p.Get("sid-1")
	if err != nil {
		t.Fatal(err)
	}
	if got != user {
		t.Fatalf("Get() = %+v, want %+v", got, user)
	}
}

func TestPSessionGetUnmarshalError(t *testing.T) {
	p := newTestSession(t)
	if err := p.store.Set("corrupt", "not-json"); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Get("corrupt"); err == nil {
		t.Fatal("Get() = nil error, want error for non-json value")
	}
}

func TestPSessionGetMissing(t *testing.T) {
	p := newTestSession(t)
	if _, err := p.Get("missing"); err == nil {
		t.Fatal("Get() = nil error, want error for missing key")
	}
}
