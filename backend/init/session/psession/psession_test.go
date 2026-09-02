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

// TestPSessionCleanRunsHook pins the Clean contract used for JWT
// revocation: every call to Clean (and only Clean, not Delete) runs the
// registered clean hook exactly once, so the JWT refresh version bump wired
// through the hook fires on every session-clean call site automatically.
func TestPSessionCleanRunsHook(t *testing.T) {
	p := newTestSession(t)

	calls := 0
	p.SetCleanHook(func() { calls++ })

	if err := p.Clean(); err != nil {
		t.Fatalf("Clean failed: %v", err)
	}
	if calls != 1 {
		t.Fatalf("hook calls after one Clean = %d, want 1", calls)
	}
	if err := p.Clean(); err != nil {
		t.Fatalf("second Clean failed: %v", err)
	}
	if calls != 2 {
		t.Fatalf("hook calls after two Cleans = %d, want 2", calls)
	}
	if err := p.Delete("whatever"); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
	if calls != 2 {
		t.Fatalf("hook calls after Delete = %d, want 2 (Delete must not run the hook)", calls)
	}
}

// TestPSessionCleanWithoutHookStaysSafe: a session store with no hook (unit
// tests, or an init order where the hook was never installed) must still
// clean the store without panicking.
func TestPSessionCleanWithoutHookStaysSafe(t *testing.T) {
	p := newTestSession(t)
	user := SessionUser{ID: 1, Name: "admin", LoggedIn: true}
	if err := p.Set("sid-1", user, 60); err != nil {
		t.Fatal(err)
	}
	if err := p.Clean(); err != nil {
		t.Fatalf("Clean without hook failed: %v", err)
	}
	if _, err := p.Get("sid-1"); err == nil {
		t.Fatal("session still present after Clean without hook")
	}
}
