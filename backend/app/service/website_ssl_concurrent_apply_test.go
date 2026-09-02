package service

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/1Panel-dev/1Panel/backend/app/dto/request"
	"github.com/1Panel-dev/1Panel/backend/app/model"
	"github.com/1Panel-dev/1Panel/backend/app/repo"
	"github.com/1Panel-dev/1Panel/backend/buserr"
	"github.com/1Panel-dev/1Panel/backend/constant"
	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/1Panel-dev/1Panel/backend/i18n"
	"github.com/glebarez/sqlite"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

// sslApplyRaceTestDBSeq gives every setupSSLApplyRaceTest call its own
// shared-cache in-memory database (same pattern as snapshotTestDBSeq, see
// snapshot_test.go).
var sslApplyRaceTestDBSeq atomic.Int64

// setupSSLApplyRaceTest prepares an isolated in-memory sqlite (website_ssls,
// website_acme_accounts and website_dns_accounts, because
// WebsiteSSLRepo.GetFirst preloads the two account relations) plus the
// production service/repo singletons wired to it, mirroring
// app/service/entry.go.
func setupSSLApplyRaceTest(t *testing.T) {
	t.Helper()
	dsn := fmt.Sprintf("file:%s-%d?mode=memory&cache=shared", t.Name(), sslApplyRaceTestDBSeq.Add(1))
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open in-memory sqlite failed: %v", err)
	}
	if err := db.AutoMigrate(&model.WebsiteSSL{}, &model.WebsiteAcmeAccount{}, &model.WebsiteDnsAccount{}); err != nil {
		t.Fatalf("migrate website ssl tables failed: %v", err)
	}
	global.DB = db
	global.LOG = logrus.New()
	websiteSSLRepo = repo.NewISSLRepo()
	websiteAcmeRepo = repo.NewIAcmeAccountRepo()
	websiteDnsRepo = repo.NewIWebsiteDnsAccountRepo()
	websiteRepo = repo.NewIWebsiteRepo()
}

// seedApplyableSSL inserts a website_ssls row plus the acme account it
// references, and returns both ids. The row starts in the given status so the
// test controls exactly what the CAS sees.
func seedApplyableSSL(t *testing.T, status string) (sslID uint) {
	t.Helper()
	acct := &model.WebsiteAcmeAccount{
		Email:      "test@example.com",
		URL:        "https://acme.example.com/directory",
		PrivateKey: "test-private-key",
		Type:       "letsencrypt",
		KeyType:    "2048",
	}
	if err := websiteAcmeRepo.Create(*acct); err != nil {
		t.Fatalf("seed acme account failed: %v", err)
	}
	// The acme repo Create takes the account by value and cannot echo the
	// generated id back, so reload it (the seed email is unique per test db).
	savedAcct, err := websiteAcmeRepo.GetFirst(websiteAcmeRepo.WithEmail(acct.Email))
	if err != nil {
		t.Fatalf("reload acme account failed: %v", err)
	}
	ssl := &model.WebsiteSSL{
		Status:        status,
		Provider:      constant.DNSAccount,
		AcmeAccountID: savedAcct.ID,
		PrimaryDomain: "race-ssl-test.example.com",
		KeyType:       "2048",
	}
	if err := websiteSSLRepo.Create(context.Background(), ssl); err != nil {
		t.Fatalf("seed ssl failed: %v", err)
	}
	return ssl.ID
}

// currentSSLStatus reads the persisted status of the given ssl row straight
// from the database.
func currentSSLStatus(t *testing.T, id uint) string {
	t.Helper()
	var cur model.WebsiteSSL
	if err := global.DB.First(&cur, id).Error; err != nil {
		t.Fatalf("reload ssl %d failed: %v", id, err)
	}
	return cur.Status
}

// dbStatusAfter runs cond until the persisted status of the ssl row differs
// from wantGone (or times out): the applying goroutine spawned by
// ObtainSSL/runApply flips the row asynchronously, so every assertion on a
// goroutine-side state change must wait for it instead of racing.
func dbStatusAfter(t *testing.T, id uint, wantGone string, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if s := currentSSLStatus(t, id); s != wantGone {
			return s
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("ssl %d status stayed %q within %v", id, wantGone, timeout)
	return ""
}

// TestSSLApplyCASStatusMachine verifies the atomic reservation guard: records
// in any state an application may start from (init/error/ready/applyError)
// are claimed and move to applying, while a record already applying (or one
// a process restart left in systemRestart) is refused and stays untouched.
func TestSSLApplyCASStatusMachine(t *testing.T) {
	setupSSLApplyRaceTest(t)

	for _, tc := range []struct {
		from      string
		claimable bool
	}{
		{constant.SSLInit, true},
		{constant.SSLError, true},
		{constant.SSLReady, true},
		{constant.SSLApplyError, true},
		{constant.SystemRestart, true}, // interrupted by a restart: no live application, must stay retryable
		{constant.SSLApply, false},     // a live application owns the record
		{"unknown", false},
	} {
		t.Run(tc.from, func(t *testing.T) {
			id := seedApplyableSSL(t, tc.from)

			claimed, err := websiteSSLRepo.TryBeginApply(id, sslApplyAllowedStatuses)
			if err != nil {
				t.Fatalf("TryBeginApply from %s: %v", tc.from, err)
			}
			if tc.claimable {
				if claimed != 1 {
					t.Fatalf("TryBeginApply from %s: rows = %d, want 1", tc.from, claimed)
				}
				if got := currentSSLStatus(t, id); got != constant.SSLApply {
					t.Fatalf("TryBeginApply from %s: status = %s, want applying", tc.from, got)
				}
			} else {
				if claimed != 0 {
					t.Fatalf("TryBeginApply from %s: rows = %d, want 0 (must refuse)", tc.from, claimed)
				}
				if got := currentSSLStatus(t, id); got != tc.from {
					t.Fatalf("TryBeginApply from %s: refused claim changed status to %s", tc.from, got)
				}
			}
		})
	}
}

// TestSSLApplyCASConcurrentClaimIssuesOneWinner fires two real concurrent
// TryBeginApply calls at the same record (exactly what the Create auto
// goroutine, the manual apply API and the renew cron do when they overlap):
// exactly one of them must win and the row must end up applying exactly once.
func TestSSLApplyCASConcurrentClaimIssuesOneWinner(t *testing.T) {
	setupSSLApplyRaceTest(t)
	id := seedApplyableSSL(t, constant.SSLReady)

	start := make(chan struct{})
	results := make(chan int64, 2)
	for i := 0; i < 2; i++ {
		go func() {
			<-start
			rows, _ := websiteSSLRepo.TryBeginApply(id, sslApplyAllowedStatuses)
			results <- rows
		}()
	}
	close(start)
	winners := 0
	for i := 0; i < 2; i++ {
		if rows := <-results; rows == 1 {
			winners++
		}
	}
	if winners != 1 {
		t.Fatalf("concurrent TryBeginApply winners = %d, want exactly 1", winners)
	}
	if got := currentSSLStatus(t, id); got != constant.SSLApply {
		t.Fatalf("status after concurrent claim = %s, want applying", got)
	}
}

// TestSSLApplyObtainRefusesDuplicateBeforeACME verifies that the second
// entry point reaching ObtainSSL while the first application is in flight
// (its applying goroutine is parked, simulating a live ACME exchange) is
// refused with the ErrSSLApplying business error instead of racing a second
// ACME order against the first one. The refusal happens right after the CAS,
// before any acme account lookup or ACME client creation, so it never
// touches the network and the row stays untouched.
func TestSSLApplyObtainRefusesDuplicateBeforeACME(t *testing.T) {
	setupSSLApplyRaceTest(t)
	id := seedApplyableSSL(t, constant.SSLReady)

	// The first ObtainSSL wins the CAS (record -> applying) and launches its
	// applying goroutine. We then remove the acme account reference so that
	// anything past the CAS guard would fail loudly with record-not-found
	// instead of hanging on ACME traffic — the duplicate must still be
	// refused with the busy error, i.e. never reach that point.
	if err := websiteAcmeRepo.DeleteBy(commonRepo.WithByID(1)); err != nil {
		t.Fatalf("delete acme account failed: %v", err)
	}
	claimed, err := websiteSSLRepo.TryBeginApply(id, sslApplyAllowedStatuses)
	if err != nil || claimed != 1 {
		t.Fatalf("initial claim failed (rows=%d, err=%v)", claimed, err)
	}

	// The duplicate entry point (manual apply API / cron renew / Create auto
	// goroutine racing the first one) runs the full service entry: it reads
	// the row and loses the CAS, returning the busy business error.
	err = WebsiteSSLService{}.ObtainSSL(request.WebsiteSSLApply{ID: id})
	be, ok := err.(buserr.BusinessError)
	if !ok {
		t.Fatalf("ObtainSSL on applying record err = %v (%T), want a BusinessError", err, err)
	}
	if be.Msg != constant.ErrSSLApplying {
		t.Fatalf("ObtainSSL on applying record err key = %s, want %s", be.Msg, constant.ErrSSLApplying)
	}
	// The translated message must resolve (zh fallback is always loaded in
	// tests) and surface in the error text — not the raw key.
	wantMsg := i18n.GetErrMsg(constant.ErrSSLApplying, nil)
	if wantMsg == "" || wantMsg == constant.ErrSSLApplying {
		t.Fatalf("i18n message for %s did not resolve (got %q)", constant.ErrSSLApplying, wantMsg)
	}
	if !strings.Contains(err.Error(), wantMsg) {
		t.Fatalf("ObtainSSL error text = %q, want translated %q", err.Error(), wantMsg)
	}

	// The in-flight first application was never disturbed.
	if got := currentSSLStatus(t, id); got != constant.SSLApply {
		t.Fatalf("status after refused duplicate = %s, want applying (first application still running)", got)
	}
}

// ---------------------------------------------------------------------------
// Deterministic harness: WebsiteSSLRepo.Save is swapped for a scripted
// stand-in, so a test can make the in-goroutine applying-Save fail
// deterministically without touching the ACME code path (ssl.NewAcmeClient
// would need real network state).
// ---------------------------------------------------------------------------

// scriptedSSLRepo drives WebsiteSSLRepo's Save to fail exactly once (the
// first Save after the hook is armed) and then delegate to the wrapped
// production repo. Only Save is scripted because ObtainSSL's synchronous
// prefix uses GetFirst and TryBeginApply, and runApply's very first action
// is a Save — the one-shot failure simulates that single write failing in
// production, while the rollback write afterwards must succeed.
type scriptedSSLRepo struct {
	repo.ISSLRepo
	failSaves int
}

func (s *scriptedSSLRepo) Save(ssl *model.WebsiteSSL) error {
	if s.failSaves > 0 {
		s.failSaves--
		return fmt.Errorf("injected applying-save failure")
	}
	return s.ISSLRepo.Save(ssl)
}

// newScriptedSSLRepo installs a scripted repo as the package singleton and
// returns it, restoring the production repo on cleanup.
func newScriptedSSLRepo(t *testing.T, inner repo.ISSLRepo) *scriptedSSLRepo {
	t.Helper()
	s := &scriptedSSLRepo{ISSLRepo: inner}
	orig := websiteSSLRepo
	websiteSSLRepo = s
	t.Cleanup(func() { websiteSSLRepo = orig })
	return s
}

// TestSSLApplySaveFailureReleasesApplyingDeterministic deterministically
// simulates the "reserved but the applying goroutine can never start" window:
// the very first Save inside runApply (re-persisting the applying state)
// fails, so obtainWithLegoLock/ACME is never reached. The record must be
// rolled back from applying to a terminal failed state instead of staying
// applying.
func TestSSLApplySaveFailureReleasesApplyingDeterministic(t *testing.T) {
	setupSSLApplyRaceTest(t)
	id := seedApplyableSSL(t, constant.SSLReady)
	claimed, err := websiteSSLRepo.TryBeginApply(id, sslApplyAllowedStatuses)
	if err != nil || claimed != 1 {
		t.Fatalf("initial claim failed (rows=%d, err=%v)", claimed, err)
	}
	if got := currentSSLStatus(t, id); got != constant.SSLApply {
		t.Fatalf("pre-state = %s, want applying", got)
	}

	repo := newScriptedSSLRepo(t, websiteSSLRepo)
	repo.failSaves = 1 // the first Save (the applying re-persist) fails

	start := make(chan struct{})
	go func() {
		<-start
		// runApply is exactly what ObtainSSL launches after winning the CAS:
		// re-save applying, then hand over to obtainWithLegoLock (ACME).
		WebsiteSSLService{}.runApply(
			request.WebsiteSSLApply{ID: id, DisableLog: true},
			&model.WebsiteSSL{BaseModel: model.BaseModel{ID: id}, Status: constant.SSLApply},
			nil, nil, nil, nil,
		)
	}()
	close(start)

	got := dbStatusAfter(t, id, constant.SSLApply, 5*time.Second)
	if got != constant.SSLApplyError {
		t.Fatalf("status after forced applying-save failure = %s, want applyError (record must not stay applying)", got)
	}
}

// TestSSLApplySyncPrepFailureReleasesClaim drives the FULL ObtainSSL entry
// point through the "claim won, synchronous preparation failed" window: the
// record is reserved (applying) and then the acme account lookup fails (the
// row was deleted behind the caller's back). ObtainSSL must roll the record
// back to a terminal failed state instead of leaving it applying forever.
// The rollback runs inside ObtainSSL itself (releaseFailedApply), before any
// goroutine or ACME network call, so this test is fully deterministic.
func TestSSLApplySyncPrepFailureReleasesClaim(t *testing.T) {
	setupSSLApplyRaceTest(t)
	id := seedApplyableSSL(t, constant.SSLReady)

	// The acme account vanishes between the ssl read and the lookup.
	if err := websiteAcmeRepo.DeleteBy(commonRepo.WithByID(1)); err != nil {
		t.Fatalf("delete acme account failed: %v", err)
	}
	err := WebsiteSSLService{}.ObtainSSL(request.WebsiteSSLApply{ID: id})
	if err == nil {
		t.Fatal("ObtainSSL with a missing acme account succeeded, want error")
	}
	got := dbStatusAfter(t, id, constant.SSLApply, 5*time.Second)
	if got != constant.SSLApplyError {
		t.Fatalf("status after sync prep failure = %s, want applyError (claim must be released)", got)
	}

	// The record must now be retryable: the same entry point can claim it
	// again from applyError.
	claimed, err := websiteSSLRepo.TryBeginApply(id, sslApplyAllowedStatuses)
	if err != nil || claimed != 1 {
		t.Fatalf("re-claim after release failed (rows=%d, err=%v), want the record retryable", claimed, err)
	}
}
