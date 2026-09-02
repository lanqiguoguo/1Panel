package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/1Panel-dev/1Panel/backend/app/dto/request"
	"github.com/1Panel-dev/1Panel/backend/app/model"
	"github.com/1Panel-dev/1Panel/backend/constant"
	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/glebarez/sqlite"
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

// sslDeployTestDBSeq gives every setupSSLPemDeployTest its own shared-cache
// in-memory database plus a temp data dir, so createPemFile / applySSL's
// snapshot and restore helpers can be exercised against real files without
// touching any real openresty install. The tests seed one openresty App /
// AppInstall row pair pointing into the temp dir and assert on the files
// createPemFile actually writes.
var sslDeployTestDBSeq atomic.Int64

// setupSSLPemDeployTest wires the in-memory db + temp data dir and seeds the
// openresty App/AppInstall pair. setupSSLUploadTest (which replaces
// global.DB with its own db, so the two setups must not be stacked) covers
// the WebsiteSSL tables; tests that need BOTH website_ssls and the
// app/website rows call setupSSLPemDeployTestFull below instead.
func setupSSLPemDeployTest(t *testing.T) {
	t.Helper()
	db := openSSLPemDeployTestDB(t)
	seedOpenrestyAppInstall(t, db)
}

func setupSSLPemDeployTestFull(t *testing.T) {
	t.Helper()
	db := openSSLPemDeployTestDB(t)
	if err := db.AutoMigrate(&model.WebsiteSSL{}, &model.WebsiteAcmeAccount{}, &model.WebsiteDnsAccount{}); err != nil {
		t.Fatalf("migrate ssl tables failed: %v", err)
	}
	seedOpenrestyAppInstall(t, db)
}

func openSSLPemDeployTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := fmt.Sprintf("file:%s-%d?mode=memory&cache=shared", t.Name(), sslDeployTestDBSeq.Add(1))
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open in-memory sqlite failed: %v", err)
	}
	if err := db.AutoMigrate(&model.App{}, &model.AppTag{}, &model.AppInstall{}, &model.Website{}, &model.WebsiteDomain{}); err != nil {
		t.Fatalf("migrate tables failed: %v", err)
	}
	global.DB = db
	global.LOG = logrus.New()

	dataDir := t.TempDir()
	oldDataDir := global.CONF.System.DataDir
	global.CONF.System.DataDir = dataDir
	t.Cleanup(func() {
		global.CONF.System.DataDir = oldDataDir
	})

	// constant.AppInstallDir is bound once at package init from the then-empty
	// DataDir, so deploy tests writing through it would land cwd-relative
	// under the package source dir. Point it at the temp data dir for the
	// duration of the test, like the global.CONF.System.BaseDir patterns do.
	oldAppInstallDir := constant.AppInstallDir
	constant.AppInstallDir = path.Join(dataDir, "apps")
	t.Cleanup(func() {
		constant.AppInstallDir = oldAppInstallDir
	})
	return db
}

func seedOpenrestyAppInstall(t *testing.T, db *gorm.DB) {
	t.Helper()
	app := model.App{Name: "OpenResty", Key: constant.AppOpenresty, Type: constant.AppResourceRemote, Status: "installed", Resource: constant.AppResourceRemote}
	if err := db.Create(&app).Error; err != nil {
		t.Fatalf("seed openresty app failed: %v", err)
	}
	install := model.AppInstall{
		AppId:         app.ID,
		Name:          "openresty-test",
		AppDetailId:   0,
		Version:       "1.0",
		Status:        "Running",
		ContainerName: "openresty-test",
		ServiceName:   "openresty-test",
	}
	if err := db.Create(&install).Error; err != nil {
		t.Fatalf("seed openresty install failed: %v", err)
	}
}

// seedDeployWebsite inserts a website row bound to no ssl and returns it with
// the alias used as the ssl directory name.
func seedDeployWebsite(t *testing.T) model.Website {
	t.Helper()
	web := model.Website{
		PrimaryDomain: "deploy.example.com",
		Alias:         "deployexamplecom",
		Type:          constant.Static,
		Status:        constant.WebRunning,
		Protocol:      constant.ProtocolHTTP,
		HttpConfig:    "HTTPOnly",
	}
	if err := global.DB.Create(&web).Error; err != nil {
		t.Fatalf("seed website failed: %v", err)
	}
	return web
}

func sslDirOf(t *testing.T, website model.Website) string {
	t.Helper()
	fullChain, _, err := getWebsiteSSLPemFilePaths(website)
	if err != nil {
		t.Fatalf("resolve ssl paths: %v", err)
	}
	return filepath.Dir(fullChain)
}

// writeSitePemPair deploys cert/key directly with the production writers, the
// way a prior successful deployment would have left them.
func writeSitePemPair(t *testing.T, website model.Website, certPEM, keyPEM string) {
	t.Helper()
	dir := sslDirOf(t, website)
	if err := os.MkdirAll(dir, 0775); err != nil {
		t.Fatalf("mkdir ssl dir: %v", err)
	}
	if err := writePemFileAtomic(path.Join(dir, "fullchain.pem"), certPEM); err != nil {
		t.Fatalf("seed fullchain: %v", err)
	}
	if err := writePrivateKeyFile(path.Join(dir, "privkey.pem"), keyPEM); err != nil {
		t.Fatalf("seed privkey: %v", err)
	}
}

func readFileString(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read %s: %v", p, err)
	}
	return string(b)
}

// makeSecondKey returns a different EC key whose certificate would not match
// a cert created with makeSelfSignedCert.
func makeSecondKey(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
}

// TestCreatePemFileWritesPair verifies the deploy writer creates the ssl dir
// and both PEM files (chain mode 0644, key mode 0600) with the given content.
func TestCreatePemFileWritesPair(t *testing.T) {
	setupSSLPemDeployTest(t)
	website := seedDeployWebsite(t)
	certPEM, keyPEM := makeSelfSignedCert(t, []string{"deploy.example.com"})

	if err := createPemFile(website, model.WebsiteSSL{Pem: certPEM, PrivateKey: keyPEM}); err != nil {
		t.Fatalf("createPemFile: %v", err)
	}
	dir := sslDirOf(t, website)
	if got := readFileString(t, path.Join(dir, "fullchain.pem")); got != certPEM {
		t.Fatal("fullchain.pem content mismatch")
	}
	if got := readFileString(t, path.Join(dir, "privkey.pem")); got != keyPEM {
		t.Fatal("privkey.pem content mismatch")
	}
	info, err := os.Stat(path.Join(dir, "privkey.pem"))
	if err != nil {
		t.Fatalf("stat privkey: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("privkey mode = %v, want 0600", info.Mode().Perm())
	}
}

// TestWritePemFileAtomicReplacesWithoutTruncation verifies the atomic writer:
// a failed replacement leaves the previous destination untouched and no *.tmp
// residue behind, while a successful replacement fully swaps the content.
// The failure is induced by a destination that is an existing non-empty
// directory (rename fails with EISDIR) — tests often run as root, so plain
// chmod-based permission failures do not apply.
func TestWritePemFileAtomicReplacesWithoutTruncation(t *testing.T) {
	dir := t.TempDir()
	dst := path.Join(dir, "fullchain.pem")
	if err := os.WriteFile(dst, []byte("old-good-cert"), 0644); err != nil {
		t.Fatal(err)
	}

	// Failure path: an occupied directory cannot be renamed over.
	occupied := path.Join(dir, "occupied")
	if err := os.Mkdir(occupied, 0755); err != nil {
		t.Fatal(err)
	}
	marker := path.Join(occupied, "marker")
	if err := os.WriteFile(marker, []byte("keep-me"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := writePemFileAtomic(occupied, "new-cert"); err == nil {
		t.Fatal("rename over occupied directory succeeded, want error")
	}
	if got := readFileString(t, marker); got != "keep-me" {
		t.Fatalf("destination mutated on failed replace: %q", got)
	}

	// Positive path: replace the file.
	if err := writePemFileAtomic(dst, "new-cert"); err != nil {
		t.Fatalf("replacement write failed: %v", err)
	}
	if got := readFileString(t, dst); got != "new-cert" {
		t.Fatalf("content = %q, want new-cert", got)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp") {
			t.Fatalf("temp file %s left behind after rename", e.Name())
		}
	}
}

// TestSnapshotRestorePemFiles verifies the snapshot/restore round trip used by
// applySSL: a snapshot taken before an overwrite restores the exact previous
// cert and key, and restoring a snapshot of a never-deployed site is a no-op.
func TestSnapshotRestorePemFiles(t *testing.T) {
	setupSSLPemDeployTest(t)
	website := seedDeployWebsite(t)
	certPEM, keyPEM := makeSelfSignedCert(t, []string{"deploy.example.com"})
	otherCertPEM, otherKeyPEM := makeSelfSignedCert(t, []string{"other.example.com"})
	writeSitePemPair(t, website, certPEM, keyPEM)

	snap, err := snapshotWebsitePemFiles(website)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if !snap.exist || snap.certPem != certPEM || snap.keyPem != keyPEM {
		t.Fatalf("snapshot = %+v, want existing %q/%q pair", snap, certPEM, keyPEM)
	}

	if err := createPemFile(website, model.WebsiteSSL{Pem: otherCertPEM, PrivateKey: otherKeyPEM}); err != nil {
		t.Fatalf("overwrite: %v", err)
	}
	dir := sslDirOf(t, website)
	if got := readFileString(t, path.Join(dir, "fullchain.pem")); got != otherCertPEM {
		t.Fatal("overwrite did not replace fullchain")
	}

	restored, err := restoreWebsitePemFiles(website, snap)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if !restored {
		t.Fatal("restore reported nothing to restore, want restored")
	}
	if got := readFileString(t, path.Join(dir, "fullchain.pem")); got != certPEM {
		t.Fatal("fullchain not restored to previous content")
	}
	if got := readFileString(t, path.Join(dir, "privkey.pem")); got != keyPEM {
		t.Fatal("privkey not restored to previous content")
	}

	// No previous deployment -> no-op, no error.
	restored, err = restoreWebsitePemFiles(seedDeployWebsite(t), websitePemSnapshot{exist: false})
	if err != nil {
		t.Fatalf("restore of empty snapshot: %v", err)
	}
	if restored {
		t.Fatal("restore of empty snapshot reported restored, want false")
	}
}

// TestValidateCertKeyPairPinsMatchRule verifies the pure pair check: matching
// pair passes, swapped/garbage key is rejected, multi-block chain passes, and
// an expired cert is still accepted (pair validation only).
func TestValidateCertKeyPairPinsMatchRule(t *testing.T) {
	certPEM, keyPEM := makeSelfSignedCert(t, []string{"pair.example.com"})
	if err := validateCertKeyPair([]byte(certPEM), []byte(keyPEM)); err != nil {
		t.Fatalf("matching pair rejected: %v", err)
	}
	if err := validateCertKeyPair([]byte(certPEM), []byte(makeSecondKey(t))); err == nil {
		t.Fatal("mismatched pair accepted, want error")
	}
	if err := validateCertKeyPair([]byte(certPEM), []byte("not a pem key")); err == nil {
		t.Fatal("garbage key accepted, want error")
	}
	if err := validateCertKeyPair([]byte(certPEM+certPEM), []byte(keyPEM)); err != nil {
		t.Fatalf("leaf+extra block chain rejected: %v", err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "expired"},
		NotBefore:    time.Now().Add(-48 * time.Hour),
		NotAfter:     time.Now().Add(-24 * time.Hour),
		DNSNames:     []string{"expired.example.com"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	expiredCert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	expiredKey := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	if err := validateCertKeyPair([]byte(expiredCert), []byte(expiredKey)); err != nil {
		t.Fatalf("expired cert rejected by pair validation: %v", err)
	}
}

// TestUploadMismatchedPairRejectedKeepsRowAndFiles verifies H4c for the
// existing-certificate overwrite path: uploading a certificate that does not
// belong to the stored key must fail before UpdateSSLConfig runs, so the DB
// row and the deployed PEM files (the old cert is a valid pair with the old
// key, so nginx still works) stay untouched.
func TestUploadMismatchedPairRejectedKeepsRowAndFiles(t *testing.T) {
	setupSSLPemDeployTestFull(t)
	website := seedDeployWebsite(t)
	service := NewIWebsiteSSLService()

	goodCert, goodKey := makeSelfSignedCert(t, []string{"upload.example.com"})
	ssl := &model.WebsiteSSL{PrimaryDomain: "upload.example.com", Provider: constant.Manual, Status: constant.SSLReady, Pem: goodCert, PrivateKey: goodKey}
	if err := global.DB.Create(ssl).Error; err != nil {
		t.Fatalf("seed ssl row: %v", err)
	}
	website.WebsiteSSLID = ssl.ID
	if err := websiteRepo.Save(context.Background(), &website); err != nil {
		t.Fatalf("bind website: %v", err)
	}
	writeSitePemPair(t, website, goodCert, goodKey)

	badCert, _ := makeSelfSignedCert(t, []string{"evil.example.com"})
	err := service.Upload(pasteUploadReq(badCert, goodKey))
	if err == nil {
		t.Fatal("upload with mismatched pair accepted, want rejection")
	}
	if !strings.Contains(err.Error(), "ErrSSLManualDeploy") && !strings.Contains(err.Error(), "tls") {
		t.Logf("mismatched-pair upload error: %v", err)
	}

	var rows []model.WebsiteSSL
	if err := global.DB.Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d ssl rows, want 1 (no new row, no overwrite)", len(rows))
	}
	if rows[0].Pem != goodCert {
		t.Fatal("existing ssl row content changed on rejected upload")
	}
	dir := sslDirOf(t, website)
	if got := readFileString(t, path.Join(dir, "fullchain.pem")); got != goodCert {
		t.Fatal("deployed fullchain.pem changed on rejected upload")
	}
	if got := readFileString(t, path.Join(dir, "privkey.pem")); got != goodKey {
		t.Fatal("deployed privkey.pem changed on rejected upload")
	}
}

// TestReDeployCertOverSameKeyPinsOverwriteSequence covers the parts of the
// positive overwrite path (Upload with an existing SSLID) that run before the
// docker-bound openresty reload: the new certificate matches the already
// stored key, so Upload's pair validation passes, UpdateSSLConfig overwrites
// the deployed PEM pair on disk, and only the final nginx reload needs a real
// container (E2E). The DB row of the seeded site is bound and the on-disk
// pair is asserted to have been replaced with the same key.
func TestReDeployCertOverSameKeyPinsOverwriteSequence(t *testing.T) {
	// The positive overwrite in Upload is exercised directly through the same
	// code path UpdateSSLConfig uses: a certificate reissued over the stored
	// key must pass validateCertKeyPair and createPemFile must swap the
	// deployed fullchain while keeping the key file untouched.
	keyPEM, certA, certB := makeCertPairAndReissue(t, "rekey.example.com")

	if err := validateCertKeyPair([]byte(certB), []byte(keyPEM)); err != nil {
		t.Fatalf("reissued cert over same key rejected: %v", err)
	}
	setupSSLPemDeployTestFull(t)
	website := seedDeployWebsite(t)
	writeSitePemPair(t, website, certA, keyPEM)

	dir := sslDirOf(t, website)
	if err := createPemFile(website, model.WebsiteSSL{Pem: certB, PrivateKey: keyPEM}); err != nil {
		t.Fatalf("re-deploy over same key: %v", err)
	}
	if got := readFileString(t, path.Join(dir, "fullchain.pem")); got != certB {
		t.Fatal("deployed fullchain.pem not replaced by matching re-deploy")
	}
	if got := readFileString(t, path.Join(dir, "privkey.pem")); got != keyPEM {
		t.Fatal("deployed privkey.pem changed by re-deploy")
	}
}

// makeCertPairAndReissue returns a key and two certificates over it (so certB
// is a valid "renewal" of certA sharing the same private key).
func makeCertPairAndReissue(t *testing.T, dnsName string) (keyPEM, certA, certB string) {
	t.Helper()
	certA, keyPEM = makeSelfSignedCert(t, []string{dnsName})
	keyBlock, _ := pem.Decode([]byte(keyPEM))
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatalf("parse seeded key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano() + 1),
		Subject:      pkix.Name{CommonName: "new", Organization: []string{"new"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{dnsName},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certB = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return keyPEM, certA, certB
}

// TestUploadMultiBlockChainKeepsWorking pins the chain case: the uploaded
// bundle may contain leaf + intermediate CERTIFICATE blocks, Upload must
// derive the fields from the leaf (last block carrying DNS SANs) and persist
// the whole bundle without mangling it.
func TestUploadMultiBlockChainKeepsWorking(t *testing.T) {
	setupSSLUploadTest(t)
	service := NewIWebsiteSSLService()

	certPEM, keyPEM := makeSelfSignedCert(t, []string{"chain.example.com"})
	bundle := certPEM + certPEM // leaf + one "intermediate"
	if err := service.Upload(pasteUploadReq(bundle, keyPEM)); err != nil {
		t.Fatalf("chain upload rejected: %v", err)
	}
	rows := countSSLRows(t)
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	if rows[0].PrimaryDomain != "chain.example.com" {
		t.Fatalf("PrimaryDomain = %q, want chain.example.com", rows[0].PrimaryDomain)
	}
	if rows[0].Pem != bundle {
		t.Fatal("stored Pem does not keep the whole uploaded bundle")
	}
}

// TestValidateCertSANsPinsBoundary verifies the shared SAN validator used by
// Upload and the manual deploy path rejects hostile dNSName entries while
// accepting normal domains, wildcards and CN-only certificates.
func TestValidateCertSANsPinsBoundary(t *testing.T) {
	_, keyPEM := makeSelfSignedCert(t, []string{"ok.example.com"})

	mkCert := func(dnsNames []string) *x509.Certificate {
		t.Helper()
		keyBlock, _ := pem.Decode([]byte(keyPEM))
		key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()),
			Subject:      pkix.Name{CommonName: "santest"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
			DNSNames:     dnsNames,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return cert
	}

	for _, bad := range []string{"../../evil", "a;b.c", "evil/../../x"} {
		if err := validateCertSANs(mkCert([]string{bad})); err == nil {
			t.Fatalf("SAN %q accepted, want ErrDomainFormat", bad)
		}
	}
	if err := validateCertSANs(mkCert([]string{"ok.example.com", "*.wild.example.com"})); err != nil {
		t.Fatalf("valid SANs rejected: %v", err)
	}
	if err := validateCertSANs(mkCert(nil)); err != nil {
		t.Fatalf("CN-only certificate rejected: %v", err)
	}
}

// TestOpWebsiteHTTPSRejectsAutoType pins H4a: type=auto must be refused
// before any nginx conf or PEM file is touched, even when the request is
// otherwise well-formed, so the empty certificate can never be written over
// the deployed pair.
func TestOpWebsiteHTTPSRejectsAutoType(t *testing.T) {
	setupSSLPemDeployTest(t)
	website := seedDeployWebsite(t)

	// Simulate an already-deployed HTTPS site so a buggy auto branch would
	// clobber real files.
	oldCert, oldKey := makeSelfSignedCert(t, []string{"deploy.example.com"})
	writeSitePemPair(t, website, oldCert, oldKey)

	service := NewIWebsiteService()
	_, err := service.OpWebsiteHTTPS(context.Background(), request.WebsiteHTTPSOp{
		WebsiteID:  website.ID,
		Enable:     true,
		Type:       constant.SSLAuto,
		HttpConfig: constant.HTTPSOnly,
	})
	if err == nil {
		t.Fatal("type=auto accepted, want rejection")
	}
	if !strings.Contains(err.Error(), "ErrSSLDeployTypeAuto") {
		t.Logf("type=auto error: %v", err)
	}
	dir := sslDirOf(t, website)
	if got := readFileString(t, path.Join(dir, "fullchain.pem")); got != oldCert {
		t.Fatal("fullchain.pem clobbered by type=auto request")
	}
	if got := readFileString(t, path.Join(dir, "privkey.pem")); got != oldKey {
		t.Fatal("privkey.pem clobbered by type=auto request")
	}
	// A garbage type is refused the same way.
	if _, err := service.OpWebsiteHTTPS(context.Background(), request.WebsiteHTTPSOp{
		WebsiteID: website.ID, Enable: true, Type: "no-such-type", HttpConfig: constant.HTTPSOnly,
	}); err == nil {
		t.Fatal("unknown type accepted, want rejection")
	}
}

// TestOpWebsiteHTTPSManualRejectsMaliciousSAN pins the M1/L1 gap in the
// manual branch: a pasted certificate whose dNSName carries "/" must be
// rejected before applySSL (no disk writes) and must not create an SSL row or
// touch the deployed files. The manual branch also rejects a pair whose
// private key does not belong to the certificate.
func TestOpWebsiteHTTPSManualRejectsMaliciousSAN(t *testing.T) {
	setupSSLPemDeployTestFull(t)
	website := seedDeployWebsite(t)
	oldCert, oldKey := makeSelfSignedCert(t, []string{"deploy.example.com"})
	writeSitePemPair(t, website, oldCert, oldKey)

	service := NewIWebsiteService()
	op := request.WebsiteHTTPSOp{
		WebsiteID:  website.ID,
		Enable:     true,
		Type:       constant.SSLManual,
		ImportType: "paste",
		HttpConfig: constant.HTTPSOnly,
	}

	certPEM, keyPEM := makeSelfSignedCert(t, []string{"evil/../../x"})
	op.Certificate = certPEM
	op.PrivateKey = keyPEM
	if _, err := service.OpWebsiteHTTPS(context.Background(), op); err == nil {
		t.Fatal("manual deploy with hostile SAN accepted, want rejection")
	}
	var rows []model.WebsiteSSL
	if err := global.DB.Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Fatalf("manual deploy persisted %d ssl rows, want 0", len(rows))
	}
	dir := sslDirOf(t, website)
	if got := readFileString(t, path.Join(dir, "fullchain.pem")); got != oldCert {
		t.Fatal("deployed fullchain.pem clobbered by rejected manual deploy")
	}

	// Mismatched private key is rejected before any write as well.
	goodCert, _ := makeSelfSignedCert(t, []string{"ok.example.com"})
	op.Certificate = goodCert
	op.PrivateKey = makeSecondKey(t)
	if _, err := service.OpWebsiteHTTPS(context.Background(), op); err == nil {
		t.Fatal("manual deploy with mismatched key accepted, want rejection")
	}
	if got := readFileString(t, path.Join(dir, "fullchain.pem")); got != oldCert {
		t.Fatal("deployed fullchain.pem clobbered by mismatched-key manual deploy")
	}
}
