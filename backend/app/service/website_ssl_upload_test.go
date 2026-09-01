package service

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
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

// sslUploadTestDBSeq gives every setupSSLUploadTest call its own shared-cache
// in-memory database (same pattern as snapshotTestDBSeq, see snapshot_test.go).
var sslUploadTestDBSeq atomic.Int64

// setupSSLUploadTest gives every test its own in-memory sqlite with the tables
// touched by Upload/DownloadFile (the two account tables are needed because
// WebsiteSSLRepo.GetFirst preloads them) and points global.CONF.System.BaseDir
// at an empty temp dir, so any path traversal shows up as residue there.
func setupSSLUploadTest(t *testing.T) {
	t.Helper()
	dsn := fmt.Sprintf("file:%s-%d?mode=memory&cache=shared", t.Name(), sslUploadTestDBSeq.Add(1))
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open in-memory sqlite failed: %v", err)
	}
	if err := db.AutoMigrate(&model.WebsiteSSL{}, &model.WebsiteAcmeAccount{}, &model.WebsiteDnsAccount{}); err != nil {
		t.Fatalf("migrate website ssl tables failed: %v", err)
	}
	global.DB = db
	global.LOG = logrus.New()

	baseDir := t.TempDir()
	oldBaseDir := global.CONF.System.BaseDir
	global.CONF.System.BaseDir = baseDir
	t.Cleanup(func() {
		global.CONF.System.BaseDir = oldBaseDir
	})
}

// makeSelfSignedCert builds a self-signed certificate whose DNS SANs are
// dnsNames, PEM-encoded like a manually uploaded certificate (certificate
// first, then the private key). x509 dNSName entries are plain IA5Strings, so
// hostile values like "../../evil" can be embedded this way by any CA.
func makeSelfSignedCert(t *testing.T, dnsNames []string) (certPEM string, keyPEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ecdsa key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   "test",
			Organization: []string{"test"},
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
		DNSNames:  dnsNames,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal ecdsa key: %v", err)
	}
	certOut := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyOut := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return string(certOut), string(keyOut)
}

func pasteUploadReq(certPEM, keyPEM string) request.WebsiteSSLUpload {
	return request.WebsiteSSLUpload{
		Certificate: certPEM,
		PrivateKey:  keyPEM,
		Type:        "paste",
	}
}

// baseDirEntries walks BaseDir and returns every path below it; an empty
// result means the upload/download flows created no residue at all.
func baseDirEntries(t *testing.T, baseDir string) []string {
	t.Helper()
	var names []string
	err := filepath.Walk(baseDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if path == baseDir {
			return nil
		}
		names = append(names, path)
		return nil
	})
	if err != nil {
		t.Fatalf("walk base dir %s: %v", baseDir, err)
	}
	return names
}

func countSSLRows(t *testing.T) []model.WebsiteSSL {
	t.Helper()
	var rows []model.WebsiteSSL
	if err := global.DB.Find(&rows).Error; err != nil {
		t.Fatalf("query website_ssls: %v", err)
	}
	return rows
}

// TestUploadRejectsMaliciousDNSName pins the upload boundary: a certificate
// whose first DNS SAN is a path-traversal or shell-metacharacter string must
// be rejected with the same ErrDomainFormat error used by Create/Update,
// must not be persisted and must leave no directory under BaseDir
// (path.Join(BaseDir, "1panel/tmp/ssl", "../../evil") would otherwise escape
// the tmp/ssl directory on download).
func TestUploadRejectsMaliciousDNSName(t *testing.T) {
	setupSSLUploadTest(t)
	baseDir := global.CONF.System.BaseDir
	service := NewIWebsiteSSLService()

	for _, domain := range []string{"../../evil", "a;b.c"} {
		certPEM, keyPEM := makeSelfSignedCert(t, []string{domain})
		err := service.Upload(pasteUploadReq(certPEM, keyPEM))
		if err == nil {
			t.Fatalf("upload with SAN %q accepted, want ErrDomainFormat", domain)
		}
		if !strings.Contains(err.Error(), domain) {
			t.Fatalf("upload with SAN %q failed with %v, want ErrDomainFormat naming the domain", domain, err)
		}
		if entries := baseDirEntries(t, baseDir); len(entries) > 0 {
			t.Fatalf("SAN %q left residue under BaseDir: %v", domain, entries)
		}
		if rows := countSSLRows(t); len(rows) != 0 {
			t.Fatalf("SAN %q persisted %d website_ssl rows, want 0", domain, len(rows))
		}
	}
}

// TestUploadRejectsMaliciousSecondaryDNSName checks that the same validation
// also covers the DNSNames stored into Domains (elements after the first),
// not only PrimaryDomain.
func TestUploadRejectsMaliciousSecondaryDNSName(t *testing.T) {
	setupSSLUploadTest(t)
	service := NewIWebsiteSSLService()

	certPEM, keyPEM := makeSelfSignedCert(t, []string{"ok.example.com", "a;b.c"})
	if err := service.Upload(pasteUploadReq(certPEM, keyPEM)); err == nil {
		t.Fatal("upload with malicious secondary SAN accepted, want ErrDomainFormat")
	}
	if rows := countSSLRows(t); len(rows) != 0 {
		t.Fatalf("malicious secondary SAN persisted %d rows, want 0", len(rows))
	}
}

// TestUploadAcceptsValidDNSName verifies the positive case: a certificate
// with a well-formed DNS SAN is uploaded and persisted with that SAN as
// PrimaryDomain, and no download directory is created by Upload itself.
func TestUploadAcceptsValidDNSName(t *testing.T) {
	setupSSLUploadTest(t)
	baseDir := global.CONF.System.BaseDir
	service := NewIWebsiteSSLService()

	certPEM, keyPEM := makeSelfSignedCert(t, []string{"e2e.example.com"})
	if err := service.Upload(pasteUploadReq(certPEM, keyPEM)); err != nil {
		t.Fatalf("upload with valid SAN rejected: %v", err)
	}
	rows := countSSLRows(t)
	if len(rows) != 1 {
		t.Fatalf("got %d website_ssl rows, want 1", len(rows))
	}
	if rows[0].PrimaryDomain != "e2e.example.com" {
		t.Fatalf("PrimaryDomain = %q, want e2e.example.com", rows[0].PrimaryDomain)
	}
	if rows[0].Provider != constant.Manual || rows[0].Status != constant.SSLReady {
		t.Fatalf("Provider/Status = %q/%q, want manual/ready", rows[0].Provider, rows[0].Status)
	}
	if entries := baseDirEntries(t, baseDir); len(entries) > 0 {
		t.Fatalf("Upload created files under BaseDir: %v", entries)
	}
}

// TestDownloadFileRejectsTraversalPrimaryDomain is the defense-in-depth
// check: a legacy row whose stored PrimaryDomain is a traversal string must
// not make DownloadFile create directories anywhere under BaseDir.
func TestDownloadFileRejectsTraversalPrimaryDomain(t *testing.T) {
	setupSSLUploadTest(t)
	baseDir := global.CONF.System.BaseDir

	seed := &model.WebsiteSSL{
		PrimaryDomain: "../../opt/evil",
		Provider:      constant.Manual,
		Status:        constant.SSLReady,
		Pem:           "pem",
		PrivateKey:    "key",
	}
	if err := global.DB.Create(seed).Error; err != nil {
		t.Fatalf("seed row: %v", err)
	}

	service := NewIWebsiteSSLService()
	if _, err := service.DownloadFile(seed.ID); err == nil {
		t.Fatal("DownloadFile with traversal PrimaryDomain accepted, want error")
	}
	if entries := baseDirEntries(t, baseDir); len(entries) > 0 {
		t.Fatalf("DownloadFile created residue under BaseDir: %v", entries)
	}
}
