package service

// Tests for the password-envelope RSA key store (password_rsa_store.go):
// generation and convergence (business.Init path -> GenerateRSAKey), the
// legacy-plaintext-row upgrade, snapshot-restore / rollback semantics (key
// file excluded from snapshots, row as pairing source of truth), file
// permissions and the login/decryptEnvelope read path (checkPassword through
// the store). All tests run against an in-memory sqlite settings table plus a
// temp BaseDir so passwordKeyFilePath() stays inside the test sandbox.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/1Panel-dev/1Panel/backend/app/model"
	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/1Panel-dev/1Panel/backend/utils/encrypt"
	"github.com/1Panel-dev/1Panel/backend/utils/files"
)

// parseTestPublicKey parses a PKIX "PUBLIC KEY" PEM (the format
// exportPublicKeyToPEM writes) into an *rsa.PublicKey for envelope minting.
func parseTestPublicKey(t *testing.T, pubPEM string) *rsa.PublicKey {
	t.Helper()
	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		t.Fatal("decode public key PEM failed")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse public key failed: %v", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("public key is %T, want *rsa.PublicKey", pub)
	}
	return rsaPub
}

// setupKeyStoreTest prepares an in-memory settings table (like
// setupSettingUpdateTest), points BaseDir at a temp dir so the key file never
// touches a real install, seeds the EncryptKey storage key and leaves
// global.CONF.System.EncryptKey cleared so StringEncrypt/StringDecrypt load it
// from the settings table.
func setupKeyStoreTest(t *testing.T) {
	t.Helper()
	setupSettingUpdateTest(t)

	prevKey := global.CONF.System.EncryptKey
	global.CONF.System.EncryptKey = ""
	t.Cleanup(func() { global.CONF.System.EncryptKey = prevKey })

	if err := global.DB.Create(&model.Setting{Key: "EncryptKey", Value: testEncryptKey}).Error; err != nil {
		t.Fatalf("seed EncryptKey failed: %v", err)
	}

	prevBase := global.CONF.System.BaseDir
	global.CONF.System.BaseDir = t.TempDir()
	t.Cleanup(func() { global.CONF.System.BaseDir = prevBase })

	ensureValidateLogger(t)
}

func mustGenTestRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key failed: %v", err)
	}
	return key
}

// seedLegacyPlainRow stores the given PEM as a plaintext PASSWORD_PRIVATE_KEY
// row plus its public half under PASSWORD_PUBLIC_KEY, mimicking a pre-upgrade
// install or a restored snapshot taken by an old build.
func seedLegacyPlainRow(t *testing.T, pem string) {
	t.Helper()
	if err := settingRepo.UpdateOrCreate("PASSWORD_PRIVATE_KEY", pem); err != nil {
		t.Fatalf("seed legacy PASSWORD_PRIVATE_KEY row failed: %v", err)
	}
	if err := settingRepo.UpdateOrCreate("PASSWORD_PUBLIC_KEY", "test-public-key"); err != nil {
		t.Fatalf("seed PASSWORD_PUBLIC_KEY row failed: %v", err)
	}
}

// rawKeyRow reads the PASSWORD_PRIVATE_KEY row verbatim ("" when missing).
func rawKeyRow(t *testing.T) string {
	t.Helper()
	item, err := settingRepo.Get(settingRepo.WithByKey("PASSWORD_PRIVATE_KEY"))
	if err != nil {
		return ""
	}
	return item.Value
}

func keyFileMode(t *testing.T) os.FileMode {
	t.Helper()
	info, err := os.Stat(passwordKeyFilePath())
	if err != nil {
		t.Fatalf("stat password key file failed: %v", err)
	}
	return info.Mode().Perm()
}

// previewKeyRowValue returns a short safe prefix of a row value for failure
// messages (never the full value: it may contain key material).
func previewKeyRowValue(value string) string {
	if len(value) > 16 {
		return value[:16]
	}
	return value
}

func TestGenerateRSAKeyCreatesFileWrappedRowAndPublicKey(t *testing.T) {
	setupKeyStoreTest(t)
	u := &SettingService{}

	if err := u.GenerateRSAKey(); err != nil {
		t.Fatalf("GenerateRSAKey failed: %v", err)
	}

	fileData, err := os.ReadFile(passwordKeyFilePath())
	if err != nil {
		t.Fatalf("password key file missing after generation: %v", err)
	}
	if key := parsePasswordKeyPEM(string(fileData)); key == nil {
		t.Fatal("password key file does not hold a parseable RSA private key")
	}
	if got := keyFileMode(t); got != 0600 {
		t.Fatalf("password key file mode = %v, want 0600", got)
	}
	raw := rawKeyRow(t)
	if raw == "" {
		t.Fatal("PASSWORD_PRIVATE_KEY row missing after generation")
	}
	if !strings.HasPrefix(raw, passwordKeyRowPrefix) {
		t.Fatalf("PASSWORD_PRIVATE_KEY row has no wrapped prefix %q (plaintext PEM must not be stored), value starts with %q", passwordKeyRowPrefix, previewKeyRowValue(raw))
	}
	// the wrapped row must hold the same key as the file
	fileKey, _ := loadPasswordKeyFile()
	rowKey, kind, _ := loadPasswordKeyDBRow()
	if kind != dbKeyWrapped {
		t.Fatalf("PASSWORD_PRIVATE_KEY row kind = %v, want wrapped", kind)
	}
	if !sameRSAPrivateKey(fileKey, rowKey) {
		t.Fatal("file key and wrapped row key do not match")
	}
	if pub, err := settingRepo.Get(settingRepo.WithByKey("PASSWORD_PUBLIC_KEY")); err != nil || pub.Value == "" {
		t.Fatalf("PASSWORD_PUBLIC_KEY row missing after generation (err=%v)", err)
	}

	// generation must be idempotent: a second run keeps the same key
	before := raw
	fileBefore := string(fileData)
	if err := u.GenerateRSAKey(); err != nil {
		t.Fatalf("second GenerateRSAKey failed: %v", err)
	}
	if after := rawKeyRow(t); after != before {
		t.Fatal("GenerateRSAKey rotated an existing key on a second run")
	}
	fileAfter, err := os.ReadFile(passwordKeyFilePath())
	if err != nil {
		t.Fatalf("read key file after second run failed: %v", err)
	}
	if string(fileAfter) != fileBefore {
		t.Fatal("key file changed on a second GenerateRSAKey run")
	}
}

// TestGenerateRSAKeyUpgradesLegacyPlaintextRow simulates an existing install
// upgraded from the old build: the DB still holds a plaintext PEM row, the
// key file does not exist yet. GenerateRSAKey (startup) must keep that key
// (the browser cookie may already carry its public half), materialise the
// 0600 file from it and replace the plaintext row with the wrapped form.
func TestGenerateRSAKeyUpgradesLegacyPlaintextRow(t *testing.T) {
	setupKeyStoreTest(t)
	u := &SettingService{}

	legacyPEM := exportPrivateKeyToPEM(mustGenTestRSAKey(t))
	seedLegacyPlainRow(t, legacyPEM)

	if err := u.GenerateRSAKey(); err != nil {
		t.Fatalf("GenerateRSAKey over a legacy plaintext row failed: %v", err)
	}

	fileKey, _ := loadPasswordKeyFile()
	if fileKey == nil {
		t.Fatal("key file was not materialised from the legacy row")
	}
	if _, kind, _ := loadPasswordKeyDBRow(); kind != dbKeyWrapped {
		t.Fatal("legacy plaintext row was not upgraded to the wrapped form")
	}
	rowKey, _, _ := loadPasswordKeyDBRow()
	if !sameRSAPrivateKey(fileKey, rowKey) {
		t.Fatal("materialised file key does not match the (upgraded) row key")
	}
	if pub, err := settingRepo.Get(settingRepo.WithByKey("PASSWORD_PUBLIC_KEY")); err != nil || pub.Value == "" {
		t.Fatal("PASSWORD_PUBLIC_KEY row was lost during the legacy upgrade")
	}
}

// TestGenerateRSAKeyUpgradeIdempotent runs the legacy upgrade twice: the
// second run must be a no-op (no key rotation, no error).
func TestGenerateRSAKeyUpgradeIdempotent(t *testing.T) {
	setupKeyStoreTest(t)
	u := &SettingService{}

	legacyPEM := exportPrivateKeyToPEM(mustGenTestRSAKey(t))
	seedLegacyPlainRow(t, legacyPEM)
	if err := u.GenerateRSAKey(); err != nil {
		t.Fatalf("first GenerateRSAKey failed: %v", err)
	}
	row1 := rawKeyRow(t)
	file1, _ := os.ReadFile(passwordKeyFilePath())

	if err := u.GenerateRSAKey(); err != nil {
		t.Fatalf("second GenerateRSAKey failed: %v", err)
	}
	if row2 := rawKeyRow(t); row2 != row1 {
		t.Fatal("second GenerateRSAKey changed the PASSWORD_PRIVATE_KEY row")
	}
	file2, _ := os.ReadFile(passwordKeyFilePath())
	if string(file2) != string(file1) {
		t.Fatal("second GenerateRSAKey changed the key file")
	}
}

// TestGenerateRSAKeyMaterialisesFileAfterSnapshotRestore simulates the
// snapshot-restore semantics: the payload ships the database (plaintext row +
// public key, e.g. from an old snapshot) but EXCLUDES secret/password_rsa, and
// a leftover file from the previous install may still sit in the data dir.
// The restored row must win (it is paired with the restored PASSWORD_PUBLIC_KEY
// that the frontend cookie now holds): GenerateRSAKey rewrites the file from
// the row key.
func TestGenerateRSAKeyMaterialisesFileAfterSnapshotRestore(t *testing.T) {
	setupKeyStoreTest(t)
	u := &SettingService{}

	rowKey := mustGenTestRSAKey(t)
	seedLegacyPlainRow(t, exportPrivateKeyToPEM(rowKey))

	// stale leftover file with an unrelated (previous install) key
	staleKey := mustGenTestRSAKey(t)
	if err := writePasswordKeyFile(exportPrivateKeyToPEM(staleKey)); err != nil {
		t.Fatalf("write stale key file failed: %v", err)
	}

	if err := u.GenerateRSAKey(); err != nil {
		t.Fatalf("GenerateRSAKey after restore failed: %v", err)
	}

	fileKey, _ := loadPasswordKeyFile()
	if !sameRSAPrivateKey(fileKey, rowKey) {
		t.Fatal("key file was not rewritten with the restored row key")
	}
	if _, kind, _ := loadPasswordKeyDBRow(); kind != dbKeyWrapped {
		t.Fatal("restored plaintext row was not upgraded to the wrapped form")
	}
}

// TestGenerateRSAKeyRotatesWhenWrappedRowUnusable simulates an EncryptKey
// rotation that orphaned the wrapped row (it can no longer be unwrapped): no
// usable key exists anywhere, so startup generates a fresh keypair (dropping
// the stale rows first).
func TestGenerateRSAKeyRotatesWhenWrappedRowUnusable(t *testing.T) {
	setupKeyStoreTest(t)
	u := &SettingService{}

	if err := settingRepo.UpdateOrCreate("PASSWORD_PRIVATE_KEY", passwordKeyRowPrefix+"rotated-away"); err != nil {
		t.Fatalf("seed orphaned wrapped row failed: %v", err)
	}
	if err := u.GenerateRSAKey(); err != nil {
		t.Fatalf("GenerateRSAKey with an orphaned wrapped row failed: %v", err)
	}
	if _, kind, _ := loadPasswordKeyDBRow(); kind != dbKeyWrapped {
		t.Fatal("fresh key was not stored in wrapped form")
	}
	rowKey, _, _ := loadPasswordKeyDBRow()
	fileKey, _ := loadPasswordKeyFile()
	if !sameRSAPrivateKey(rowKey, fileKey) {
		t.Fatal("fresh file key and row key do not match")
	}
	if raw := rawKeyRow(t); raw == passwordKeyRowPrefix+"rotated-away" {
		t.Fatal("orphaned wrapped row was not replaced by the fresh key")
	}
}

// TestLoadPasswordPrivateKeyFilePreferredWhenMatching ensures the login hot
// path prefers the 0600 file (raw PEM out of the database) when both layers
// hold the same key, and that the loader is side-effect free.
func TestLoadPasswordPrivateKeyFilePreferredWhenMatching(t *testing.T) {
	setupKeyStoreTest(t)

	key := mustGenTestRSAKey(t)
	pem := exportPrivateKeyToPEM(key)
	if err := StorePasswordPrivateKey(pem); err != nil {
		t.Fatalf("StorePasswordPrivateKey failed: %v", err)
	}

	loaded, err := LoadPasswordPrivateKey()
	if err != nil {
		t.Fatalf("LoadPasswordPrivateKey failed: %v", err)
	}
	if !sameRSAPrivateKey(loaded, key) {
		t.Fatal("loaded key does not match the stored key")
	}
	fileData, _ := os.ReadFile(passwordKeyFilePath())
	if string(fileData) != pem {
		t.Fatal("LoadPasswordPrivateKey modified the key file")
	}
}

// TestLoadPasswordPrivateKeyFailsClosedWithoutAnyKey pins the fail-closed
// contract: with no file and no usable row the login path must error instead
// of falling back to plaintext.
func TestLoadPasswordPrivateKeyFailsClosedWithoutAnyKey(t *testing.T) {
	setupKeyStoreTest(t)
	if _, err := LoadPasswordPrivateKey(); err == nil {
		t.Fatal("LoadPasswordPrivateKey succeeded without any key material")
	}
}

// TestLoadPasswordPublicKeyPEMRebuildsMissingRow covers the login-page path:
// when the public key row is missing but the private key exists, the served
// public key must be rebuilt from the private key (the two always pair).
func TestLoadPasswordPublicKeyPEMRebuildsMissingRow(t *testing.T) {
	setupKeyStoreTest(t)

	key := mustGenTestRSAKey(t)
	if err := StorePasswordPrivateKey(exportPrivateKeyToPEM(key)); err != nil {
		t.Fatalf("StorePasswordPrivateKey failed: %v", err)
	}

	pub := LoadPasswordPublicKeyPEM()
	if pub == "" {
		t.Fatal("LoadPasswordPublicKeyPEM returned empty public key")
	}
	row, err := settingRepo.Get(settingRepo.WithByKey("PASSWORD_PUBLIC_KEY"))
	if err != nil || row.Value != pub {
		t.Fatalf("PASSWORD_PUBLIC_KEY row was not rebuilt from the private key (err=%v)", err)
	}

	// the rebuilt public key must pair with the private key the login path
	// loads: mint an envelope against it and decrypt through decryptEnvelope
	envelope := buildPasswordEnvelope(t, parseTestPublicKey(t, pub), "pair-check")
	plain, err := decryptEnvelope(envelope)
	if err != nil || plain != "pair-check" {
		t.Fatalf("envelope decrypt with rebuilt public key failed: plain=%q err=%v", plain, err)
	}
}

// TestCheckPasswordAndDecryptEnvelopeUseFileKey drives the real login path:
// after GenerateRSAKey, a frontend-style envelope minted against the public
// key must decrypt through checkPassword and decryptEnvelope (both read the
// store). Also asserts login fails closed when the whole key material is
// removed.
func TestCheckPasswordAndDecryptEnvelopeUseFileKey(t *testing.T) {
	setupKeyStoreTest(t)
	u := &SettingService{}

	if err := u.GenerateRSAKey(); err != nil {
		t.Fatalf("GenerateRSAKey failed: %v", err)
	}
	// seed a stored password like the real init migration does
	const stored = "admin-password-1"
	encStored, err := encrypt.StringEncrypt(stored)
	if err != nil {
		t.Fatalf("encrypt stored password failed: %v", err)
	}
	if err := settingRepo.UpdateOrCreate("Password", encStored); err != nil {
		t.Fatalf("seed Password failed: %v", err)
	}

	pubRow, err := settingRepo.Get(settingRepo.WithByKey("PASSWORD_PUBLIC_KEY"))
	if err != nil {
		t.Fatalf("read PASSWORD_PUBLIC_KEY failed: %v", err)
	}
	envelope := buildPasswordEnvelope(t, parseTestPublicKey(t, pubRow.Value), stored)
	if err := checkPassword(envelope); err != nil {
		t.Fatalf("checkPassword rejected a valid envelope: %v", err)
	}
	if err := checkPassword("plaintext-must-fail"); err == nil {
		t.Fatal("checkPassword accepted plaintext (fail closed broken)")
	}

	// remove all key material: login must fail closed
	_ = os.Remove(passwordKeyFilePath())
	_ = settingRepo.Delete("PASSWORD_PRIVATE_KEY")
	_ = settingRepo.Delete("PASSWORD_PUBLIC_KEY")
	if err := checkPassword(envelope); err == nil {
		t.Fatal("checkPassword succeeded without any key material")
	}
	if _, err := decryptEnvelope(envelope); err == nil {
		t.Fatal("decryptEnvelope succeeded without any key material")
	}
}

// TestKeyFileSurvivesUnrelatedSecretDirCleanup ensures the password key file
// is never swept by the TLS-material cleanup. UpdateSSL(disable) removes
// exactly the two panel TLS files (server.crt/server.key); the password key
// file shares the secret dir by convention (like loadInfoFromCert) but must
// never be touched by that cleanup. The disable branch's removals are
// replicated here instead of calling UpdateSSL, whose trailing
// systemctl.Restart goroutine is not testable in a unit environment.
func TestKeyFileSurvivesUnrelatedSecretDirCleanup(t *testing.T) {
	setupKeyStoreTest(t)
	u := &SettingService{}

	if err := u.GenerateRSAKey(); err != nil {
		t.Fatalf("GenerateRSAKey failed: %v", err)
	}
	secretDir := filepath.Dir(passwordKeyFilePath())
	crtPath := filepath.Join(secretDir, "server.crt")
	keyPath := filepath.Join(secretDir, "server.key")
	if err := os.WriteFile(crtPath, []byte("x"), 0600); err != nil {
		t.Fatalf("seed server.crt failed: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte("x"), 0600); err != nil {
		t.Fatalf("seed server.key failed: %v", err)
	}

	// the exact removals UpdateSSL performs for SSL=disable
	_ = os.Remove(crtPath)
	_ = os.Remove(keyPath)

	if _, err := os.Stat(passwordKeyFilePath()); err != nil {
		t.Fatalf("password key file was removed by the TLS cleanup: %v", err)
	}
}

// TestSnapPanelDataExcludesPasswordKeyFile pins the snapshot hardening: the
// 1panel_data payload must never carry the password_rsa key file. It runs
// snapPanelData end to end (like the real snapshot pipeline) and inspects the
// produced archive member list.
func TestSnapPanelDataExcludesPasswordKeyFile(t *testing.T) {
	setupKeyStoreTest(t)

	if err := settingRepo.UpdateOrCreate("SystemIP", "10.0.0.1"); err != nil {
		t.Fatalf("seed SystemIP failed: %v", err)
	}
	if err := settingRepo.UpdateOrCreate("SnapshotIgnore", ""); err != nil {
		t.Fatalf("seed SnapshotIgnore failed: %v", err)
	}

	dataDir := filepath.Join(global.CONF.System.BaseDir, "1panel")
	secretDir := filepath.Join(dataDir, "secret")
	if err := os.MkdirAll(filepath.Join(dataDir, "db"), 0755); err != nil {
		t.Fatalf("mkdir db: %v", err)
	}
	if err := os.MkdirAll(secretDir, 0755); err != nil {
		t.Fatalf("mkdir secret: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "db", "1Panel.db"), []byte("sqlite"), 0600); err != nil {
		t.Fatalf("write fake db: %v", err)
	}
	if err := os.WriteFile(filepath.Join(secretDir, passwordKeyFileName), []byte("secret-key"), 0600); err != nil {
		t.Fatalf("write password_rsa: %v", err)
	}
	if err := os.WriteFile(filepath.Join(secretDir, "server.crt"), []byte("crt"), 0600); err != nil {
		t.Fatalf("write server.crt: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "keep.txt"), []byte("keep"), 0644); err != nil {
		t.Fatalf("write keep.txt: %v", err)
	}

	localDir := filepath.Join(global.CONF.System.BaseDir, "backup")
	outDir := filepath.Join(localDir, "out")
	if err := os.MkdirAll(outDir, 0755); err != nil {
		t.Fatalf("mkdir out: %v", err)
	}

	h := snapHelper{
		SnapID: 1,
		Status: &model.SnapshotStatus{},
		Ctx:    context.Background(),
		FileOp: files.NewFileOp(),
		Wg:     &sync.WaitGroup{},
	}
	snapPanelData(h, localDir, outDir)

	members := archiveMembers(t, filepath.Join(outDir, "1panel_data.tar.gz"))
	if strings.Contains(members, "password_rsa") {
		t.Fatalf("snapshot payload carries the password key file:\n%s", members)
	}
	if !strings.Contains(members, "server.crt") {
		t.Fatalf("snapshot payload should still carry server.crt:\n%s", members)
	}
	if !strings.Contains(members, "keep.txt") {
		t.Fatalf("snapshot payload should carry regular data files:\n%s", members)
	}
}
