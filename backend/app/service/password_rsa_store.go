package service

// password_rsa_store.go — storage of the RSA keypair that protects login
// passwords in transit (the "password envelope": the frontend RSA-OAEP/AES
// encrypts the typed password against PASSWORD_PUBLIC_KEY; the server
// decrypts it with the matching private key before comparing against the
// stored Password setting).
//
// Threat model: the raw RSA private key used to live as plaintext PEM in the
// settings table (key PASSWORD_PRIVATE_KEY), i.e. inside 1Panel.db — the same
// database that carries EncryptKey and JWTSigningKey. Any channel that leaks
// the database file (panel backup/snapshot payload, arbitrary-file-read
// vulnerability, host read) therefore also leaked the key that decrypts every
// historical in-transit password envelope.
//
// Storage strategy (three layers, one authoritative key):
//
//  1. File: <BaseDir>/1panel/secret/password_rsa, root-owned 0600, written
//     atomically (temp file + rename). This keeps a raw PEM out of the
//     database: a leak of only the settings table (or a sqlite export) no
//     longer yields the envelope-decryption key. The file sits in the
//     pre-existing secret dir next to the panel TLS server.crt/server.key and
//     follows their conventions (loadInfoFromCert/checkCertValid read the
//     same directory).
//
//  2. Settings row PASSWORD_PRIVATE_KEY, wrapped with EncryptKey (AES, the
//     same scheme that protects the Password row itself) under the prefix
//     "1panel:rsa:key:". New installs and post-upgrade convergence always
//     leave the row wrapped, never plaintext. The wrapped row makes a
//     snapshot restore self-sufficient: snapshots EXCLUDE the key file (see
//     snapshot_create.go snapPanelData), so after a restore the panel boots
//     with a file that may belong to the pre-restore install; the startup
//     convergence below re-derives the file from the restored row, keeping
//     the served PASSWORD_PUBLIC_KEY (also restored) paired with the private
//     key. Without the row, a restore onto a fresh install would strand a
//     mismatched key file and lock the panel out (frontend would encrypt
//     against the restored public key while the leftover file decrypts with
//     a different private key).
//
//  3. Pre-upgrade installs keep a plaintext PEM row until the first boot of
//     this build, whose convergence (ensurePasswordRSAKey, called from
//     business.Init -> GenerateRSAKey before the router starts serving)
//     replaces it with the wrapped form and materialises the file.
//
// Read order (LoadPasswordPrivateKey, the login/decryptEnvelope hot path):
// the database row is the pairing source of truth because PASSWORD_PUBLIC_KEY
// is served to browsers from the same table; the file is preferred only when
// it matches the row-derived key (compared by public modulus/exponent), so a
// restore or rollback that swaps the database never lets a stale file shadow
// the restored key. When only one layer is usable, it is used. The function
// is read-only and side-effect free: every write happens in
// ensurePasswordRSAKey at startup, so a failure mid-boot cannot leave the
// login path half-converged (a file can only disagree with the row between a
// restore swap and the next restart, and the row wins there).

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/1Panel-dev/1Panel/backend/global"
	"github.com/1Panel-dev/1Panel/backend/utils/encrypt"
)

// passwordKeyFileName is the private-key file name inside the panel secret
// directory. It deliberately shares no suffix with the panel TLS material
// (server.crt/server.key): UpdateSSL removes those files when SSL is
// disabled, and this file must never be swept by that path.
const passwordKeyFileName = "password_rsa"

// passwordKeyRowPrefix marks a PASSWORD_PRIVATE_KEY row value that is the
// EncryptKey-wrapped PEM (scheme: prefix + base64(AES(PEM))). A PEM block
// always starts with "-----", so the prefix is unambiguous.
const passwordKeyRowPrefix = "1panel:rsa:key:"

type dbKeyKind int

const (
	dbKeyNone dbKeyKind = iota
	dbKeyWrapped
	dbKeyPlain
)

func passwordKeyFilePath() string {
	return path.Join(global.CONF.System.BaseDir, "1panel", "secret", passwordKeyFileName)
}

// passwordKeyDBRow reads the PASSWORD_PRIVATE_KEY row value ("" when the row
// is missing).
func passwordKeyDBRow() string {
	item, err := settingRepo.Get(settingRepo.WithByKey("PASSWORD_PRIVATE_KEY"))
	if err != nil || item.Value == "" {
		return ""
	}
	return item.Value
}

// encodeWrappedPasswordKey wraps a PEM private key with the panel EncryptKey
// (the AES key that already protects the Password setting).
func encodeWrappedPasswordKey(privateKeyPEM string) (string, error) {
	encrypted, err := encrypt.StringEncrypt(privateKeyPEM)
	if err != nil {
		return "", err
	}
	return passwordKeyRowPrefix + encrypted, nil
}

// decodeWrappedPasswordKey unwraps a row value produced by
// encodeWrappedPasswordKey.
func decodeWrappedPasswordKey(value string) (string, error) {
	if !strings.HasPrefix(value, passwordKeyRowPrefix) {
		return "", errors.New("setting value is not a wrapped password key")
	}
	plain, err := encrypt.StringDecrypt(strings.TrimPrefix(value, passwordKeyRowPrefix))
	if err != nil {
		return "", err
	}
	return plain, nil
}

// parsePasswordKeyPEM parses a PEM string into an RSA private key, returning
// nil (no error) when the value cannot be a PEM key so callers can treat it
// as "no usable key in this layer" without failing the whole lookup.
func parsePasswordKeyPEM(value string) *rsa.PrivateKey {
	if value == "" {
		return nil
	}
	key, err := encrypt.ParseRSAPrivateKey(value)
	if err != nil {
		return nil
	}
	return key
}

// sameRSAPrivateKey reports whether two parsed keys carry the same public
// part (modulus and exponent). Comparing only the public part is sufficient:
// two private keys with equal public parameters are interchangeable for
// decrypting envelopes minted against the shared PASSWORD_PUBLIC_KEY.
func sameRSAPrivateKey(a, b *rsa.PrivateKey) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.PublicKey.N.Cmp(b.PublicKey.N) == 0 && a.PublicKey.E == b.PublicKey.E
}

// loadPasswordKeyFile reads and parses the key file, returning nil when the
// file is absent or unparseable (an unparseable file is treated as absent so
// the layer fallback still works; ensurePasswordRSAKey rewrites it).
func loadPasswordKeyFile() (*rsa.PrivateKey, string) {
	data, err := os.ReadFile(passwordKeyFilePath())
	if err != nil {
		return nil, ""
	}
	value := string(data)
	return parsePasswordKeyPEM(value), value
}

// LoadPasswordPublicKeyPEM returns the PEM of the PASSWORD_PUBLIC_KEY row the
// frontend needs on the (unauthenticated) login page, recreating the row from
// the private key when it is missing so the served public key always pairs
// with the private key the login handler can use. Returns "" when no key is
// available at all; SetPasswordPublicKey then simply does not set the cookie
// and login fails closed server-side.
func LoadPasswordPublicKeyPEM() string {
	if item, err := settingRepo.Get(settingRepo.WithByKey("PASSWORD_PUBLIC_KEY")); err == nil && item.Value != "" {
		return item.Value
	}
	privateKey, err := LoadPasswordPrivateKey()
	if err != nil {
		return ""
	}
	pubPEM, err := exportPublicKeyToPEM(&privateKey.PublicKey)
	if err != nil {
		return ""
	}
	_ = settingRepo.UpdateOrCreate("PASSWORD_PUBLIC_KEY", pubPEM)
	return pubPEM
}

// loadPasswordKeyDBRow classifies and parses the PASSWORD_PRIVATE_KEY row.
func loadPasswordKeyDBRow() (*rsa.PrivateKey, dbKeyKind, string) {
	value := passwordKeyDBRow()
	if value == "" {
		return nil, dbKeyNone, ""
	}
	if strings.HasPrefix(value, passwordKeyRowPrefix) {
		if plain, err := decodeWrappedPasswordKey(value); err == nil {
			if key := parsePasswordKeyPEM(plain); key != nil {
				return key, dbKeyWrapped, plain
			}
		}
		// A wrapped row that cannot be unwrapped/parsed (e.g. EncryptKey
		// rotated since the row was written) is unusable; the caller treats
		// it like a missing row.
		return nil, dbKeyNone, ""
	}
	if key := parsePasswordKeyPEM(value); key != nil {
		return key, dbKeyPlain, value
	}
	return nil, dbKeyNone, ""
}

// LoadPasswordPrivateKey returns the RSA private key used to decrypt
// password envelopes on the login / password-change hot paths
// (checkPassword, decryptEnvelope). Read order and pairing rules:
//
//   - usable row key + usable file key, matching -> the file is returned
//     (the raw PEM lives on disk, not in the database);
//   - usable row key + usable file key, mismatching -> the row key wins,
//     because the served PASSWORD_PUBLIC_KEY is paired with the row key
//     (this can only happen between a snapshot restore/rollback swap and
//     the next startup convergence);
//   - only one usable layer -> that key is returned;
//   - none -> an error (fail closed, mirroring the historical behavior of a
//     missing/corrupt PASSWORD_PRIVATE_KEY row).
func LoadPasswordPrivateKey() (*rsa.PrivateKey, error) {
	rowKey, _, _ := loadPasswordKeyDBRow()
	fileKey, _ := loadPasswordKeyFile()

	switch {
	case rowKey != nil && fileKey != nil:
		if sameRSAPrivateKey(rowKey, fileKey) {
			return fileKey, nil
		}
		return rowKey, nil
	case rowKey != nil:
		return rowKey, nil
	case fileKey != nil:
		return fileKey, nil
	}
	return nil, errors.New("no usable password RSA private key (file and settings row are both missing or unparseable)")
}

// writePasswordKeyFile persists the PEM atomically with 0600 permissions:
// content goes to a temp file in the same directory (same filesystem), is
// synced, then renamed over the target. Re-running is idempotent.
func writePasswordKeyFile(privateKeyPEM string) error {
	filePath := passwordKeyFilePath()
	dirPath := path.Dir(filePath)
	if err := os.MkdirAll(dirPath, 0700); err != nil {
		return fmt.Errorf("create password key dir failed: %w", err)
	}
	tmpPath := filePath + ".tmp"
	f, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("create password key temp file failed: %w", err)
	}
	if _, err := f.WriteString(privateKeyPEM); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("write password key temp file failed: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("sync password key temp file failed: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("close password key temp file failed: %w", err)
	}
	// OpenFile already applied 0600 (subject to umask); tighten explicitly so
	// a permissive umask can never widen the file.
	if err := os.Chmod(tmpPath, 0600); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("chmod password key temp file failed: %w", err)
	}
	if err := os.Rename(tmpPath, filePath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("install password key file failed: %w", err)
	}
	if err := os.Chmod(filePath, 0600); err != nil {
		return fmt.Errorf("chmod password key file failed: %w", err)
	}
	return nil
}

// StorePasswordPrivateKey persists a freshly generated (or converged) private
// key in both layers: the 0600 file and the EncryptKey-wrapped settings row.
// The plaintext PEM is never written to the settings table by this function.
func StorePasswordPrivateKey(privateKeyPEM string) error {
	if err := writePasswordKeyFile(privateKeyPEM); err != nil {
		return err
	}
	wrapped, err := encodeWrappedPasswordKey(privateKeyPEM)
	if err != nil {
		// Wrapping needs the EncryptKey row; when it is unavailable the file
		// is already in place and the wrapped row is skipped (the row only
		// matters as a restore fallback). Do not fail the store over it.
		global.LOG.Errorf("wrap PASSWORD_PRIVATE_KEY for the settings row failed: %v", err)
		return nil
	}
	if err := settingRepo.UpdateOrCreate("PASSWORD_PRIVATE_KEY", wrapped); err != nil {
		return fmt.Errorf("store wrapped PASSWORD_PRIVATE_KEY failed: %w", err)
	}
	return nil
}

// ensurePasswordRSAKey converges the key store to a single authoritative
// key. It runs once per startup (business.Init -> GenerateRSAKey, before the
// router begins serving) and is idempotent:
//
//   - row and file usable and matching -> nothing to do (the common case);
//   - only a usable row (legacy plaintext or wrapped, e.g. right after a
//     snapshot restore whose payload excluded the file) -> materialise the
//     file from the row key and upgrade a legacy plaintext row to the
//     wrapped form;
//   - only a usable file (e.g. EncryptKey rotation wiped the rows) ->
//     rebuild the wrapped row and the PASSWORD_PUBLIC_KEY row from the file;
//   - row and file usable but mismatching -> the row wins (public-key
//     pairing), the file is rewritten with the row key;
//   - nothing usable -> generate a fresh 2048-bit key and store it in both
//     layers plus the PASSWORD_PUBLIC_KEY row (historical GenerateRSAKey
//     semantics, minus the plaintext row).
func ensurePasswordRSAKey() error {
	rowKey, rowKind, rowPEM := loadPasswordKeyDBRow()
	fileKey, _ := loadPasswordKeyFile()

	switch {
	case rowKey != nil && fileKey != nil && sameRSAPrivateKey(rowKey, fileKey):
		if rowKind == dbKeyPlain {
			// Legacy plaintext row from a pre-upgrade install (or from a
			// restored old snapshot): keep the file, upgrade the row to the
			// wrapped form so the settings table stops carrying a raw PEM.
			return upgradePlainPasswordKeyRow(rowPEM)
		}
		return nil
	case rowKey != nil:
		// The database row is the pairing source of truth: when the file is
		// absent (fresh boot of an upgraded install, snapshot restore that
		// excluded the file, manual deletion) or stale, re-derive it from the
		// row key so the on-disk copy always matches the served public key.
		if err := writePasswordKeyFile(rowPEM); err != nil {
			return err
		}
		if rowKind == dbKeyPlain {
			return upgradePlainPasswordKeyRow(rowPEM)
		}
		return nil
	case fileKey != nil:
		// No usable row (e.g. a wrapped row whose EncryptKey rotated, or a
		// pre-key-row database): rebuild the rows from the file. The public
		// key must match the private key so browsers encrypt against it.
		pubPEM, err := exportPublicKeyToPEM(&fileKey.PublicKey)
		if err != nil {
			return err
		}
		if err := StorePasswordPrivateKey(exportPrivateKeyToPEM(fileKey)); err != nil {
			return err
		}
		return settingRepo.UpdateOrCreate("PASSWORD_PUBLIC_KEY", pubPEM)
	}

	// Nothing usable anywhere: generate a fresh keypair. Stale unparseable
	// rows (e.g. a wrapped row left behind by an EncryptKey rotation) are
	// dropped first so they cannot shadow the new key later.
	_ = settingRepo.Delete("PASSWORD_PRIVATE_KEY")
	_ = settingRepo.Delete("PASSWORD_PUBLIC_KEY")

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	privateKeyPEM := exportPrivateKeyToPEM(privateKey)
	publicKeyPEM, err := exportPublicKeyToPEM(&privateKey.PublicKey)
	if err != nil {
		return err
	}
	if err := StorePasswordPrivateKey(privateKeyPEM); err != nil {
		return err
	}
	return settingRepo.UpdateOrCreate("PASSWORD_PUBLIC_KEY", publicKeyPEM)
}

// upgradePlainPasswordKeyRow replaces a legacy plaintext PASSWORD_PRIVATE_KEY
// row with its EncryptKey-wrapped form. The file already carries the key at
// this point, so a wrap failure (missing EncryptKey) keeps the plaintext row
// functional instead of breaking login.
func upgradePlainPasswordKeyRow(plainPEM string) error {
	wrapped, err := encodeWrappedPasswordKey(plainPEM)
	if err != nil {
		global.LOG.Errorf("wrap legacy PASSWORD_PRIVATE_KEY row failed: %v", err)
		return nil
	}
	return settingRepo.Update("PASSWORD_PRIVATE_KEY", wrapped)
}
