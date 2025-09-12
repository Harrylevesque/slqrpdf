package internal

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ===== Master Key / User File Storage =====
// TODO(storage-backend-abstraction): Abstract storage (interface) so we can replace JSON files with DB later.
// TODO(storage-user-encryption-metadata): Store encryption key version + AEAD algorithm with user file.
// TODO(storage-device-index): Add index structure for devices by user for quick lookup (map or separate file / DB table).
// TODO(storage-session-revocation-cache): Implement in-memory + persistent revocation list (session_id -> revoked_at).
// TODO(storage-nonce-store): Add nonce persistence (Value -> {user_id, device_id, expires_at, used}).
// TODO(storage-audit-append): Implement AppendAudit(event) that writes + chains hash (prev_hash, hash) atomically.
// TODO(storage-recovery-codes): Persist hashed recovery codes & mark used atomically.
// TODO(storage-heartbeat): Buffer heartbeat updates in memory & flush periodically.
// TODO(storage-cleanup): Add GC for expired nonces, dead sessions, used recovery codes.
// TODO(storage-account-deletion): Implement deletion scheduler scanning for users in deleting state.
// TODO(storage-migrations): Provide simple migration runner to evolve file schema.

func ReadMasterKey() ([]byte, error) {
	h := os.Getenv("MASTER_KEY_HEX")
	if h == "" {
		// Try to read from master.key file
		data, err := os.ReadFile("master.key")
		if err != nil {
			return nil, fmt.Errorf("MASTER_KEY_HEX not set and master.key file not found")
		}
		h = string(data)
	}
	h = strings.TrimSpace(h)
	b, err := hex.DecodeString(h)
	if err != nil {
		return nil, fmt.Errorf("master key hex decode error: %w", err)
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("master key length must be 32 bytes (hex 64 chars)")
	}
	return b, nil
}

func WriteEncryptedUserFile(outDir string, user *User, masterKey []byte) (string, error) {
	plain, err := json.MarshalIndent(user, "", "  ")
	if err != nil {
		return "", err
	}
	enc, err := EncryptAESGCM(masterKey, plain)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(outDir, 0700); err != nil {
		return "", err
	}
	filename := filepath.Join(outDir, user.UserID+".json.enc")
	if err := os.WriteFile(filename, enc, 0600); err != nil {
		return "", err
	}
	return filename, nil
}

func ReadEncryptedUserFile(path string, masterKey []byte) (*User, error) {
	blob, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	plain, err := DecryptAESGCM(masterKey, blob)
	if err != nil {
		return nil, err
	}
	var u User
	if err := json.Unmarshal(plain, &u); err != nil {
		return nil, err
	}
	return &u, nil
}

func WriteUserFile(outDir string, user *User) (string, error) {
	plain, err := json.MarshalIndent(user, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(outDir, 0700); err != nil {
		return "", err
	}
	filename := filepath.Join(outDir, user.UserID+".json")
	if err := os.WriteFile(filename, plain, 0600); err != nil {
		return "", err
	}
	return filename, nil
}

func ReadUserFile(path string) (*User, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var u User
	if err := json.NewDecoder(f).Decode(&u); err != nil {
		return nil, err
	}
	return &u, nil
}

// ===== RSA Key Pair (optional) =====
// TODO(storage-rsa-deprecate): Evaluate if RSA needed once Ed25519/PQC added; possibly remove to reduce surface.

const (
	privateKeyFile = "private_key.pem"
	publicKeyFile  = "public_key.pem"
)

func GenerateKeyPair(dir string) error {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	privBytes := x509.MarshalPKCS1PrivateKey(priv)
	if err := ioutil.WriteFile(filepath.Join(dir, privateKeyFile), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}), 0600); err != nil {
		return err
	}
	pubBytes := x509.MarshalPKCS1PublicKey(&priv.PublicKey)
	if err := ioutil.WriteFile(filepath.Join(dir, publicKeyFile), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes}), 0644); err != nil {
		return err
	}
	return nil
}

func LoadPrivateKey(dir string) (*rsa.PrivateKey, error) {
	pemBytes, err := ioutil.ReadFile(filepath.Join(dir, privateKeyFile))
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("decode private key")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func LoadPublicKey(dir string) (*rsa.PublicKey, error) {
	pemBytes, err := ioutil.ReadFile(filepath.Join(dir, publicKeyFile))
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("decode public key")
	}
	return x509.ParsePKCS1PublicKey(block.Bytes)
}

func EncryptWithPublic(plain []byte, pub *rsa.PublicKey) ([]byte, error) {
	return rsa.EncryptPKCS1v15(rand.Reader, pub, plain)
}
func DecryptWithPrivate(ct []byte, priv *rsa.PrivateKey) ([]byte, error) {
	return rsa.DecryptPKCS1v15(rand.Reader, priv, ct)
}

func FileExists(path string) bool { _, err := os.Stat(path); return !os.IsNotExist(err) }

// ===== QR Store (simple JSON file in home dir) =====
// TODO(storage-qr-encryption): If qrEncryption enabled, encrypt QR data before save.
// TODO(storage-qr-expiry): Enforce max lifetime for stored QR codes and purge old entries.
// TODO(storage-qr-index): Provide lookup by ID in addition to GetAll().

type QRCode struct {
	ID        string    `json:"id"`
	Data      string    `json:"data"`
	CreatedAt time.Time `json:"created_at"`
}

type QRCodeStore struct {
	filePath string
	mu       sync.RWMutex
}

const qrDB = "qr_store.json"

func NewQRCodeStore() *QRCodeStore {
	dir, err := os.UserHomeDir()
	if err != nil {
		dir = os.TempDir()
	}
	return &QRCodeStore{filePath: filepath.Join(dir, qrDB)}
}

func (s *QRCodeStore) Save(qr *QRCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var qrs []QRCode
	if data, err := ioutil.ReadFile(s.filePath); err == nil {
		_ = json.Unmarshal(data, &qrs)
	}
	for _, v := range qrs {
		if v.Data == qr.Data {
			return fmt.Errorf("duplicate qr data")
		}
	}
	qr.ID = fmt.Sprintf("qr-%d", time.Now().UnixNano())
	qr.CreatedAt = time.Now()
	qrs = append(qrs, *qr)
	data, err := json.MarshalIndent(qrs, "", "  ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(s.filePath, data, 0644)
}

func (s *QRCodeStore) GetAll() ([]QRCode, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	data, err := ioutil.ReadFile(s.filePath)
	if err != nil {
		return nil, err
	}
	var qrs []QRCode
	if err := json.Unmarshal(data, &qrs); err != nil {
		return nil, err
	}
	return qrs, nil
}

func (s *QRCodeStore) Clear() error { s.mu.Lock(); defer s.mu.Unlock(); return os.Remove(s.filePath) }
