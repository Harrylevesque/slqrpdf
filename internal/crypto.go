package internal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"io"
	"strings"

	"golang.org/x/crypto/hkdf"
)

// ===== Crypto / Key Derivation =====

// TODO(crypto-hkdf-context): Centralize HKDF info strings as constants for auditability.
// TODO(crypto-pqc): Add placeholder Dilithium key generation & signature verify stubs (guarded by build tag / config).
// TODO(crypto-secretK-rotation): Implement SecretK rotation policy (track key version; maintain previous for grace window).
// TODO(crypto-secretD-hardware): Integrate hardware-backed key retrieval when available instead of derivation fallback.
// TODO(crypto-zeroize): Ensure sensitive byte slices are zeroed after use (use explicit wipe helper).
// TODO(crypto-totp-migration): Provide migration path if switching away from TOTP to passkeys only.

func DeriveLongSeed(mash []byte) ([]byte, error) {
	h := hkdf.New(sha256.New, mash, nil, []byte("long-seed"))
	out := make([]byte, 64)
	if _, err := io.ReadFull(h, out); err != nil {
		return nil, err
	}
	return out, nil
}

func DeriveShortSeed(long []byte) []byte {
	if len(long) < 16 {
		return long
	}
	return long[:16]
}

func DeriveTOTPSeed(long []byte) (string, error) {
	mac := hmac.New(sha256.New, long)
	mac.Write([]byte("totp-seed"))
	out := mac.Sum(nil)
	seedBytes := out[:20]
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	return strings.ToUpper(enc.EncodeToString(seedBytes)), nil
}

func DeriveSecretD(mash []byte, deviceFP string) ([]byte, error) {
	ikm := append(mash, []byte(deviceFP)...)
	h := hkdf.New(sha256.New, ikm, nil, []byte("secret-d"))
	out := make([]byte, 32)
	if _, err := io.ReadFull(h, out); err != nil {
		return nil, err
	}
	return out, nil
}

func GenerateSecretK() []byte { return MustRandom(32) }

func MustRandom(n int) []byte {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		panic(err)
	}
	return b
}

// ===== AES-GCM File Encryption =====

// TODO(crypto-xchacha): Add XChaCha20-Poly1305 option (libsodium / chacha20poly1305) for large-scale nonce simplification.
// TODO(crypto-aead-associated): Incorporate associated data (user_id + filename) into AEAD seal for integrity binding.
// TODO(crypto-key-id): Prepend a key version header to ciphertext for future rotation/decryption decisions.
// TODO(crypto-auth-encrypt): Move to streaming encryption helper for large user blobs (if size grows).

var ErrInvalidKeyLength = errors.New("invalid key length")

func EncryptAESGCM(masterKey, plaintext []byte) ([]byte, error) {
	if len(masterKey) != 32 {
		return nil, errors.New("master key must be 32 bytes")
	}
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ct := gcm.Seal(nil, nonce, plaintext, nil)
	return append(nonce, ct...), nil
}

func DecryptAESGCM(masterKey, blob []byte) ([]byte, error) {
	if len(masterKey) != 32 {
		return nil, errors.New("master key must be 32 bytes")
	}
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(blob) < ns {
		return nil, errors.New("ciphertext too short")
	}
	nonce := blob[:ns]
	ct := blob[ns:]
	return gcm.Open(nil, nonce, ct, nil)
}
