package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

// EncryptAESGCM encrypts plaintext with a 32-byte key using AES-GCM.
// Returns nonce||ciphertext.
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

// DecryptAESGCM decrypts nonce||ciphertext with a 32-byte key using AES-GCM.
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

// generateRandomBytes generates a slice of random bytes of the given length.
// Returns the byte slice and any error encountered.
func generateRandomBytes(length int) ([]byte, error) {
	bytes := make([]byte, length)
	_, err := io.ReadFull(rand.Reader, bytes)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}

// ErrInvalidKeyLength is returned when the provided key length is invalid.
var ErrInvalidKeyLength = errors.New("invalid key length")
