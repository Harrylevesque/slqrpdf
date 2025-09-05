package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
)

// Encrypt encrypts the given plaintext using the provided key.
// The key must be 16, 24, or 32 bytes long for AES-128, AES-192, or AES-256 respectively.
// Returns the ciphertext and any error encountered.
func Encrypt(plaintext, key string) (string, error) {
	// Convert the key to a byte slice
	keyBytes, err := hex.DecodeString(key)
	if err != nil {
		return "", err
	}

	// Create a new AES cipher using the key
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", err
	}

	// Convert the plaintext to a byte slice
	plainBytes, err := hex.DecodeString(plaintext)
	if err != nil {
		return "", err
	}

	// Encrypt the plaintext using AES in CTR mode
	ciphertext := make([]byte, len(plainBytes))
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext, plainBytes)

	return hex.EncodeToString(ciphertext), nil
}

// Decrypt decrypts the given ciphertext using the provided key.
// The key must be 16, 24, or 32 bytes long for AES-128, AES-192, or AES-256 respectively.
// Returns the plaintext and any error encountered.
func Decrypt(ciphertext, key string) (string, error) {
	// Convert the key to a byte slice
	keyBytes, err := hex.DecodeString(key)
	if err != nil {
		return "", err
	}

	// Create a new AES cipher using the key
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", err
	}

	// Convert the ciphertext to a byte slice
	cipherBytes, err := hex.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	// Decrypt the ciphertext using AES in CTR mode
	plaintext := make([]byte, len(cipherBytes))
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(plaintext, cipherBytes)

	return hex.EncodeToString(plaintext), nil
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
