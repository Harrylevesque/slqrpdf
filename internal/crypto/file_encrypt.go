package crypto

import (
	"crypto/rand"
	"errors"
	"io"
)

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
