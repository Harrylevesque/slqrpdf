package crypto

import (
	"crypto/hmac"

	"crypto/sha256"
	"encoding/base32"
	"golang.org/x/crypto/hkdf"
	"io"
	"strings"
)

// DeriveLongSeed derives a 64-byte long seed from a mash seed using HKDF-SHA256.
func DeriveLongSeed(mash []byte) ([]byte, error) {
	h := hkdf.New(sha256.New, mash, nil, []byte("long-seed"))
	out := make([]byte, 64)
	if _, err := io.ReadFull(h, out); err != nil {
		return nil, err
	}
	return out, nil
}

// DeriveShortSeed returns the first 16 bytes of the long seed.
func DeriveShortSeed(long []byte) []byte {
	if len(long) < 16 {
		return long
	}
	return long[:16]
}

// DeriveTOTPSeed derives a TOTP seed from the long seed using HMAC-SHA256 and encodes it in base32.
func DeriveTOTPSeed(long []byte) (string, error) {
	mac := hmac.New(sha256.New, long)
	mac.Write([]byte("totp-seed"))
	out := mac.Sum(nil)
	seedBytes := out[:20] // 160-bit
	base32encoder := base32.StdEncoding.WithPadding(base32.NoPadding)
	return strings.ToUpper(base32encoder.EncodeToString(seedBytes)), nil
}

// DeriveSecretD derives a device-specific secret using HKDF-SHA256 from mash seed and device fingerprint.
func DeriveSecretD(mash []byte, deviceFP string) ([]byte, error) {
	ikm := append(mash, []byte(deviceFP)...)
	hk := hkdf.New(sha256.New, ikm, nil, []byte("secret-d"))
	out := make([]byte, 32)
	if _, err := io.ReadFull(hk, out); err != nil {
		return nil, err
	}
	return out, nil
}

// GenerateSecretK generates a random 32-byte secret key.
func GenerateSecretK() []byte {
	return MustRandom(32)
}

// MustRandom returns n random bytes or panics.
func MustRandom(n int) []byte {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		panic(err)
	}
	return b
}
