package files

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/harrylevesque/slqrpdf/internal/crypto"
	"github.com/harrylevesque/slqrpdf/internal/models"
)

// ReadMasterKey reads MASTER_KEY_HEX env var (hex, 64 chars -> 32 bytes)
func ReadMasterKey() ([]byte, error) {
	hexk := os.Getenv("MASTER_KEY_HEX")
	if hexk == "" {
		return nil, fmt.Errorf("MASTER_KEY_HEX not set")
	}
	b, err := hex.DecodeString(hexk)
	if err != nil {
		return nil, fmt.Errorf("master key hex decode error: %w", err)
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("master key length must be 32 bytes (hex 64 chars)")
	}
	return b, nil
}

// WriteEncryptedUserFile writes a user struct to an encrypted file
func WriteEncryptedUserFile(outDir string, user *models.User, masterKey []byte) (string, error) {
	plain, err := json.MarshalIndent(user, "", "  ")
	if err != nil {
		return "", err
	}
	enc, err := crypto.EncryptAESGCM(masterKey, plain)
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

// ReadEncryptedUserFile reads and decrypts a user file
func ReadEncryptedUserFile(path string, masterKey []byte) (*models.User, error) {
	blob, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	plain, err := crypto.DecryptAESGCM(masterKey, blob)
	if err != nil {
		return nil, err
	}
	var u models.User
	if err := json.Unmarshal(plain, &u); err != nil {
		return nil, err
	}
	return &u, nil
}

// WriteUserFile writes a user struct to a plain JSON file
func WriteUserFile(outDir string, user *models.User) (string, error) {
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

// ReadUserFile reads a plain JSON user file and returns a User struct
func ReadUserFile(path string) (*models.User, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	var user models.User
	err = json.NewDecoder(f).Decode(&user)
	closeErr := f.Close()
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		return nil, closeErr
	}
	return &user, nil
}
