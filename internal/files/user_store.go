package files

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/harry/slqrpdf/internal/crypto"
	"github.com/harry/slqrpdf/internal/models"
)

// readMasterKey reads MASTER_KEY_HEX env var (hex, 64 chars -> 32 bytes)
func readMasterKey() ([]byte, error) {
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

// writeEncryptedUserFile writes a user struct to an encrypted file
func writeEncryptedUserFile(outDir string, user *models.User, masterKey []byte) (string, error) {
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
	if err := ioutil.WriteFile(filename, enc, 0600); err != nil {
		return "", err
	}
	return filename, nil
}

// readEncryptedUserFile reads and decrypts a user file
func readEncryptedUserFile(path string, masterKey []byte) (*models.User, error) {
	blob, err := ioutil.ReadFile(path)
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
