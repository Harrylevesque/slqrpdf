package utils

import (
	"os"
	"path/filepath"
)

// GetProjectRoot returns the absolute path to the project root directory.
func GetProjectRoot() string {
	// Assumes this file is always in internal/utils/ relative to the project root
	dir, err := os.Getwd()
	if err != nil {
		return "." // fallback
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break // reached root
		}
		dir = parent
	}
	return "." // fallback
}

// GetUserDataDir returns the absolute path to encrypted_data/users under the project root.
func GetUserDataDir() string {
	return filepath.Join(GetProjectRoot(), "encrypted_data", "users")
}
