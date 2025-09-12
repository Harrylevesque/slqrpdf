package internal

import (
	"encoding/json"
	"os"
	"sync"
)

// EncryptionConfig holds the configuration for encryption settings.
// TODO(config-expand): Add fields for heartbeatInterval, sessionTTL, refreshTTL, nonceTTL, deletionGracePeriod.
// TODO(config-crypto-policy): Add algorithm selections (sigAlgo, aeadAlgo, enablePQC) with sane defaults.
// TODO(config-rate-limit): Introduce rate limit settings (authPerMinute, enrollPerHour, recoverPerHour).
// TODO(config-recovery): Add recovery options toggles (enableRecoveryCodes, enableEmailFallback).
// TODO(config-log): Add audit log path & enableHashChain flag.
// TODO(config-hot-reload): Support optional hot reload (SIGHUP) for non-critical parameters.
// TODO(config-validation): Implement Validate() to sanitize & clamp values.
// TODO(config-env-override): Allow environment variable overrides for CI / prod deployment.
// TODO(config-secret-management): Integrate external secret source (KMS/HSM identifiers) for master key referencing.
type EncryptionConfig struct {
	UserFileEncryption bool `json:"userFileEncryption"`
	QREncryption       bool `json:"qrEncryption"`
	KeyEncryption      bool `json:"keyEncryption"`
}

var (
	config     EncryptionConfig
	configOnce sync.Once
)

// LoadConfig reads config.json and populates the EncryptionConfig struct.
func LoadConfig() EncryptionConfig {
	configOnce.Do(func() {
		f, err := os.Open("config.json")
		if err != nil {
			// Default: all encryption ON
			config = EncryptionConfig{true, true, true}
			return
		}
		defer f.Close()
		dec := json.NewDecoder(f)
		if err := dec.Decode(&config); err != nil {
			config = EncryptionConfig{true, true, true}
		}
		// Fill missing fields with true
		if !fieldPresent("userFileEncryption") {
			config.UserFileEncryption = true
		}
		if !fieldPresent("qrEncryption") {
			config.QREncryption = true
		}
		if !fieldPresent("keyEncryption") {
			config.KeyEncryption = true
		}
	})
	return config
}

// fieldPresent checks if a field is present in config.json
func fieldPresent(field string) bool {
	f, err := os.Open("config.json")
	if err != nil {
		return false
	}
	defer f.Close()
	var m map[string]interface{}
	if err := json.NewDecoder(f).Decode(&m); err != nil {
		return false
	}
	_, ok := m[field]
	return ok
}
