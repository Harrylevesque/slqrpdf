package models

import "time"

// User struct with secrets, sessions, and metadata
// (moved from files/user_store.go)
type User struct {
	UserID   string    `json:"user_id"`
	Secrets  Secrets   `json:"secrets"`
	Sessions []Session `json:"sessions"`
	Metadata Metadata  `json:"metadata"`
}

type Secrets struct {
	SecretD   string `json:"secret_d"`   // hex
	SecretK   string `json:"secret_k"`   // hex
	LongSeed  string `json:"long_seed"`  // hex
	ShortSeed string `json:"short_seed"` // hex
	MashSeed  string `json:"mash_seed"`  // hex
	TOTPSeed  string `json:"totp_seed"`  // base32
}

type Session struct {
	SessionID string    `json:"session_id"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Status    string    `json:"status"`
}

type Metadata struct {
	CreatedAt         time.Time `json:"created_at"`
	LastLogin         time.Time `json:"last_login"`
	DeviceFingerprint string    `json:"device_fingerprint"`
	IPHistory         []string  `json:"ip_history"`
}
