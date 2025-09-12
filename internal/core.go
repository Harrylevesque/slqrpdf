package internal

import "time"

// ===== Domain Models =====

// TODO(model-devices): Introduce Device struct {DeviceID, UserID, PubHW, PubPQ, Status, CreatedAt, LastSeen, AttestationMeta}.
// TODO(model-nonces): Add Nonce struct {Value, UserID, DeviceID, ExpiresAt, UsedAt} for auth challenge tracking.
// TODO(model-audit): Add AuditEvent struct {ID, UserID, DeviceID, Type, Payload, Timestamp, PrevHash, Hash} (hash chain).
// TODO(model-session-attrs): Extend Session with fields: RefreshTokenHash, LastHeartbeat, RiskScore.
// TODO(model-recovery): Add RecoveryCode struct {Hash, IssuedAt, UsedAt}.
// TODO(model-softdelete): Add User.Status and DeletionScheduledAt for account deletion flow.
// TODO(model-token): Consider AccessToken struct (if moving away from embedding in Sessions slice).

type User struct {
	UserID   string    `json:"user_id"`
	Secrets  Secrets   `json:"secrets"`
	Sessions []Session `json:"sessions"`
	Metadata Metadata  `json:"metadata"`
}

type Secrets struct {
	SecretD   string `json:"secret_d"`
	SecretK   string `json:"secret_k"`
	LongSeed  string `json:"long_seed"`
	ShortSeed string `json:"short_seed"`
	MashSeed  string `json:"mash_seed"`
	TOTPSeed  string `json:"totp_seed"`
}

type Session struct {
	SessionID string    `json:"session_id"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Status    string    `json:"status"`
}

type Metadata struct {
	CreatedAt          time.Time `json:"created_at"`
	LastLogin          time.Time `json:"last_login"`
	DeviceFingerprints []string  `json:"device_fingerprints"`
	IPHistory          []string  `json:"ip_history"`
}

// TODO(model-validation): Add validation helpers (e.g., ValidateUser(), ValidateSession()).
// TODO(model-json): Provide custom JSON marshalling to omit sensitive fields (future when adding more secrets).
// Protocol flow, session management
