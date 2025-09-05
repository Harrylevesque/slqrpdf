package models

import "time"

type Session struct {
	SessionID string    `json:"session_id"`
	CreatedAt time.Time `json:"created_at"`
}

type User struct {
	UserID   string    `json:"user_id"`
	SecretD  string    `json:"secret_d"`
	SecretK  string    `json:"secret_k"`
	Sessions []Session `json:"sessions"`
}
