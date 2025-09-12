package internal

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

// ===== High-Level Implementation TODOs (API Layer) =====
// Each TODO maps to design doc sections (1-18).
// Keep tasks small & independent for incremental delivery.
// NOTE: Do not remove until implemented & tested; prefer converting to issues.

// TODO(flow-1-enroll): Add /enroll endpoint (POST) accepting pub_hw, pub_pq, attestation, client metadata; store device, user pending state.
// TODO(flow-1-attestation): Implement platform attestation verification (Android Key Attestation, Apple AppAttest) before activating device.
// TODO(flow-1-session): Issue short-lived session/refresh tokens (opaque or JWT) after successful enrollment; bind to device_id.
// TODO(flow-1-audit): Write ENROLL audit log entry (append-only) including attestation result + risk flags.

// TODO(flow-2-auth-challenge): Implement /auth/challenge to mint 32-byte nonce, persist (nonce,user_id,device_id,exp,used=false).
// TODO(flow-2-auth-verify): Implement /auth/verify to validate signatures (hw + optional pq), atomically mark nonce used, create session.
// TODO(flow-2-replay): Enforce atomic nonce use + expiration (30s TTL configurable).
// TODO(flow-2-failure): Add rate limiting + failed attempt counter & lockout thresholds.
// TODO(flow-2-audit): Log LOGIN_SUCCESS / LOGIN_FAIL with geo/ip/device diff metrics.

// TODO(flow-3-logout): Implement /session/logout to revoke active session (status=logged_out + revocation cache entry).
// TODO(flow-3-multi): Support global logout (invalidate all sessions for user) via optional flag.

// TODO(flow-4-device-add-request): Implement /device/add-request issuing ephemeral_code (128-bit) + expiry.
// TODO(flow-4-device-approve): Implement /device/approve-add (existing trusted device signs approval) → finalize new device row.
// TODO(flow-4-qr): Provide QR payload format (code + server origin + checksum) & optional encryption.
// TODO(flow-4-audit): Log DEVICE_ADD with approval device_id + new device_id.

// TODO(flow-5-device-revoke): Implement /device/revoke (strong reauth required) to set device.status=revoked + kill sessions.
// TODO(flow-5-notify): Push revocation notifications to other active devices (websocket/push - later).
// TODO(flow-5-audit): Log DEVICE_REVOKE with reason + initiating device.

// TODO(flow-6-account-delete): Implement /account/delete with grace period scheduling + irreversible purge pipeline.
// TODO(flow-6-hard-delete): Add background job to finalize deletion after grace_period, scrubbing encrypted blobs.
// TODO(flow-6-audit): Log ACCOUNT_DELETE_REQUEST + ACCOUNT_DELETE_FINAL.

// TODO(flow-7-recovery-codes): Implement recovery code issuance (N codes, hashed store) accessible via secure UI.
// TODO(flow-7-recover): Implement /recover using recovery_code -> issue recovery_token -> allow enroll new device.
// TODO(flow-7-mfa): Optionally chain email confirm + recovery code (defense-in-depth).
// TODO(flow-7-audit): Log RECOVERY_CODE_USED, include code hash id (not plaintext).

// TODO(flow-8-heartbeat): Implement /heartbeat (signed seq+timestamp) updating session liveness + detection of missed heartbeats.
// TODO(flow-8-threshold): Add policy config for heartbeat interval + grace (# consecutive misses to suspend session).
// TODO(flow-8-suspend): Auto-suspend session on heartbeat failure; require fresh auth.
// TODO(flow-8-audit): Log HEARTBEAT_MISS & HEARTBEAT_RECOVER.

// TODO(flow-9-kill): Implement privileged /kill endpoint (admin / automated) to revoke sessions/devices immediately.
// TODO(flow-9-push): Integrate realtime push (websocket) to deliver kill signal.
// TODO(flow-9-audit): Log KILL_SESSION with trigger source.

// TODO(flow-10-oauth-init): Stub endpoints to act as OAuth/OIDC provider (authorize, token) w/ PKCE & device binding.
// TODO(flow-10-dpop): Add DPoP / proof-of-possession header verification referencing device public key.
// TODO(flow-10-introspect): Implement /introspect to validate & return token metadata (internal security service).

// TODO(flow-11-refresh-rotate): Add /session/refresh rotating refresh tokens (store token_hash + previous hash chain).
// TODO(flow-11-pop): Enforce PoP on protected resource requests (verify signature per request - future middleware).
// TODO(flow-11-reauth): Add reauth requirement for sensitive scope escalation.

// TODO(flow-12-audit-log-ingest): Route all security events via single AuditLog() helper ensuring signed chain.
// TODO(flow-12-merkle): (Later) Implement Merkle / hash-chain for tamper-evident logs.

// TODO(flow-13-models): Expand persistence (devices, sessions, nonces, audit) beyond current JSON user file.
// TODO(flow-13-migrate): Provide migration util from flat JSON to structured store.

// TODO(flow-14-crypto-hybrid): Integrate hybrid signature (Ed25519 + Dilithium placeholder) abstraction.
// TODO(flow-14-config): Add crypto policy config (algorithms, key sizes, rotation intervals).

// TODO(flow-15-cache): Add in-memory revocation & nonce caches (Redis optional future) for scale.
// TODO(flow-15-batching): Batch heartbeat writes instead of per-request disk persistence.

// TODO(flow-16-ux): Provide user-friendly JSON responses with actionable remediation hints.
// TODO(flow-16-i18n): Add minimal structure to support localization.

// TODO(flow-17-doc): Generate OpenAPI spec covering all endpoints including securitySchemes.
// TODO(flow-17-ratelimit): Add rate limiting middleware (IP + user + device granularity).

// TODO(flow-18-threat-detection): Implement anomaly detection hooks (impossible travel, rapid device add attempts).
// TODO(flow-18-alerting): Integrate simple alert channel (stdout or webhook) for critical events.

// ===== Handlers =====

func GetTimeHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"time": time.Now().Format(time.RFC3339)})
}

func GetUserHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID := vars["id"]
	if userID == "" {
		http.Error(w, "missing user id", http.StatusBadRequest)
		return
	}
	masterKey, err := ReadMasterKey()
	if err != nil {
		http.Error(w, "server misconfiguration", http.StatusInternalServerError)
		return
	}
	encPath := filepath.Join(GetUserDataDir(), userID+".json.enc")
	plainPath := filepath.Join(GetUserDataDir(), userID+".json")
	var u *User
	if _, err := os.Stat(encPath); err == nil {
		u, err = ReadEncryptedUserFile(encPath, masterKey)
	} else if _, err := os.Stat(plainPath); err == nil {
		u, err = ReadUserFile(plainPath)
	} else {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "failed to load user", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(u)
}

func CreateUserHandler(w http.ResponseWriter, r *http.Request) {
	cfg := LoadConfig()
	var err error // Declare err for the whole function
	// TODO(flow-1-validation): Enforce additional enrollment validation (attestation, policy flags).
	// Require client-provided data
	var req struct {
		DeviceFingerprint string `json:"device_fingerprint"`
		SecretDHash       string `json:"secret_d_hash"`
		SecretKPublic     string `json:"secret_k_public"`
		LongSeed          string `json:"long_seed"`
		ShortSeed         string `json:"short_seed"`
		MashSeed          string `json:"mash_seed"`
		TOTPSeed          string `json:"totp_seed"`
	}
	if err = json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.DeviceFingerprint == "" {
		http.Error(w, "device_fingerprint required", http.StatusBadRequest)
		return
	}
	fingerprints := []string{req.DeviceFingerprint}

	userUUID := uuid.New().String()
	userID := "u--" + userUUID

	// Create first session
	// TODO(flow-2-session-create): Replace with POST /auth/verify issuance once challenge flow added.
	sessionUUID := uuid.New().String()
	sessionID := "s--" + sessionUUID
	now := time.Now().UTC()
	firstSession := Session{
		SessionID: sessionID,
		CreatedAt: now,
		ExpiresAt: now.Add(24 * time.Hour), // or adjust policy
		Status:    "active",
	}

	var mashSeed []byte
	if req.MashSeed != "" {
		mashSeed, err = hex.DecodeString(req.MashSeed)
		if err != nil {
			http.Error(w, "invalid mash_seed", http.StatusBadRequest)
			return
		}
	} else {
		mashSeed = MustRandom(32)
	}

	var longSeed []byte
	if req.LongSeed != "" {
		longSeed, err = hex.DecodeString(req.LongSeed)
		if err != nil {
			http.Error(w, "invalid long_seed", http.StatusBadRequest)
			return
		}
	} else {
		longSeed, err = DeriveLongSeed(mashSeed)
		if err != nil {
			http.Error(w, "derive long seed", http.StatusInternalServerError)
			return
		}
	}

	var shortSeed []byte
	if req.ShortSeed != "" {
		shortSeed, err = hex.DecodeString(req.ShortSeed)
		if err != nil {
			http.Error(w, "invalid short_seed", http.StatusBadRequest)
			return
		}
	} else {
		shortSeed = DeriveShortSeed(longSeed)
	}

	var totpSeed string
	if req.TOTPSeed != "" {
		totpSeed = req.TOTPSeed
	} else {
		totpSeed, err = DeriveTOTPSeed(longSeed)
		if err != nil {
			http.Error(w, "derive totp seed", http.StatusInternalServerError)
			return
		}
	}

	var secretD []byte
	var secretDHash string
	if req.SecretDHash != "" {
		secretDHash = req.SecretDHash // client already hashed
	} else {
		secretD, err = DeriveSecretD(mashSeed, fingerprints[0])
		if err != nil {
			http.Error(w, "derive secret d", http.StatusInternalServerError)
			return
		}
		h := sha256.Sum256(secretD)
		secretDHash = hex.EncodeToString(h[:])
	}

	var secretK []byte
	if req.SecretKPublic != "" {
		secretK, err = hex.DecodeString(req.SecretKPublic)
		if err != nil {
			http.Error(w, "invalid secret_k_public", http.StatusBadRequest)
			return
		}
	} else {
		secretK = GenerateSecretK()
	}

	now = time.Now().UTC()
	user := &User{
		UserID: userID,
		Secrets: Secrets{
			SecretD:   secretDHash,
			SecretK:   hex.EncodeToString(secretK),
			LongSeed:  hex.EncodeToString(longSeed),
			ShortSeed: hex.EncodeToString(shortSeed),
			MashSeed:  hex.EncodeToString(mashSeed),
			TOTPSeed:  totpSeed,
		},
		Sessions: []Session{firstSession},
		Metadata: Metadata{
			DeviceFingerprints: fingerprints,
			CreatedAt:          now,
			LastLogin:          now,
		},
	}

	// TODO(flow-12-audit-enroll): Record enrollment event via audit log subsystem (pending implementation).

	masterKey, err := ReadMasterKey()
	if err != nil {
		http.Error(w, "server misconfiguration", http.StatusInternalServerError)
		return
	}
	var saveErr error
	if cfg.UserFileEncryption {
		_, saveErr = WriteEncryptedUserFile(GetUserDataDir(), user, masterKey)
	} else {
		_, saveErr = WriteUserFile(GetUserDataDir(), user)
	}
	if saveErr != nil {
		http.Error(w, "failed to save user", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(user)
}

func GetDeviceIDHandler(w http.ResponseWriter, r *http.Request) {
	ids, err := GetDeviceFingerprints()
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"device_fingerprints": []string{}, "error": err.Error()})
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"device_fingerprints": ids})
}

func SetupPasskeyHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var req struct {
		UserID string `json:"user_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.UserID == "" {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}
	masterKey, err := ReadMasterKey()
	if err != nil {
		http.Error(w, `{"error":"server misconfiguration"}`, http.StatusInternalServerError)
		return
	}
	encPath := filepath.Join(GetUserDataDir(), req.UserID+".json.enc")
	plainPath := filepath.Join(GetUserDataDir(), req.UserID+".json")
	var user *User
	if _, err := os.Stat(encPath); err == nil {
		user, err = ReadEncryptedUserFile(encPath, masterKey)
	} else if _, err := os.Stat(plainPath); err == nil {
		user, err = ReadUserFile(plainPath)
	} else {
		http.Error(w, `{"error":"user not found"}`, http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, `{"error":"failed to load user"}`, http.StatusInternalServerError)
		return
	}
	// TODO(flow-10-passkey): Integrate with future WebAuthn / passkey store abstraction.
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "passkey": user.Secrets.SecretK})
}

func WebAuthnRegisterOptionsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var req struct {
		UserID string `json:"user_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.UserID == "" {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}
	masterKey, err := ReadMasterKey()
	if err != nil {
		http.Error(w, `{"error":"server misconfiguration"}`, http.StatusInternalServerError)
		return
	}
	encPath := filepath.Join(GetUserDataDir(), req.UserID+".json.enc")
	plainPath := filepath.Join(GetUserDataDir(), req.UserID+".json")
	var user *User
	if _, err := os.Stat(encPath); err == nil {
		user, err = ReadEncryptedUserFile(encPath, masterKey)
	} else if _, err := os.Stat(plainPath); err == nil {
		user, err = ReadUserFile(plainPath)
	} else {
		http.Error(w, `{"error":"user not found"}`, http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, `{"error":"failed to load user"}`, http.StatusInternalServerError)
		return
	}
	challenge := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, challenge); err != nil {
		challenge = []byte(time.Now().Format(time.RFC3339Nano))
	}
	options := map[string]interface{}{
		"challenge":        encodeBase64Url(challenge),
		"rp":               map[string]interface{}{"name": "slqrpdf-demo", "id": "localhost"},
		"user":             map[string]interface{}{"id": encodeBase64Url([]byte(user.UserID)), "name": user.UserID, "displayName": user.UserID},
		"pubKeyCredParams": []map[string]interface{}{{"type": "public-key", "alg": -7}},
		"timeout":          60000,
		"attestation":      "direct",
	}
	// TODO(flow-10-webauthn): Persist challenge + origin binding for later verify step.
	fmt.Println("[WebAuthn] rp.id: localhost, request Host:", r.Host)
	json.NewEncoder(w).Encode(options)
}

func WebAuthnRegisterVerifyHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var req struct {
		UserID      string      `json:"user_id"`
		Attestation interface{} `json:"attestation"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.UserID == "" {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}
	// TODO(flow-10-webauthn-verify): Verify attestation object, register credential public key, link to device.
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// TODO(flow-11-middleware): Add auth middleware verifying session tokens & revocation before protected handlers.
// TODO(flow-17-openapi): Auto-generate swagger docs from route registrations.

// ===== Router =====

func NewRouter() *mux.Router {
	r := mux.NewRouter()
	indexPath := filepath.Join(GetProjectRoot(), "internal", "mobile", "static", "index.html")
	r.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("OK")) }).Methods("GET")
	// TODO(flow-2-route): Split user retrieval from login semantics; consider /users/{id} pure read.
	r.HandleFunc("/time", GetTimeHandler).Methods("GET")
	r.HandleFunc("/users/login/{id}", GetUserHandler).Methods("GET")
	r.HandleFunc("/users/create", CreateUserHandler).Methods("POST")
	// TODO(flow-1-route-enroll): Replace /users/create with /enroll (backward compat alias) once device model added.
	r.HandleFunc("/users/passkey/setup", SetupPasskeyHandler).Methods("POST")
	// TODO(flow-2-new): Add /auth/challenge, /auth/verify routes.
	// TODO(flow-3-new): Add /session/logout route.
	// TODO(flow-4-new): Add /device/add-request & /device/approve-add routes.
	// TODO(flow-5-new): Add /device/revoke route.
	// TODO(flow-6-new): Add /account/delete route.
	// TODO(flow-7-new): Add /recover route.
	// TODO(flow-8-new): Add /heartbeat route.
	// TODO(flow-9-new): Add /kill route (admin protected).
	// TODO(flow-10-new): Add /oauth/authorize & /oauth/token routes.
	// TODO(flow-11-new): Add /session/refresh route.
	// TODO(flow-10-introspect-route): Add /introspect route (internal only).
	r.HandleFunc("/deviceid", GetDeviceIDHandler).Methods("GET")
	r.HandleFunc("/webauthn/register/options", WebAuthnRegisterOptionsHandler).Methods("POST")
	r.HandleFunc("/webauthn/register/verify", WebAuthnRegisterVerifyHandler).Methods("POST")
	// index
	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { http.ServeFile(w, r, indexPath) }).Methods("GET")
	r.HandleFunc("/index.html", func(w http.ResponseWriter, r *http.Request) { http.ServeFile(w, r, indexPath) }).Methods("GET")
	// static fallback
	r.PathPrefix("/").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" || r.URL.Path == "/index.html" {
			http.NotFound(w, r)
			return
		}
		http.FileServer(http.Dir(filepath.Dir(indexPath))).ServeHTTP(w, r)
	})
	return r
}

// ===== Helpers =====

func encodeBase64Url(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	s := base64.StdEncoding.EncodeToString(b)
	s = strings.ReplaceAll(s, "+", "-")
	s = strings.ReplaceAll(s, "/", "_")
	return strings.TrimRight(s, "=")
}
