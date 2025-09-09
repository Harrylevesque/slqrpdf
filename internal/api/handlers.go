package api

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/harrylevesque/slqrpdf/internal/crypto"
	"github.com/harrylevesque/slqrpdf/internal/files"
	"github.com/harrylevesque/slqrpdf/internal/models"
	"github.com/harrylevesque/slqrpdf/internal/utils"
)

// Toggle for enabling encryption based on environment variable
var enableEncryption = os.Getenv("ENABLE_ENCRYPTION") == "false"

// GetTimeHandler returns the current server time in RFC3339 format
func GetTimeHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte(`{"time": "` + time.Now().Format(time.RFC3339) + `"}`)); err != nil {
		// Optionally log the error
	}
}

// GetUserHandler returns the decrypted user JSON for a given user ID
func GetUserHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID := vars["id"]
	if userID == "" {
		http.Error(w, "missing user id", http.StatusBadRequest)
		return
	}
	masterKey, err := files.ReadMasterKey()
	if err != nil {
		http.Error(w, "server misconfiguration", http.StatusInternalServerError)
		return
	}
	userPath := filepath.Join(utils.GetUserDataDir(), userID+".json.enc")
	user, err := files.ReadEncryptedUserFile(userPath, masterKey)
	if err != nil {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(user); err != nil {
		// Optionally log the error
	}
}

type CreateUserRequest struct {
	UserID             string   `json:"user_id"`
	DeviceFingerprints []string `json:"device_fingerprints"`
}

// CreateUserHandler creates a new user with a generated user ID and device fingerprints gathered on the server
func CreateUserHandler(w http.ResponseWriter, r *http.Request) {
	userUUID := uuid.New().String()
	userID := "u--" + userUUID

	fingerprints, err := utils.GetDeviceFingerprints()
	if err != nil || len(fingerprints) == 0 {
		http.Error(w, "could not gather device fingerprints: "+err.Error(), http.StatusInternalServerError)
		return
	}

	mashSeed := crypto.MustRandom(32)
	longSeed, err := crypto.DeriveLongSeed(mashSeed)
	if err != nil {
		http.Error(w, "failed to derive long seed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	shortSeed := crypto.DeriveShortSeed(longSeed)
	totpSeed, err := crypto.DeriveTOTPSeed(longSeed)
	if err != nil {
		http.Error(w, "failed to derive TOTP seed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	secretD, err := crypto.DeriveSecretD(mashSeed, fingerprints[0])
	if err != nil {
		http.Error(w, "failed to derive secret D: "+err.Error(), http.StatusInternalServerError)
		return
	}
	secretK := crypto.GenerateSecretK()

	user := &models.User{
		UserID: userID,
		Secrets: models.Secrets{
			SecretD:   hex.EncodeToString(secretD),
			SecretK:   hex.EncodeToString(secretK),
			LongSeed:  hex.EncodeToString(longSeed),
			ShortSeed: hex.EncodeToString(shortSeed),
			MashSeed:  hex.EncodeToString(mashSeed),
			TOTPSeed:  totpSeed,
		},
		Metadata: models.Metadata{
			DeviceFingerprints: fingerprints,
			CreatedAt:          time.Now().UTC(),
			LastLogin:          time.Now().UTC(),
		},
	}

	masterKey, err := files.ReadMasterKey()
	if err != nil {
		http.Error(w, "server misconfiguration", http.StatusInternalServerError)
		return
	}
	if enableEncryption {
		_, err = files.WriteEncryptedUserFile(utils.GetUserDataDir(), user, masterKey)
	} else {
		_, err = files.WriteUserFile(utils.GetUserDataDir(), user)
	}
	if err != nil {
		http.Error(w, "failed to save user", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(user); err != nil {
		// Optionally log the error
	}
}

// GetCPUFingerprints returns a slice of CPU IDs (hardware UUIDs) on macOS
func GetCPUFingerprints() ([]string, error) {
	cmd := exec.Command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(out), "\n")
	var ids []string
	for _, line := range lines {
		if strings.Contains(line, "IOPlatformUUID") {
			parts := strings.Split(line, "\"")
			if len(parts) >= 4 {
				ids = append(ids, parts[3])
			}
		}
	}
	return ids, nil
}

// GetDeviceIDHandler returns the device fingerprints as JSON
func GetDeviceIDHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	ids, err := utils.GetDeviceFingerprints()
	if err != nil || len(ids) == 0 {
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"device_fingerprints": []string{},
			"error":               err.Error(),
		}); err != nil {
			// Optionally log the error
		}
		return
	}
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"device_fingerprints": ids,
	}); err != nil {
		// Optionally log the error
	}
}

// SetupPasskeyHandler sets up a user's passkey using their SecretK as the key
func SetupPasskeyHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var req struct {
		UserID string `json:"user_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.UserID == "" {
		http.Error(w, `{"error": "invalid request"}`, http.StatusBadRequest)
		return
	}

	masterKey, err := files.ReadMasterKey()
	if err != nil {
		http.Error(w, `{"error": "server misconfiguration"}`, http.StatusInternalServerError)
		return
	}

	// Try both encrypted and unencrypted user files
	userPathEnc := filepath.Join(utils.GetUserDataDir(), req.UserID+".json.enc")
	userPathPlain := filepath.Join(utils.GetUserDataDir(), req.UserID+".json")
	var user *models.User
	if _, err := os.Stat(userPathEnc); err == nil {
		user, err = files.ReadEncryptedUserFile(userPathEnc, masterKey)
	} else if _, err := os.Stat(userPathPlain); err == nil {
		user, err = files.ReadUserFile(userPathPlain)
	} else {
		http.Error(w, `{"error": "user not found"}`, http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, `{"error": "failed to load user"}`, http.StatusInternalServerError)
		return
	}

	// For demonstration, return SecretK as the passkey (in real use, never return secrets!)
	resp := map[string]string{
		"status":  "ok",
		"passkey": user.Secrets.SecretK,
	}
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		// Optionally log the error
	}
}

// WebAuthnRegisterOptionsHandler returns PublicKeyCredentialCreationOptions for passkey registration
func WebAuthnRegisterOptionsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var req struct {
		UserID string `json:"user_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.UserID == "" {
		http.Error(w, `{"error": "invalid request"}`, http.StatusBadRequest)
		return
	}
	// For demo: load user, use user_id and SecretK as user.id and user.displayName
	masterKey, err := files.ReadMasterKey()
	if err != nil {
		http.Error(w, `{"error": "server misconfiguration"}`, http.StatusInternalServerError)
		return
	}
	userPathEnc := filepath.Join(utils.GetUserDataDir(), req.UserID+".json.enc")
	userPathPlain := filepath.Join(utils.GetUserDataDir(), req.UserID+".json")
	var user *models.User
	if _, err := os.Stat(userPathEnc); err == nil {
		user, err = files.ReadEncryptedUserFile(userPathEnc, masterKey)
	} else if _, err := os.Stat(userPathPlain); err == nil {
		user, err = files.ReadUserFile(userPathPlain)
	} else {
		http.Error(w, `{"error": "user not found"}`, http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, `{"error": "failed to load user"}`, http.StatusInternalServerError)
		return
	}
	// Generate a random challenge
	challenge := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, challenge); err != nil {
		// fallback to time-based challenge for demo
		challenge = []byte(time.Now().Format(time.RFC3339Nano))
	}
	// Build PublicKeyCredentialCreationOptions
	options := map[string]interface{}{
		"challenge":        encodeBase64Url(challenge),
		"rp":               map[string]interface{}{"name": "slqrpdf-demo", "id": "localhost"},
		"user":             map[string]interface{}{"id": encodeBase64Url([]byte(user.UserID)), "name": user.UserID, "displayName": user.UserID},
		"pubKeyCredParams": []map[string]interface{}{{"type": "public-key", "alg": -7}},
		"timeout":          60000,
		"attestation":      "direct",
	}
	// Log rp.id and request Host for debugging WebAuthn issues
	logMsg := "[WebAuthn] rp.id: localhost, request Host: " + r.Host
	println(logMsg)

	json.NewEncoder(w).Encode(options)
}

// WebAuthnRegisterVerifyHandler accepts attestation and returns success (demo only)
func WebAuthnRegisterVerifyHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var req struct {
		UserID      string      `json:"user_id"`
		Attestation interface{} `json:"attestation"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.UserID == "" {
		http.Error(w, `{"error": "invalid request"}`, http.StatusBadRequest)
		return
	}
	// For demo: just return success
	json.NewEncoder(w).Encode(map[string]string{
		"status": "ok",
	})
}

// Helper: encode base64url (no padding)
func encodeBase64Url(b []byte) string {
	s := ""
	if len(b) > 0 {
		s = strings.TrimRight(strings.ReplaceAll(strings.ReplaceAll(
			base64.StdEncoding.EncodeToString(b), "+", "-"), "/", "_"), "=")
	}
	return s
}
