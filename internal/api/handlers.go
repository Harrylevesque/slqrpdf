package api

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
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

// GetTimeHandler returns the current server time in RFC3339 format
func GetTimeHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"time": "` + time.Now().Format(time.RFC3339) + `"}`))
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
	json.NewEncoder(w).Encode(user)
}

type CreateUserRequest struct {
	UserID             string   `json:"user_id"`
	DeviceFingerprints []string `json:"device_fingerprints"`
}

// CreateUserHandler creates a new user with a generated user ID and device fingerprints gathered on the server
func CreateUserHandler(w http.ResponseWriter, r *http.Request) {
	// Ignore client-supplied user_id and device_fingerprints
	userUUID := uuid.New().String()
	userID := "u--" + userUUID

	fingerprints, err := utils.GetDeviceFingerprints()
	if err != nil || len(fingerprints) == 0 {
		http.Error(w, "could not gather device fingerprints: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Generate mash seed (random 32 bytes)
	mashSeed := crypto.MustRandom(32)
	longSeed, _ := crypto.DeriveLongSeed(mashSeed)
	shortSeed := crypto.DeriveShortSeed(longSeed)
	totpSeed, _ := crypto.DeriveTOTPSeed(longSeed)
	secretD, _ := crypto.DeriveSecretD(mashSeed, fingerprints[0]) // Use first fingerprint for secretD
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
	_, err = files.WriteEncryptedUserFile(utils.GetUserDataDir(), user, masterKey)
	if err != nil {
		http.Error(w, "failed to save user", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(user)
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
		json.NewEncoder(w).Encode(map[string]interface{}{
			"device_fingerprints": []string{},
			"error":               err.Error(),
		})
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"device_fingerprints": ids,
	})
}
