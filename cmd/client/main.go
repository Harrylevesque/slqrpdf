package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"slqrpdf/internal"
)

// ===== Client Roadmap TODOs =====
// TODO(client-auth-challenge): Implement login via /auth/challenge + /auth/verify instead of direct /users/login.
// TODO(client-token-store): Securely persist session & refresh tokens (keychain / encrypted file) with rotation.
// TODO(client-local-encrypt): Encrypt local secret file with OS keystore derived key.
// TODO(client-passkey): Replace placeholder secretK generation with proper keypair + hardware binding.
// TODO(client-recovery): Add subcommand to generate & display recovery codes (store hashed remote).
// TODO(client-device-add): Implement device add flow (request QR, scan/enter ephemeral code, approve).
// TODO(client-device-revoke): Subcommand to revoke a device by id (strong reauth required).
// TODO(client-logout): Implement session logout (single/all) calling /session/logout.
// TODO(client-refresh): Add automatic refresh token rotation before expiry.
// TODO(client-config): Support config file (~/.slqrpdf/config.json) overriding server & timeouts.
// TODO(client-rate-limit-backoff): Detect 429 responses & backoff with jitter.
// TODO(client-audit-local): Maintain minimal local audit trail (JSONL) of critical operations.
// TODO(client-secure-wipe): Securely wipe sensitive byte slices after use.
// TODO(client-progress): Provide progress output with --quiet flag to suppress.
// TODO(client-json-output): Support --json flag for machine-readable output.
// TODO(client-error-map): Map server error codes to friendly messages.
// TODO(client-test): Add unit tests for seed derivation + command parsing.

// Default server base URL; can override with SLQRPDF_SERVER env var or --server flag.
var serverBaseURL = "http://localhost:8081"

func main() {
	cmd := flag.String("cmd", "create", "Command: create|get|show-local")
	userID := flag.String("id", "", "User ID (for get/show-local)")
	serverFlag := flag.String("server", "", "Override server base URL (e.g. https://api.example.com)")
	flag.Parse()
	if env := os.Getenv("SLQRPDF_SERVER"); env != "" {
		serverBaseURL = strings.TrimRight(env, "/")
	}
	if *serverFlag != "" {
		serverBaseURL = strings.TrimRight(*serverFlag, "/")
	}

	switch *cmd {
	case "create":
		if err := createUserFlow(); err != nil {
			fmt.Println("Error:", err)
			os.Exit(1)
		}
	case "get":
		if *userID == "" {
			fmt.Println("--id required")
			os.Exit(1)
		}
		if err := getUserRemote(*userID); err != nil {
			fmt.Println("Error:", err)
			os.Exit(1)
		}
	case "show-local":
		if *userID == "" {
			fmt.Println("--id required")
			os.Exit(1)
		}
		if err := showLocal(*userID); err != nil {
			fmt.Println("Error:", err)
			os.Exit(1)
		}
	default:
		fmt.Println("Unknown command")
		os.Exit(1)
	}
}

// ====== User Creation Flow (Client-Side) ======

type localSecrets struct {
	UserID            string    `json:"user_id"`
	SecretD           string    `json:"secret_d"`      // raw hex (device only)
	SecretDHash       string    `json:"secret_d_hash"` // sha256(secret_d)
	SecretKPrivate    string    `json:"secret_k_private"`
	SecretKPublic     string    `json:"secret_k_public"`
	LongSeed          string    `json:"long_seed"`
	ShortSeed         string    `json:"short_seed"`
	MashSeed          string    `json:"mash_seed"`
	TOTPSeed          string    `json:"totp_seed"`
	DeviceFingerprint string    `json:"device_fingerprint"`
	CreatedAt         time.Time `json:"created_at"`
}

func createUserFlow() error {
	fmt.Println("[1] Gathering device fingerprint...")
	fps, err := internal.GetDeviceFingerprints()
	if err != nil || len(fps) == 0 {
		return fmt.Errorf("device fingerprint: %w", err)
	}
	deviceFP := fps[0]

	fmt.Println("[2] Generating seeds & secrets locally...")
	mashSeed := internal.MustRandom(32)
	longSeed, err := internal.DeriveLongSeed(mashSeed)
	if err != nil {
		return fmt.Errorf("derive long seed: %w", err)
	}
	shortSeed := internal.DeriveShortSeed(longSeed)
	totpSeed, err := internal.DeriveTOTPSeed(longSeed)
	if err != nil {
		return fmt.Errorf("derive totp seed: %w", err)
	}
	secretD, err := internal.DeriveSecretD(mashSeed, deviceFP)
	if err != nil {
		return fmt.Errorf("derive secretD: %w", err)
	}
	h := sha256.Sum256(secretD)
	secretDHash := hex.EncodeToString(h[:])
	// Placeholder keypair: generate separate public/private random values.
	secretKPrivate := internal.GenerateSecretK()
	secretKPublic := internal.GenerateSecretK()

	payload := map[string]string{
		"device_fingerprint": deviceFP,
		"secret_d_hash":      secretDHash,
		"secret_k_public":    hex.EncodeToString(secretKPublic),
		"long_seed":          hex.EncodeToString(longSeed),
		"short_seed":         hex.EncodeToString(shortSeed),
		"mash_seed":          hex.EncodeToString(mashSeed),
		"totp_seed":          totpSeed,
	}

	fmt.Println("[3] Sending create request to server", serverBaseURL)
	body, status, err := postJSON(serverBaseURL+"/users/create", payload)
	if err != nil {
		return fmt.Errorf("post create: %w", err)
	}
	if status != http.StatusCreated {
		return fmt.Errorf("server returned status %d: %s", status, string(body))
	}

	var user internal.User
	if err := json.Unmarshal(body, &user); err != nil {
		return fmt.Errorf("decode server response: %w", err)
	}
	fmt.Println("[4] User created:", user.UserID)

	ls := localSecrets{
		UserID:            user.UserID,
		SecretD:           hex.EncodeToString(secretD),
		SecretDHash:       secretDHash,
		SecretKPrivate:    hex.EncodeToString(secretKPrivate),
		SecretKPublic:     hex.EncodeToString(secretKPublic),
		LongSeed:          hex.EncodeToString(longSeed),
		ShortSeed:         hex.EncodeToString(shortSeed),
		MashSeed:          hex.EncodeToString(mashSeed),
		TOTPSeed:          totpSeed,
		DeviceFingerprint: deviceFP,
		CreatedAt:         time.Now().UTC(),
	}
	if err := saveLocalSecrets(ls); err != nil {
		return fmt.Errorf("save local secrets: %w", err)
	}
	fmt.Println("[5] Local secrets stored.")

	return nil
}

// ===== Helpers =====

func postJSON(url string, payload any) ([]byte, int, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, 0, err
	}
	resp, err := http.Post(url, "application/json", strings.NewReader(string(data)))
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return b, resp.StatusCode, nil
}

func saveLocalSecrets(ls localSecrets) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	dir := filepath.Join(home, ".slqrpdf", "users")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	path := filepath.Join(dir, ls.UserID+".local.json")
	data, err := json.MarshalIndent(ls, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func loadLocalSecrets(userID string) (*localSecrets, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(home, ".slqrpdf", "users", userID+".local.json")
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var ls localSecrets
	if err := json.Unmarshal(b, &ls); err != nil {
		return nil, err
	}
	return &ls, nil
}

func getUserRemote(id string) error {
	url := fmt.Sprintf("%s/users/login/%s", serverBaseURL, id)
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("status %d: %s", resp.StatusCode, string(body))
	}
	io.Copy(os.Stdout, resp.Body)
	return nil
}

func showLocal(id string) error {
	ls, err := loadLocalSecrets(id)
	if err != nil {
		return err
	}
	enc, _ := json.MarshalIndent(ls, "", "  ")
	fmt.Println(string(enc))
	return nil
}

// Guard to ensure we compiled against expected internal functions
func _sanity() {
	var _ = internal.MustRandom
	var _ = internal.DeriveLongSeed
	var _ = internal.DeriveSecretD
}

// ===== Potential future: challenge login flow (not yet implemented) =====

var ErrNotImplemented = errors.New("not implemented")
