package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"slqrpdf/internal"
	"strings"
	"time"
)

// TODO(guiclient-webauthn-real): Integrate real WebAuthn library (navigator.credentials.* in JS layer) and backend verify.
// TODO(guiclient-session-store): Store issued session tokens in HttpOnly cookies with CSRF protection.
// TODO(guiclient-csrf): Add CSRF token endpoint & middleware (double submit or same-site strategy).
// TODO(guiclient-device-list): Fetch and render device list (pending device model endpoint).
// TODO(guiclient-logout): Implement logout button calling /session/logout.
// TODO(guiclient-refresh): Silent refresh of access token before expiry.
// TODO(guiclient-error-banner): Standardize error banner component fed by JSON error codes.
// TODO(guiclient-i18n): Add lightweight translation map with data-* attributes for dynamic text replacement.
// TODO(guiclient-security-headers): Ensure index.html includes CSP & other headers (server side middleware too).
// TODO(guiclient-metrics): Emit frontend performance metrics (ttfb, webauthn latency) to an internal endpoint.
// TODO(guiclient-accessibility): Add keyboard focus management & aria-live regions for status updates.
// TODO(guiclient-theme): Support dark/light theme toggle stored in localStorage.
// TODO(guiclient-crypto): Offload hashing / key generation to WebCrypto where available.
// TODO(guiclient-recovery): UI for recovery code entry & submission.
// TODO(guiclient-qrcode): Render QR for device add and scan via getUserMedia.

type PasskeyResp struct {
	Passkey string `json:"passkey,omitempty"`
	Error   string `json:"error,omitempty"`
}

func main() {
	mux := http.NewServeMux()
	guiDir := filepath.Join("internal", "mobile", "gui")
	mux.Handle("/", http.FileServer(http.Dir(guiDir)))
	mux.HandleFunc("/api/create_account", handleCreateAccount)
	mux.HandleFunc("/api/webauthn/register/options", handleWebAuthnRegisterOptions)
	mux.HandleFunc("/api/webauthn/register/verify", handleWebAuthnRegisterVerify)

	addr := ":8081"
	fmt.Println("[GUI] Serving at http://localhost" + addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func handleCreateAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	// Generate secrets (simulate passkey)
	fps, err := internal.GetDeviceFingerprints()
	if err != nil || len(fps) == 0 {
		json.NewEncoder(w).Encode(PasskeyResp{Error: "Could not get device fingerprint"})
		return
	}
	deviceFP := fps[0]
	mashSeed := internal.MustRandom(32)
	longSeed, err := internal.DeriveLongSeed(mashSeed)
	if err != nil {
		json.NewEncoder(w).Encode(PasskeyResp{Error: "Seed error"})
		return
	}
	shortSeed := internal.DeriveShortSeed(longSeed)
	totpSeed, err := internal.DeriveTOTPSeed(longSeed)
	if err != nil {
		json.NewEncoder(w).Encode(PasskeyResp{Error: "TOTP error"})
		return
	}
	secretD, err := internal.DeriveSecretD(mashSeed, deviceFP)
	if err != nil {
		json.NewEncoder(w).Encode(PasskeyResp{Error: "SecretD error"})
		return
	}
	secretK := internal.GenerateSecretK()
	passkey := fmt.Sprintf("%x", secretK)
	// Store locally (simple demo: write to .slqrpdf-gui.json in home)
	home, _ := os.UserHomeDir()
	localPath := filepath.Join(home, ".slqrpdf-gui.json")
	local := map[string]any{
		"created_at":         time.Now().UTC(),
		"device_fingerprint": deviceFP,
		"mash_seed":          fmt.Sprintf("%x", mashSeed),
		"long_seed":          fmt.Sprintf("%x", longSeed),
		"short_seed":         fmt.Sprintf("%x", shortSeed),
		"totp_seed":          totpSeed,
		"secret_d":           fmt.Sprintf("%x", secretD),
		"secret_k":           passkey,
	}
	_ = os.WriteFile(localPath, mustJSON(local), 0600)
	// TODO(guiclient-enroll-post): POST public enrollment data to backend once /enroll endpoint available.
	json.NewEncoder(w).Encode(PasskeyResp{Passkey: passkey})
}

// WebAuthn registration options endpoint
func handleWebAuthnRegisterOptions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var req struct {
		UserID string `json:"user_id"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req) // user_id is optional for demo
	challenge := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, challenge); err != nil {
		for i := range challenge {
			challenge[i] = byte(65 + i%26)
		}
	}
	options := map[string]any{
		"challenge":        base64url(challenge),
		"rp":               map[string]any{"name": "slqrpdf-gui", "id": "localhost"},
		"user":             map[string]any{"id": base64url([]byte("demo-user")), "name": "demo-user", "displayName": "Demo User"},
		"pubKeyCredParams": []map[string]any{{"type": "public-key", "alg": -7}},
		"timeout":          60000,
		"attestation":      "direct",
	}
	// TODO(guiclient-webauthn-store-challenge): Persist challenge (JS local state) to verify at /verify.
	json.NewEncoder(w).Encode(options)
}

// WebAuthn registration verify endpoint
func handleWebAuthnRegisterVerify(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var req map[string]any
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid request"})
		return
	}
	// TODO(guiclient-webauthn-verify): Forward attestation to backend verification when implemented.
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func base64url(b []byte) string {
	s := base64.StdEncoding.EncodeToString(b)
	s = strings.ReplaceAll(s, "+", "-")
	s = strings.ReplaceAll(s, "/", "_")
	return strings.TrimRight(s, "=")
}

func mustJSON(v any) []byte {
	b, _ := json.MarshalIndent(v, "", "  ")
	return b
}
