package internal

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Logging, hashing, misc helpers
// TODO(utils-hashchain): Implement hash chaining helper (prevHash + event -> newHash) for audit log integrity.
// TODO(utils-merkle): Provide optional Merkle tree builder for batched audit proofs (future optimization).
// TODO(utils-rate-limit): Add in-memory rate limiter (token bucket) keyed by IP + user + device.
// TODO(utils-risk-score): Add simple risk scoring function (ip_distance, new_device, geo_anomaly) -> float.
// TODO(utils-geoip): Stub GeoIP lookup (config flag) returning country + region.
// TODO(utils-time-skew): Add time skew validation helper for heartbeat & challenge timestamps.
// TODO(utils-zeroize): Add Zeroize([]byte) to securely wipe slices after use.
// TODO(utils-idgen): Centralize ID generation (prefix + uuid) ensuring uniqueness & future monotonic option.
// TODO(utils-config-reload): Implement optional SIGHUP config reload (later if needed).
// TODO(utils-validate-fp): Add heuristic validation for device fingerprint formats.
// TODO(utils-env): Add EnvOrDefault helpers to standardize environment variable reads.
// TODO(utils-logging-context): Provide context-aware logging (trace/session/device IDs) for correlation.
// TODO(utils-math-clamp): Add small math helpers (Clamp, MinDuration) for policy normalization.

// ===== Paths =====

func GetProjectRoot() string {
	dir, err := os.Getwd()
	if err != nil {
		return "."
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "."
		}
		dir = parent
	}
}

func GetUserDataDir() string { return filepath.Join(GetProjectRoot(), "encrypted_data", "users") }

// ===== Device Fingerprints =====
// TODO(utils-device-attestation): Add platform-specific attestation invocation helpers (Android/iOS) once integrated.
// TODO(utils-root-detect): Provide basic root/jailbreak detection stubs (non-fatal flags).

func GetDeviceFingerprints() ([]string, error) {
	switch runtime.GOOS {
	case "darwin":
		return getMacOSUUID()
	case "linux":
		return getLinuxUUID()
	case "windows":
		return getWindowsUUID()
	default:
		return nil, errors.New("unsupported platform: " + runtime.GOOS)
	}
}

func getMacOSUUID() ([]string, error) {
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
	if len(ids) == 0 {
		return nil, errors.New("no IOPlatformUUID found")
	}
	return ids, nil
}

func getLinuxUUID() ([]string, error) {
	out, err := exec.Command("cat", "/sys/class/dmi/id/product_uuid").Output()
	if err == nil {
		id := strings.TrimSpace(string(out))
		if id != "" {
			return []string{id}, nil
		}
	}
	cpuinfo, err := exec.Command("cat", "/proc/cpuinfo").Output()
	if err == nil {
		lines := strings.Split(string(cpuinfo), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "Serial") {
				parts := strings.Split(line, ":")
				if len(parts) == 2 {
					id := strings.TrimSpace(parts[1])
					if id != "" {
						return []string{id}, nil
					}
				}
			}
		}
	}
	return nil, errors.New("no hardware UUID found on Linux")
}

func getWindowsUUID() ([]string, error) {
	cmd := exec.Command("wmic", "csproduct", "get", "UUID")
	out, err := cmd.Output()
	if err == nil {
		lines := bytes.Split(out, []byte("\n"))
		for _, line := range lines {
			s := strings.TrimSpace(string(line))
			if s != "" && !strings.EqualFold(s, "UUID") {
				return []string{s}, nil
			}
		}
	}
	cmd = exec.Command("wmic", "cpu", "get", "ProcessorId")
	out, err = cmd.Output()
	if err == nil {
		lines := bytes.Split(out, []byte("\n"))
		for _, line := range lines {
			s := strings.TrimSpace(string(line))
			if s != "" && !strings.EqualFold(s, "ProcessorId") {
				return []string{s}, nil
			}
		}
	}
	return nil, errors.New("no hardware UUID found on Windows")
}

// ===== Logger =====
// TODO(utils-logger-structured): Replace plain text with structured JSON logs (level,time,msg,fields...).
// TODO(utils-logger-levels): Add dynamic log level control (env + runtime toggle).
// TODO(utils-logger-redact): Redact sensitive fields before log output.
// TODO(utils-logger-metrics): Emit counters for key events (login_success, login_fail, heartbeat_miss).

type Logger struct {
	file   *os.File
	logger *log.Logger
}

func NewLogger(path string) (*Logger, error) {
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		return nil, fmt.Errorf("open log: %w", err)
	}
	return &Logger{file: file, logger: log.New(file, "", log.LstdFlags)}, nil
}

func (l *Logger) Info(msg string)  { l.logger.SetPrefix("INFO: "); l.logger.Println(msg) }
func (l *Logger) Warn(msg string)  { l.logger.SetPrefix("WARN: "); l.logger.Println(msg) }
func (l *Logger) Error(msg string) { l.logger.SetPrefix("ERROR: "); l.logger.Println(msg) }
func (l *Logger) Close() {
	if l.file != nil {
		_ = l.file.Close()
	}
}

func (l *Logger) RotateDaily() {
	for {
		now := time.Now()
		next := now.Add(24 * time.Hour)
		time.Sleep(next.Sub(now))
		l.Close()
		file, err := os.OpenFile(l.file.Name(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
		if err != nil {
			fmt.Printf("log rotate failed: %v\n", err)
			return
		}
		l.file = file
		l.logger.SetOutput(file)
	}
}
