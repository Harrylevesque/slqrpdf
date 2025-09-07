package utils

import (
	"bytes"
	"errors"
	"os/exec"
	"runtime"
	"strings"
)

// GetDeviceFingerprints returns a slice of unique device IDs (CPU/hardware UUIDs) for the current device.
// On mobile/web platforms, this should be provided by the client app.
func GetDeviceFingerprints() ([]string, error) {
	osName := runtime.GOOS
	switch osName {
	case "darwin":
		// macOS/iOS
		return getMacOSUUID()
	case "linux":
		return getLinuxUUID()
	case "windows":
		return getWindowsUUID()
	case "android":
		// Not available from Go; must be provided by the app
		return nil, errors.New("Android: must provide ANDROID_ID from app")
	case "ios":
		// Not available from Go; must be provided by the app
		return nil, errors.New("iOS: must provide identifierForVendor from app")
	case "chromeos":
		// Not available from Go; must be provided by the app/browser
		return nil, errors.New("ChromeOS: must provide VPD or unique ID from app/browser")
	default:
		return nil, errors.New("unsupported platform: " + osName)
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
	// Try /sys/class/dmi/id/product_uuid
	out, err := exec.Command("cat", "/sys/class/dmi/id/product_uuid").Output()
	if err == nil {
		id := strings.TrimSpace(string(out))
		if id != "" {
			return []string{id}, nil
		}
	}
	// Try /proc/cpuinfo for Serial
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
	// Try wmic csproduct get UUID
	cmd := exec.Command("wmic", "csproduct", "get", "UUID")
	out, err := cmd.Output()
	if err == nil {
		lines := bytes.Split(out, []byte("\n"))
		for _, line := range lines {
			str := strings.TrimSpace(string(line))
			if str != "" && !strings.EqualFold(str, "UUID") {
				return []string{str}, nil
			}
		}
	}
	// Try wmic cpu get ProcessorId
	cmd = exec.Command("wmic", "cpu", "get", "ProcessorId")
	out, err = cmd.Output()
	if err == nil {
		lines := bytes.Split(out, []byte("\n"))
		for _, line := range lines {
			str := strings.TrimSpace(string(line))
			if str != "" && !strings.EqualFold(str, "ProcessorId") {
				return []string{str}, nil
			}
		}
	}
	return nil, errors.New("no hardware UUID found on Windows")
}
