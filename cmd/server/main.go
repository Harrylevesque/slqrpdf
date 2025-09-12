package main

import (
	"log"
	"net/http"
	"os"
	"slqrpdf/internal"
)

// TODO(server-startup-config): Validate config values & print effective configuration at startup (JSON-based, no DB).
// TODO(server-shutdown): Implement graceful shutdown on SIGINT/SIGTERM with context cancellation.
// TODO(server-metrics): Add /metrics endpoint (Prometheus) and basic counters (requests, errors).
// TODO(server-sec-headers): Add middleware setting security headers (Content-Security-Policy, X-Content-Type-Options, etc.).
// TODO(server-rate-limit): Add global & per-route rate limiting middleware.
// TODO(server-cors): Add configurable CORS policy (allow list of origins for GUI/mobile).
// TODO(server-logging): Introduce structured access log middleware (method,path,status,duration,ip,device_id?).
// TODO(server-recovery): Add panic recovery middleware returning 500 JSON with correlation id.
// TODO(server-health-extended): Extend /health to include dependency checks (JSON storage, key material).
// TODO(server-config-reload): Optionally watch config file for safe hot reload (non-critical fields).
// TODO(server-trace): Add request ID / trace ID injection for correlation across services.

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	r := internal.NewRouter()
	addr := ":" + port
	log.Printf("Server listening on %s", addr)
	// TODO(server-listen-tls): Support TLS (cert/key paths) via config.
	log.Fatal(http.ListenAndServe(addr, r))
}
