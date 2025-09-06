package api

import (
	"net/http"
	"time"
)

// GetTimeHandler returns the current server time in RFC3339 format
func GetTimeHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"time": "` + time.Now().Format(time.RFC3339) + `"}`))
}
