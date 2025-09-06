package api

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
)

func NewRouter() *mux.Router {
	r := mux.NewRouter()
	r.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if _, err := fmt.Fprintln(w, "OK"); err != nil {
			// Optionally log the error
		}
	}).Methods("GET")
	r.HandleFunc("/time", GetTimeHandler).Methods("GET")
	return r
}
