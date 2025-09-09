package api

import (
	"fmt"
	"net/http"
	"path/filepath"

	"github.com/gorilla/mux"
	"github.com/harrylevesque/slqrpdf/internal/utils"
)

func NewRouter() *mux.Router {
	r := mux.NewRouter()
	indexPath := filepath.Join(utils.GetProjectRoot(), "index.html")
	r.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if _, err := fmt.Fprintln(w, "OK"); err != nil {
			// Optionally log the error
		}
	}).Methods("GET")
	r.HandleFunc("/time", GetTimeHandler).Methods("GET")
	r.HandleFunc("/users/login/{id}", GetUserHandler).Methods("GET")
	r.HandleFunc("/users/create", CreateUserHandler).Methods("POST")
	r.HandleFunc("/users/passkey/setup", SetupPasskeyHandler).Methods("POST")
	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, indexPath)
	}).Methods("GET")
	r.HandleFunc("/index.html", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, indexPath)
	}).Methods("GET")
	r.HandleFunc("/deviceid", GetDeviceIDHandler).Methods("GET")
	r.HandleFunc("/webauthn/register/options", WebAuthnRegisterOptionsHandler).Methods("POST")
	r.HandleFunc("/webauthn/register/verify", WebAuthnRegisterVerifyHandler).Methods("POST")

	// Serve static files from the project root, but not for / or /index.html
	r.PathPrefix("/").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" || r.URL.Path == "/index.html" {
			http.NotFound(w, r)
			return
		}
		http.FileServer(http.Dir(".")).ServeHTTP(w, r)
	})
	return r
}
