package main

import (
	"log"
	"net/http"

	"github.com/harrylevesque/slqrpdf/internal/api"
)

func main() {
	router := api.NewRouter()
	log.Println("Server running on https://localhost:8443")
	log.Fatal(http.ListenAndServeTLS(":8443", "localhost.pem", "localhost-key.pem", router))
}
