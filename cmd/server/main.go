package main

import (
	"github.com/harrylevesque/slqrpdf/internal/api"
	"log"
	"net/http"
)

func main() {
	r := api.NewRouter()
	log.Println("Server running on :8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}
