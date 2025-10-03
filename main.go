package main

import (
	"net/http"
	"log"
)

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", healthHandler)

	mux.Handle("/app/",
		http.StripPrefix(
			"/app/",
			http.FileServer(http.Dir(filepathRoot)),
		),
	)

	mux.Handle("/assets/",
		http.StripPrefix(
			"/assets/",
			http.FileServer(http.Dir("assets")),
		),
	)

	srv := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}
	
	log.Printf("Serving files from %s on port: %s\n", filepathRoot, port)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")

	// needs logic to determine readiness
	ready := true
	if !ready { 
    	w.WriteHeader(http.StatusServiceUnavailable)
	} else {
    	w.WriteHeader(http.StatusOK)
	}

	//handle error?
	_, _ = w.Write([]byte("OK"))
}
