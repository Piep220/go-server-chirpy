package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync/atomic"
)

type apiConfig struct {
	fileserverHits atomic.Int32
}

type validChirpJSON struct {
	Body string `json:"body"`
}

type errorReturnJSON struct {
	Error string `json:"error"`
}

type validReturnJSON struct {
	Valid bool `json:"valid"`
}


func main() {
	mux := http.NewServeMux()
	apiCfg := &apiConfig{}

	mux.HandleFunc("GET /api/healthz", healthHandler)
	mux.HandleFunc("POST /api/validate_chirp",validateChirpHandler)
	mux.HandleFunc("GET /admin/metrics", apiCfg.hitsHandler)
	mux.HandleFunc("POST /admin/reset", apiCfg.resetHandler)

	mux.Handle("/app/",
		apiCfg.middlewareMetricsInc(
			http.StripPrefix(
				"/app/", 
				http.FileServer(http.Dir(filepathRoot)),
			),
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

func validateChirpHandler(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	params := validChirpJSON{}
	err := decoder.Decode(&params)
	if err != nil {
		log.Printf("Error decoding parameters: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if len(params.Body) > 140 {
		tooLongError := errorReturnJSON{
			Error: "Chirp is too long",
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		jsonBytes, err := json.Marshal(tooLongError)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, `{"error":"Internal server error"}`)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		w.Write(jsonBytes)
		return
	}
	validJSON := validReturnJSON {
		Valid: true,
	}
	jsonBytes, err := json.Marshal(validJSON)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `{"error":"Internal server error"}`)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write(jsonBytes)
}

func (ac *apiConfig) hitsHandler(w http.ResponseWriter, r *http.Request) {
	count := ac.fileserverHits.Load()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	html := fmt.Sprintf(`<html>
  <body>
    <h1>Welcome, Chirpy Admin</h1>
    <p>Chirpy has been visited %d times!</p>
  </body>
</html>`, count)
	fmt.Fprint(w, html)
}

func (ac *apiConfig) resetHandler(w http.ResponseWriter, r *http.Request) {
	ac.fileserverHits.Store(0)

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprint(w, "Hit counter reset\n")
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

/*
func middlewareLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}
*/

func (ac *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ac.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}