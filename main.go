package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"sync/atomic"

	"github.com/Piep220/go-server-chirpy/internal/database"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	db *database.Queries
}

type errorReturnJSON struct {
	Error string `json:"error"`
}

type chirpJSON struct {
	Body   string 	 `json:"body"`
	UserID uuid.UUID `json:"user_id"`
}

type emailJSON struct {
	Email string `json:"email"`
}

func main() {
	godotenv.Load()
	dbURL := os.Getenv("DB_URL")
	db, _ := sql.Open("postgres", dbURL)
	dbQueries := database.New(db)

	mux := http.NewServeMux()
	apiCfg := &apiConfig{
		fileserverHits: atomic.Int32{},
		db: 			dbQueries,
	}

	mux.HandleFunc("GET /api/healthz", healthHandler)
	mux.HandleFunc("GET /api/chirps", apiCfg.getChirpsHandler)
	mux.HandleFunc("POST /api/chirps", apiCfg.chirpsHandler)
	mux.HandleFunc("POST /api/users", apiCfg.usersHandler)

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

func (ac *apiConfig)chirpsHandler(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	params := chirpJSON{}
	err := decoder.Decode(&params)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}

	if len(params.Body) > 140 {
		respondWithError(w, http.StatusBadRequest, "Chirp is too long")
		return
	}
	cleaned := cleanProfanity(params.Body)

	chirp := database.CreateChirpParams{
		Body: cleaned,
		UserID: params.UserID,
	}
	
	createdChirp, err := ac.db.CreateChirp(r.Context(), chirp)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Problem creating chirp record")
		return
	}

	respondWithJSON(w, http.StatusCreated, createdChirp)
}

func (ac *apiConfig)getChirpsHandler(w http.ResponseWriter, r *http.Request) {
	posts, err := ac.db.GetAllChirps(r.Context())
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "error retrieving db entry")
		return
	}
	respondWithJSON(w, http.StatusOK, posts)
}

func (ac *apiConfig)usersHandler(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	params := emailJSON{}
	err := decoder.Decode(&params)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}
	
	user, err := ac.db.CreateUser(r.Context(), params.Email)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "error creating db entry")
		return
	}

	respondWithJSON(w, http.StatusCreated, user)
}

func cleanProfanity(text string) string {
	var profane = regexp.MustCompile(`(?i)\b(?:kerfuffle|sharbert|fornax)\b`)
	return profane.ReplaceAllString(text, "****")
}

func respondWithError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(errorReturnJSON{Error: msg})
}

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(payload)
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
	if os.Getenv("PLATFORM") != "dev" {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	ac.db.DeleteAllUsers(r.Context())
	ac.db.DeleteAllChirps(r.Context())
	ac.fileserverHits.Store(0)

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprint(w, "System reset\n")
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
