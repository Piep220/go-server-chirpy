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
	"time"

	"github.com/Piep220/go-server-chirpy/internal/auth"
	"github.com/Piep220/go-server-chirpy/internal/database"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type apiConfig struct {
	fileserverHits 	atomic.Int32
	db 				*database.Queries
	jwtSecret 		string
}

type errorReturnJSON struct {
	Error string `json:"error"`
}

type chirpJSON struct {
	Body   string 	 `json:"body"`
	UserID uuid.UUID `json:"user_id"`
}

type loginUser struct {
	Password 		 string `json:"password"`
	Email    		 string `json:"email"`
	ExpiresInSeconds int    `json:"expires_in_seconds"`
}

type PublicUser struct {
	ID             uuid.UUID `json:"id"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	Email          string    `json:"email"`
	Token     	   string    `json:"token"`
	RefreshToken   string    `json:"refresh_token,omitempty"`
}

type tokenJSON struct {
	Token string `json:"token"`
}

func main() {
	godotenv.Load()
	dbURL := os.Getenv("DB_URL")
	jwtSecret := os.Getenv("JWT_SECRET")
	db, _ := sql.Open("postgres", dbURL)
	dbQueries := database.New(db)

	mux := http.NewServeMux()
	apiCfg := &apiConfig{
		fileserverHits: atomic.Int32{},
		db: 			dbQueries,
		jwtSecret: jwtSecret,
	}

	mux.HandleFunc("GET /api/healthz", healthHandler)
	mux.HandleFunc("GET /api/chirps", apiCfg.getChirpsHandler)
	mux.HandleFunc("GET /api/chirps/{chirpID}", apiCfg.getChripFromID)
	mux.HandleFunc("POST /api/chirps", apiCfg.chirpsHandler)
	mux.HandleFunc("POST /api/users", apiCfg.usersHandler)
	mux.HandleFunc("POST /api/login", apiCfg.loginHandler)
	mux.HandleFunc("POST /api/refresh", apiCfg.refreshHandler)
	mux.HandleFunc("POST /api/revoke", apiCfg.revokeHandler)

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

	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "error getting token from header")
		return
	}

	id, err := auth.ValidateJWT(token, ac.jwtSecret)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "invalid JWT")
		return
	}

	if len(params.Body) > 140 {
		respondWithError(w, http.StatusBadRequest, "Chirp is too long")
		return
	}
	cleaned := cleanProfanity(params.Body)

	chirp := database.CreateChirpParams{
		Body: cleaned,
		UserID: id,
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

func (ac *apiConfig)getChripFromID(w http.ResponseWriter, r *http.Request) {
	uuidStr := r.PathValue("chirpID")
	if uuidStr == "" {
		respondWithError(w, http.StatusNotFound, "no such chirp")
		return
	}

	id, err := uuid.Parse(uuidStr)
	if err != nil {
		respondWithError(w, http.StatusNotFound, "invalid UUID")
		return
	}

	chirp, err := ac.db.GetChirpByID(r.Context(), id)
	if err != nil {
		respondWithError(w, http.StatusNotFound, "cannot retrieve chirp")
		return
	}
	respondWithJSON(w, http.StatusOK, chirp)
}

func (ac *apiConfig)usersHandler(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	params := loginUser{}
	err := decoder.Decode(&params)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}

	hash, err := auth.HashPassword(params.Password)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "error creating password")
		return
	}

	newUser := database.CreateUserParams{
		Email: params.Email,
		HashedPassword: hash,
	}
	
	user, err := ac.db.CreateUser(r.Context(), newUser)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "error creating db entry")
		return
	}

	publicUser := PublicUser{
		ID: user.ID,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
		Email: user.Email,
	}

	respondWithJSON(w, http.StatusCreated, publicUser)
}

func (ac *apiConfig)loginHandler(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	params := loginUser{}
	err := decoder.Decode(&params)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}

	user, err := ac.db.GetUserByEmail(r.Context(),params.Email)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "error finding user")
		return
	}

	pwCheck, err := auth.CheckPasswordHash(params.Password, user.HashedPassword)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "error validating password")
		return
	}

	if !pwCheck {
		respondWithError(w, http.StatusUnauthorized, "Incorrect email or password")
		return
	}

	jwtExpiraionTime := time.Hour
	if params.ExpiresInSeconds != 0 {
		jwtExpiraionTime = time.Duration(params.ExpiresInSeconds)
	}
	
	token, err := auth.MakeJWT(user.ID, ac.jwtSecret, jwtExpiraionTime)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "error generating jwt")
		return
	}

	refreshToken, err := auth.MakeRefreshToken()
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "error generating refresh token")
		return
	}

	refTokenParams := database.CreateRefreshTokenParams{
		Token: refreshToken,
		UserID: user.ID,
		ExpiresAt: time.Now().Add(60 * 24 * time.Hour),
	}
	_, err = ac.db.CreateRefreshToken(r.Context(), refTokenParams)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "error storing refresh token")
		return
	}

	publicUser := PublicUser{
		ID: user.ID,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
		Email: user.Email,
		Token: token,
		RefreshToken: refreshToken,
	}

	respondWithJSON(w, http.StatusOK, publicUser)
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
	ac.db.DeleteAllRefreshTokens(r.Context())
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

func (ac *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ac.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func (ac *apiConfig) refreshHandler(w http.ResponseWriter, r *http.Request) {
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "error getting token from header")
		return
	}

	if token == "" {
		respondWithError(w, http.StatusUnauthorized, "no token provided")
		return
	}

	refreshToken, err := ac.db.GetRefreshToken(r.Context(), token)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "invalid refresh token")
		return
	}

	if refreshToken.ExpiresAt.Before(time.Now()) {
		respondWithError(w, http.StatusUnauthorized, "refresh token expired")
		return
	}

	if refreshToken.RevokedAt.Valid {
		respondWithError(w, http.StatusUnauthorized, "refresh token revoked")
		return
	}

	user, err := ac.db.GetUserByID(r.Context(), refreshToken.UserID)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "error finding user")
		return
	}

	newJWT, err := auth.MakeJWT(user.ID, ac.jwtSecret, time.Hour)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "error generating jwt")
		return
	}

	respondWithJSON(w, http.StatusOK, tokenJSON{Token: newJWT})
}

func (ac *apiConfig) revokeHandler(w http.ResponseWriter, r *http.Request) {
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "error getting token from header")
		return
	}

	if token == "" {
		respondWithError(w, http.StatusUnauthorized, "no token provided")
		return
	}

	refreshToken, err := ac.db.GetRefreshToken(r.Context(), token)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "invalid refresh token")
		return
	}

	if refreshToken.RevokedAt.Valid {
		respondWithError(w, http.StatusUnauthorized, "refresh token already revoked")
		return
	}

	err = ac.db.RevokeRefreshToken(r.Context(), refreshToken.Token)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "error revoking refresh token")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}