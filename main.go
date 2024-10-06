package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"regexp"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"github.com/l2thet/Chirpy/internal/database"
	"github.com/l2thet/Chirpy/internal/database/auth"
	_ "github.com/lib/pq"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	dbQueries *database.Queries
	platform string
	secret string
}

type User struct {
	ID uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Email string `json:"email"`
	Token string `json:"token"`
	RefreshToken string `json:"refresh_token"`
}

const ExpirationDefault = 3600

func main() {
	
	godotenv.Load()
	dbURL := os.Getenv("DB_URL")
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatal(err)
		return
	}

	dbQueries := database.New(db)

	apiCfg := &apiConfig{}
	apiCfg.fileserverHits.Store(0)
	apiCfg.dbQueries = dbQueries
	apiCfg.platform = os.Getenv("PLATFORM")
	apiCfg.secret = os.Getenv("SECRET")

	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	mux.HandleFunc("POST /api/users", func(w http.ResponseWriter, r *http.Request) {
		type parameters struct {
			Email string `json:"email"`
			Password string `json:"password"`
		}

		decoder := json.NewDecoder(r.Body)
		params := parameters{}
		err := decoder.Decode(&params)
		if err != nil {
			log.Printf("Error decoding request body: %v", err)
            http.Error(w, "Invalid request payload", http.StatusBadRequest)
            return
		}

		hashed_pass, err := auth.HashPassword(params.Password)
		if err != nil {
			log.Printf("Error hashing password: %v", err)
			http.Error(w, "Error hashing password", http.StatusInternalServerError)
			return
		}

		dbUser, err := apiCfg.dbQueries.CreateUser(r.Context(), database.CreateUserParams{
			Email:    params.Email,
			HashedPassword: hashed_pass,
		})
		if err != nil {
			log.Printf("Error creating user: %v", err)
            http.Error(w, "Error creating user", http.StatusInternalServerError)
			return
		}

		apiUser := User{
			ID:        dbUser.ID,
			CreatedAt: dbUser.CreatedAt,
			UpdatedAt: dbUser.UpdatedAt,
			Email:     dbUser.Email,
		}
		dat, err := json.Marshal(apiUser)
		if err != nil {
			log.Printf("Error marshalling user data: %v", err)
            http.Error(w, "Error processing user data", http.StatusInternalServerError)
            return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		w.Write(dat)
	})

	mux.HandleFunc(("PUT /api/users"), func(w http.ResponseWriter, r *http.Request) {
		type parameters struct {
			Email string `json:"email"`
			Password string `json:"password"`
		}

		tokenString, err := auth.GetBearerToken(r.Header)
		if err != nil {
			log.Printf("Error getting bearer token: %v", err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		userId, err := auth.ValidateJWT(tokenString, apiCfg.secret)
		if err != nil {
			log.Printf("Error validating JWT: %v", err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		decoder := json.NewDecoder(r.Body)
		params := parameters{}
		err = decoder.Decode(&params)
		if err != nil {
			log.Printf("Error decoding request body: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		hashed_pass, err := auth.HashPassword(params.Password)
		if err != nil {
			log.Printf("Error hashing password: %v", err)
			http.Error(w, "Error hashing password", http.StatusInternalServerError)
			return
		}

		err = apiCfg.dbQueries.UpdateUser(r.Context(), database.UpdateUserParams{
			ID: userId,
			Email: params.Email,
			HashedPassword: hashed_pass,
		})
		if err != nil {
			log.Printf("Error updating user: %v", err)
			http.Error(w, "Error updating user", http.StatusInternalServerError)
			return
		}

		apiUser := User{
			ID:        userId,
			Email:     params.Email,
		}
		dat, err := json.Marshal(apiUser)
		if err != nil {
			log.Printf("Error marshalling user data: %v", err)
			http.Error(w, "Error processing user data", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(dat)
	})

	mux.HandleFunc("POST /api/chirps", func(w http.ResponseWriter, r *http.Request) {
		type parameters struct {
			Body string `json:"body"`
			User_Id uuid.UUID `json:"user_id"`
		}

		tokenString, err := auth.GetBearerToken(r.Header)
		if err != nil {
			log.Printf("Error getting bearer token: %v", err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		userId, err := auth.ValidateJWT(tokenString, apiCfg.secret)
		if err != nil {
			log.Printf("Error validating JWT: %v", err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		decoder := json.NewDecoder(r.Body)
		params := parameters{}
		err = decoder.Decode(&params)
		if err != nil {
			log.Printf("Error decoding request body: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if len(params.Body) > 140 {
			log.Printf("Message is beyond the max chars: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		chirp, err := apiCfg.dbQueries.CreateChirp(r.Context(), database.CreateChirpParams{Body: params.Body, UserID: userId})
		if err != nil {
			log.Printf("Error creating chirp: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		type Chirp struct{
			Body string `json:"body"`
			CreatedAt time.Time `json:"created_at"`
			UpdatedAt time.Time `json:"updated_at"`
			UserID uuid.UUID `json:"user_id"`
			ID uuid.UUID `json:"id"`
		}
		respBody := Chirp{
			Body: stringCleaner(chirp.Body),
			CreatedAt: chirp.CreatedAt,
			UpdatedAt: chirp.UpdatedAt,
			UserID: chirp.UserID,
			ID: chirp.ID,
		}

		dat, err := json.Marshal(respBody)
		if err != nil {
			log.Printf("Error building the response: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		w.Write(dat)
	})

	mux.HandleFunc("GET /api/chirps", func(w http.ResponseWriter, r *http.Request) {
		type Chirp struct{
			Body string `json:"body"`
			CreatedAt time.Time `json:"created_at"`
			UpdatedAt time.Time `json:"updated_at"`
			UserID uuid.UUID `json:"user_id"`
			ID uuid.UUID `json:"id"`
		}

		dbChirps, err := apiCfg.dbQueries.Chirps(r.Context())
		if err != nil {
			log.Printf("Error creating chirp: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		
		var chirps []Chirp
		for _, dbChirp := range dbChirps {
			chirps = append(chirps, Chirp{
				Body: stringCleaner(dbChirp.Body),
				CreatedAt: dbChirp.CreatedAt,
				UpdatedAt: dbChirp.UpdatedAt,
				UserID: dbChirp.UserID,
				ID: dbChirp.ID,
			})
		}

		dat, err := json.Marshal(chirps)
		if err != nil {
			log.Printf("Error building the response: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(dat)
	})

	mux.HandleFunc("GET /api/chirps/{chirpId}", func(w http.ResponseWriter, r *http.Request) {
		type Chirp struct{
			Body string `json:"body"`
			CreatedAt time.Time `json:"created_at"`
			UpdatedAt time.Time `json:"updated_at"`
			UserID uuid.UUID `json:"user_id"`
			ID uuid.UUID `json:"id"`
		}

		idString := r.PathValue("chirpId")
		id, err := uuid.Parse(idString)
		if err != nil {
			log.Printf("Error parsing UUID: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		dbChirp, err := apiCfg.dbQueries.Chirp(r.Context(), id)
		if err != nil {
			log.Printf("Error retrieving chirp: %v", err)
			w.WriteHeader(http.StatusNotFound)
			return
		}

		chirp := Chirp{
			Body: stringCleaner(dbChirp.Body),
			CreatedAt: dbChirp.CreatedAt,
			UpdatedAt: dbChirp.UpdatedAt,
			UserID: dbChirp.UserID,
			ID: dbChirp.ID,
		}

		dat, err := json.Marshal(chirp)
		if err != nil {
			log.Printf("Error building the response: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(dat)
	})

	mux.HandleFunc("POST /api/login", func(w http.ResponseWriter, r *http.Request) {
		type parameters struct {
			Email string `json:"email"`
			Password string `json:"password"`
		}

		decoder := json.NewDecoder(r.Body)
		params := parameters{}
		err := decoder.Decode(&params)
		if err != nil {
			log.Printf("Error decoding request body: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		user, err := apiCfg.dbQueries.UserByEmail(r.Context(), params.Email)
		if err != nil {
			log.Printf("Error retrieving user: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		err = auth.CheckPasswordHash(params.Password, user.HashedPassword)
		if err != nil {
			log.Printf("Email or password invalid: %v", err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		token, err := auth.MakeJWT(user.ID, apiCfg.secret, time.Duration(ExpirationDefault)* time.Second)
		if err != nil {
			log.Printf("Error creating token: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		refreshToken, err := auth.MakeRefreshToken()
		if err != nil {
			log.Printf("Error creating refresh token: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		//Create a duration of 60 days
		expiresOn := time.Now().Add(time.Hour*24*60)

		_, err = apiCfg.dbQueries.CreateRefreshToken(r.Context(), database.CreateRefreshTokenParams{ Token: refreshToken, UserID: user.ID, ExpiresAt: expiresOn})
		if err != nil {
			log.Printf("Error savving refresh token: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		userData := User{
			ID: user.ID,
			CreatedAt: user.CreatedAt,
			UpdatedAt: user.UpdatedAt,
			Email: user.Email,
			Token: token,
			RefreshToken: refreshToken,
		}
		dat, err := json.Marshal(userData)
		if err != nil {
			log.Printf("Error marshalling user data: %v", err)
            http.Error(w, "Error processing user data", http.StatusInternalServerError)
            return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(dat)
	})

	mux.HandleFunc("POST /api/refresh", func(w http.ResponseWriter, r *http.Request) {
		refreshToken, err := auth.GetBearerToken(r.Header)
		if err != nil {
			log.Printf("Error getting bearer token: %v", err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		rToken, err := dbQueries.RefreshToken(r.Context(), refreshToken)
		if err != nil {
			log.Printf("Error retrieving refresh token: %v", err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if rToken.RevokedAt.Valid {
			log.Printf("Refresh token revoked: %v", err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if rToken.ExpiresAt.Before(time.Now()) {
			log.Printf("Refresh token expired: %v", err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		userId, err := dbQueries.UserFromRefreshToken(r.Context(), rToken.Token)
		if err != nil {
			log.Printf("Error retrieving user from refresh token: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		token, err := auth.MakeJWT(userId, apiCfg.secret, time.Duration(ExpirationDefault)* time.Second)
		if err != nil {
			log.Printf("Error creating token: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		type parameters struct {
			Token string `json:"token"`
		}

		dat, err := json.Marshal(parameters{Token: token})
		if err != nil {
			log.Printf("Error marshalling token: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(dat)
	})

	mux.HandleFunc("POST /api/revoke", func(w http.ResponseWriter, r *http.Request) {
		refreshToken, err := auth.GetBearerToken(r.Header)
		if err != nil {
			log.Printf("Error getting bearer token: %v", err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		err = dbQueries.RevokeRefreshToken(r.Context(), refreshToken)
		if err != nil {
			log.Printf("Error revoking refresh token: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("DELETE /api/chirps/{chirpId}", func(w http.ResponseWriter, r *http.Request) {
		token, err := auth.GetBearerToken(r.Header)
		if err != nil {
			log.Printf("Error getting bearer token: %v", err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		userId, err := auth.ValidateJWT(token, apiCfg.secret)
		if err != nil {
			log.Printf("Error validating JWT: %v", err)
			w.WriteHeader(http.StatusForbidden)
			return
		}

		chirpIdString := r.PathValue("chirpId")
		chirpId, err := uuid.Parse(chirpIdString)
		if err != nil {
			log.Printf("Error parsing UUID: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		chirp, err := dbQueries.Chirp(r.Context(), chirpId)
		if err != nil {
			log.Printf("Error retrieving chirp: %v", err)
			w.WriteHeader(http.StatusNotFound)
			return
		}

		if chirp == (database.Chirp{}) {
			log.Printf("Chirp not found")
			w.WriteHeader(http.StatusNotFound)
			return
		}

		if chirp.UserID != userId {
			log.Printf("User does not own chirp")
			w.WriteHeader(http.StatusForbidden)
			return
		}

		err = dbQueries.DeleteChirp(r.Context(), chirpId)
		if err != nil {
			log.Printf("Error deleting chirp: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("GET /admin/metrics", apiCfg.metricsHandler)

	mux.HandleFunc("POST /admin/reset", apiCfg.resetHandler)

	mux.Handle("/app/", apiCfg.middlewareMetricsInc(http.StripPrefix("/app/", http.FileServer(http.Dir(".")))))

	mux.Handle("/app/assets/", apiCfg.middlewareMetricsInc(http.StripPrefix("/app/", http.FileServer(http.Dir(".")))))

	server := http.Server{
		Addr: ":8080",
		Handler: mux,
	}

	server.ListenAndServe()
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        cfg.fileserverHits.Add(1)
        next.ServeHTTP(w, r)
    })
}

func (cfg *apiConfig) metricsHandler(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("templates/metrics.html")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    
    w.Header().Set("Content-Type", "text/html")

    err = tmpl.Execute(w, cfg.fileserverHits.Load())
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
		return
    }
}

func (cfg *apiConfig) resetHandler(w http.ResponseWriter, r *http.Request){
	if cfg.platform != "dev" {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	err := cfg.dbQueries.DeleteAllUsers(r.Context())
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	cfg.fileserverHits.Store(0)
}

func stringCleaner(input string) string {
	patterns := []string{`kerfuffle`,`sharbert`, `fornax`}
	compiledPatterns, err := compilePatterns(patterns)
    if err != nil {
		return fmt.Sprintf("Error compiling patterns: %s", err)
    }

	return stringReplace(input, compiledPatterns)
}

func compilePatterns(patterns []string) ([]*regexp.Regexp, error) {
    var compiledPatterns []*regexp.Regexp
    for _, pattern := range patterns {
        re, err := regexp.Compile("(?i)" + pattern)
        if err != nil {
            return nil, err
        }
        compiledPatterns = append(compiledPatterns, re)
    }
    return compiledPatterns, nil
}

func stringReplace(input string, patterns []*regexp.Regexp) string {
    for _, re := range patterns {
        input = re.ReplaceAllString(input, "****")
    }
    return input
}