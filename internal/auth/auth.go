package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/alexedwards/argon2id"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)


func HashPassword(password string) (string, error) {
	hash, err := argon2id.CreateHash(password, argon2id.DefaultParams)
	return hash, err
}

func CheckPasswordHash(password, hash string) (bool, error) {
	match, err := argon2id.ComparePasswordAndHash(password, hash)
	return match, err
}

func MakeJWT(userID uuid.UUID, tokenSecret string, expiresIn time.Duration) (string, error) {
	claims := jwt.RegisteredClaims{
		Issuer: 	"chirpy",
		Subject: 	userID.String(),
		IssuedAt: 	jwt.NewNumericDate(time.Now()),
		ExpiresAt: 	jwt.NewNumericDate(time.Now().Add(expiresIn)),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(tokenSecret))
	if err != nil {
        return "", err
    }
	
    return signedToken, nil
}

func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {
	claims := &jwt.RegisteredClaims{}
	keyFunc := func(t *jwt.Token)  (any, error) {
		return []byte(tokenSecret), nil
	}
	token, err := jwt.ParseWithClaims(
		tokenString, 
		claims,
		keyFunc,
		jwt.WithIssuer("chirpy"),
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name}),
	)
	if err != nil {
        return uuid.Nil, fmt.Errorf("cannot parse JWT token: %w", err)
    }

	if !token.Valid {
		return uuid.Nil, errors.New("invalid token")
	}

	subject, err := token.Claims.GetSubject()
	if err != nil {
		return uuid.Nil, fmt.Errorf("cannot get token subject: %w", err)
	}

	id, err := uuid.Parse(subject)
	if err != nil {
		return uuid.Nil, fmt.Errorf("subject is not a valid UUID: %w", err)
	}

	return id, nil
}

func GetBearerToken(headers http.Header) (string, error) {
	authHeader := headers.Get("Authorization")
	if authHeader == "" {
		return "", errors.New("no Authorization header provided")
	}

	var tokenType, token string
	n, err := fmt.Sscanf(authHeader, "%s %s", &tokenType, &token)
	if err != nil || n != 2 {
		return "", errors.New("invalid Authorization header format")
	}
	if tokenType != "Bearer" {
		return "", errors.New("authorization header is not a Bearer token")
	}

	return token, nil
}

func MakeRefreshToken() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", fmt.Errorf("error generating refresh token: %w", err)
	}

	return hex.EncodeToString(b), nil
}

func GetAPIKey(headers http.Header) (string, error) {
	//Authorization: ApiKey THE_KEY_HERE
	authHeader := headers.Get("Authorization")
	if authHeader == "" {
		return "", errors.New("no Authorization header provided")
	}

	var authType, key string
	n, err := fmt.Sscanf(authHeader, "%s %s", &authType, &key)
	if err != nil || n != 2 {
		return "", errors.New("invalid Authorization header format")
	}
	if authType != "ApiKey" {
		return "", errors.New("authorization header is not an apikey")
	}

	return key, nil
}