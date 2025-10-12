package auth

import (
	"errors"
	"time"
	"fmt"

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
