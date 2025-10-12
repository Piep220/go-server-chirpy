
package main

import (
    "testing"
    "time"

    "github.com/Piep220/go-server-chirpy/internal/auth"
    "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func TestHashPasswordAndCheckPasswordHash(t *testing.T) {
    password := "supersecret"
    hash, err := auth.HashPassword(password)
    if err != nil {
        t.Fatalf("HashPassword failed: %v", err)
    }
    if hash == "" {
        t.Fatal("HashPassword returned empty hash")
    }

    match, err := auth.CheckPasswordHash(password, hash)
    if err != nil {
        t.Fatalf("CheckPasswordHash failed: %v", err)
    }
    if !match {
        t.Error("CheckPasswordHash did not match correct password")
    }

    wrongMatch, err := auth.CheckPasswordHash("wrongpassword", hash)
    if err != nil {
        t.Fatalf("CheckPasswordHash failed: %v", err)
    }
    if wrongMatch {
        t.Error("CheckPasswordHash matched incorrect password")
    }
}

func TestMakeJWTAndValidateJWT(t *testing.T) {
    userID := uuid.New()
    secret := "mysecret"
    expires := time.Minute * 5

    token, err := auth.MakeJWT(userID, secret, expires)
    if err != nil {
        t.Fatalf("MakeJWT failed: %v", err)
    }
    if token == "" {
        t.Fatal("MakeJWT returned empty token")
    }

    parsedID, err := auth.ValidateJWT(token, secret)
    if err != nil {
        t.Fatalf("ValidateJWT failed: %v", err)
    }
    if parsedID != userID {
        t.Errorf("ValidateJWT returned wrong UUID: got %v, want %v", parsedID, userID)
    }
}

func TestValidateJWT_InvalidToken(t *testing.T) {
    secret := "mysecret"
    invalidToken := "not.a.jwt.token"

    _, err := auth.ValidateJWT(invalidToken, secret)
    if err == nil {
        t.Error("ValidateJWT should fail for invalid token")
    }
}

func TestValidateJWT_BadSecret(t *testing.T) {
    userID := uuid.New()
    secret := "mysecret"
    badSecret := "wrongsecret"
    expires := time.Minute * 5

    token, err := auth.MakeJWT(userID, secret, expires)
    if err != nil {
        t.Fatalf("MakeJWT failed: %v", err)
    }

    _, err = auth.ValidateJWT(token, badSecret)
    if err == nil {
        t.Error("ValidateJWT should fail for wrong secret")
    }
}

func TestValidateJWT_NonUUIDSubject(t *testing.T) {
    // Create a token with a non-UUID subject
    secret := "mysecret"
    expires := time.Minute * 5

    _, err := auth.MakeJWT(uuid.New(), secret, expires)
    if err != nil {
        t.Fatalf("MakeJWT failed: %v", err)
    }

    // Tamper with the token to change the subject to a non-UUID
    // This is a bit tricky, so we'll just create a token manually
    claims := map[string]any{
        "iss": "chirpy",
        "sub": "not-a-uuid",
        "iat": time.Now().Unix(),
        "exp": time.Now().Add(expires).Unix(),
    }
    tkn := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(claims))
    badToken, err := tkn.SignedString([]byte(secret))
    if err != nil {
        t.Fatalf("Failed to sign tampered token: %v", err)
    }

    _, err = auth.ValidateJWT(badToken, secret)
    if err == nil {
        t.Error("ValidateJWT should fail for non-UUID subject")
    }
}