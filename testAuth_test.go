
package main

import (
    "testing"
    "time"
	"net/http"

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

func TestCheckPasswordHash(t *testing.T) {
	// First, we need to create some hashed passwords for testing
	password1 := "correctPassword123!"
	password2 := "anotherPassword456!"
	hash2, _ := auth.HashPassword(password2)
	hash1, _ := auth.HashPassword(password1)

	tests := []struct {
		name          string
		password      string
		hash          string
		wantErr       bool
		matchPassword bool
	}{
		{
			name:          "Correct password",
			password:      password1,
			hash:          hash1,
			wantErr:       false,
			matchPassword: true,
		},
		{
			name:          "Incorrect password",
			password:      "wrongPassword",
			hash:          hash1,
			wantErr:       false,
			matchPassword: false,
		},
		{
			name:          "Password doesn't match different hash",
			password:      password1,
			hash:          hash2,
			wantErr:       false,
			matchPassword: false,
		},
		{
			name:          "Empty password",
			password:      "",
			hash:          hash1,
			wantErr:       false,
			matchPassword: false,
		},
		{
			name:          "Invalid hash",
			password:      password1,
			hash:          "invalidhash",
			wantErr:       true,
			matchPassword: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, err := auth.CheckPasswordHash(tt.password, tt.hash)
			if (err != nil) != tt.wantErr {
				t.Errorf("CheckPasswordHash() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && match != tt.matchPassword {
				t.Errorf("CheckPasswordHash() expects %v, got %v", tt.matchPassword, match)
			}
		})
	}
}

func TestValidateJWT(t *testing.T) {
	userID := uuid.New()
	validToken, _ := auth.MakeJWT(userID, "secret", time.Hour)

	tests := []struct {
		name        string
		tokenString string
		tokenSecret string
		wantUserID  uuid.UUID
		wantErr     bool
	}{
		{
			name:        "Valid token",
			tokenString: validToken,
			tokenSecret: "secret",
			wantUserID:  userID,
			wantErr:     false,
		},
		{
			name:        "Invalid token",
			tokenString: "invalid.token.string",
			tokenSecret: "secret",
			wantUserID:  uuid.Nil,
			wantErr:     true,
		},
		{
			name:        "Wrong secret",
			tokenString: validToken,
			tokenSecret: "wrong_secret",
			wantUserID:  uuid.Nil,
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotUserID, err := auth.ValidateJWT(tt.tokenString, tt.tokenSecret)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateJWT() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotUserID != tt.wantUserID {
				t.Errorf("ValidateJWT() gotUserID = %v, want %v", gotUserID, tt.wantUserID)
			}
		})
	}
}

func TestGetBearerToken(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		wantToken     string
		expectErr     bool
		expectedError string
	}{
		{
			name:      "missing Authorization header",
			headers:   http.Header{}, // empty headers
			expectErr: true,
			expectedError: "no Authorization header provided",
		},
		{
			name:    "valid Bearer token",
			headers: http.Header{"Authorization": {"Bearer abc123"}},
			wantToken:     "abc123",
			expectErr:     false,
		},
		{
			name:          "wrong token type",
			headers:       http.Header{"Authorization": {"Basic abc123"}},
			expectErr:     true,
			expectedError: "authorization header is not a Bearer token",
		},
		{
			name:          "malformed header – only token type",
			headers:       http.Header{"Authorization": {"Bearer"}},
			expectErr:     true,
			expectedError: "invalid Authorization header format",
		},
		{
			name:    "extra spaces are ignored",
			headers: http.Header{"Authorization": {"Bearer   abc123  "}},
			wantToken:     "abc123",
			expectErr:     false,
		},
		{
			name:          "case‑sensitive token type",
			headers:       http.Header{"Authorization": {"bearer abc123"}},
			expectErr:     true,
			expectedError: "authorization header is not a Bearer token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := auth.GetBearerToken(tt.headers)

			if tt.expectErr {
				if err == nil {
					t.Fatalf("expected an error but got none (token=%q)", token)
				}
				if err.Error() != tt.expectedError {
					t.Errorf("unexpected error message.\nGot:  %q\nWant: %q", err.Error(), tt.expectedError)
				}
				return
			}

			if err != nil {
				t.Fatalf("did not expect an error, but got: %v", err)
			}
			if token != tt.wantToken {
				t.Errorf("wrong token.\nGot:  %q\nWant: %q", token, tt.wantToken)
			}
		})
	}
}