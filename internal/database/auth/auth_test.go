package auth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
)

func TestMakeJWT(t *testing.T){
	userID := uuid.New()
	tokenSecret := "test_secret"
	expires := time.Hour

	token, err := MakeJWT(userID, tokenSecret, expires)
	if err != nil {
		t.Errorf("MakeJWT returned an error: %v", err)
	}

	if token == "" {
		t.Errorf("MakeJWT returned an empty token")
	}
}

func TestValidateJWT(t *testing.T){
	userID := uuid.New()
	tokenSecret := "test_secret"
	expires := time.Hour

	tokenString, err := MakeJWT(userID, tokenSecret, expires)
	if err != nil {
		t.Errorf("MakeJWT returned an error: %v", err)
	}

	id, err := ValidateJWT(tokenString, tokenSecret)
	if err != nil {
		t.Errorf("ValidateJWT returned an error: %v", err)
	}

	if id != userID {
		t.Errorf("ValidateJWT returned an incorrect user id: %v", id)
	}

	// Test invalid token
	_, err = ValidateJWT("invalid_token", tokenSecret)
	if err == nil {
		t.Errorf("ValidateJWT did not return an error for an invalid token")
	}

	// Test expired token
	claims := jwt.RegisteredClaims{}
	claims.Issuer = "chirpy"
	claims.IssuedAt = jwt.NewNumericDate(time.Now().Add(-2 * time.Hour))
	claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Hour))
	claims.Subject = userID.String()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(tokenSecret))
	if err != nil {
		t.Errorf("Error signing expired token: %v", err)
	}

	_, err = ValidateJWT(signedToken, tokenSecret)
	if err == nil {
		t.Errorf("ValidateJWT did not return an error for an expired token")
	}
}

func TestHashPassword(t *testing.T){
	password := "test_password"

	hash, err := HashPassword(password)
	if err != nil {
		t.Errorf("HashPassword returned an error: %v", err)
	}

	if hash == "" {
		t.Errorf("HashPassword returned an empty hash")
	}

	err = CheckPasswordHash(password, hash)
	if err != nil {
		t.Errorf("CheckPasswordHash returned an error: %v", err)
	}
}