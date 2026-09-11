package main

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestGenerateKeyPair(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if kp.PrivateKey == nil {
		t.Fatal("private key is nil")
	}
	if kp.KID == "" {
		t.Fatal("kid is empty")
	}
}

func TestSignIDToken(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	claims := IDTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "http://localhost:8080",
			Subject:   "user1",
			Audience:  jwt.ClaimStrings{"my-app"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		Nonce:  "test-nonce",
		Email:  "alice@example.com",
		Name:   "Alice",
		Custom: map[string]any{"roles": []string{"admin"}},
	}

	tokenStr, err := kp.SignIDToken(claims)
	if err != nil {
		t.Fatal(err)
	}
	if tokenStr == "" {
		t.Fatal("token is empty")
	}

	// Verify the token can be parsed back with the public key
	parsed, err := jwt.Parse(tokenStr, func(token *jwt.Token) (any, error) {
		return &kp.PrivateKey.PublicKey, nil
	})
	if err != nil {
		t.Fatalf("failed to parse token: %v", err)
	}
	if !parsed.Valid {
		t.Fatal("token is not valid")
	}
	mapClaims := parsed.Claims.(jwt.MapClaims)
	if mapClaims["sub"] != "user1" {
		t.Errorf("expected sub=user1, got %v", mapClaims["sub"])
	}
	if mapClaims["nonce"] != "test-nonce" {
		t.Errorf("expected nonce=test-nonce, got %v", mapClaims["nonce"])
	}
	if mapClaims["email"] != "alice@example.com" {
		t.Errorf("expected email, got %v", mapClaims["email"])
	}
	roles, ok := mapClaims["roles"]
	if !ok {
		t.Fatal("expected roles claim")
	}
	roleList, ok := roles.([]any)
	if !ok || len(roleList) == 0 || roleList[0] != "admin" {
		t.Errorf("expected roles=[admin], got %v", roles)
	}
}

func TestMarshalJSON_AudSerialization(t *testing.T) {
	tests := []struct {
		name     string
		audience jwt.ClaimStrings
		wantStr  bool // true = expect string, false = expect array
	}{
		{"single audience becomes string", jwt.ClaimStrings{"my-app"}, true},
		{"multiple audiences stays array", jwt.ClaimStrings{"app1", "app2"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := IDTokenClaims{
				RegisteredClaims: jwt.RegisteredClaims{
					Issuer:   "http://localhost:8080",
					Subject:  "user1",
					Audience: tt.audience,
				},
			}
			b, err := json.Marshal(claims)
			if err != nil {
				t.Fatal(err)
			}
			var m map[string]any
			if err := json.Unmarshal(b, &m); err != nil {
				t.Fatal(err)
			}
			switch aud := m["aud"].(type) {
			case string:
				if !tt.wantStr {
					t.Errorf("expected array, got string %q", aud)
				}
				if aud != tt.audience[0] {
					t.Errorf("expected %q, got %q", tt.audience[0], aud)
				}
			case []any:
				if tt.wantStr {
					t.Errorf("expected string, got array %v", aud)
				}
				if len(aud) != len(tt.audience) {
					t.Errorf("expected %d elements, got %d", len(tt.audience), len(aud))
				}
			default:
				t.Errorf("unexpected aud type: %T", m["aud"])
			}
		})
	}
}

func TestMarshalJSON_AudWithCustomClaims(t *testing.T) {
	claims := IDTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:   "http://localhost:8080",
			Subject:  "user1",
			Audience: jwt.ClaimStrings{"my-app"},
		},
		Custom: map[string]any{"role": "admin"},
	}
	b, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["aud"].(string); !ok {
		t.Errorf("expected aud as string, got %T", m["aud"])
	}
	if m["role"] != "admin" {
		t.Errorf("expected role=admin, got %v", m["role"])
	}
}

func TestMarshalJSON_NoAud(t *testing.T) {
	claims := IDTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:  "http://localhost:8080",
			Subject: "user1",
		},
	}
	b, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if _, exists := m["aud"]; exists {
		t.Errorf("expected no aud field, got %v", m["aud"])
	}
}
