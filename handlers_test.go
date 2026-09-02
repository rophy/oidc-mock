package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfig()
	return &Server{
		Config:  cfg,
		KeyPair: kp,
		Store:   NewStore(),
	}
}

func TestDiscoveryEndpoint(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest("GET", "/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()

	srv.HandleDiscovery(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var doc map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc["issuer"] != "http://localhost:8080" {
		t.Errorf("unexpected issuer: %v", doc["issuer"])
	}
	if doc["authorization_endpoint"] != "http://localhost:8080/authorize" {
		t.Errorf("unexpected authorization_endpoint: %v", doc["authorization_endpoint"])
	}
	if doc["token_endpoint"] != "http://localhost:8080/token" {
		t.Errorf("unexpected token_endpoint: %v", doc["token_endpoint"])
	}
	if doc["jwks_uri"] != "http://localhost:8080/jwks" {
		t.Errorf("unexpected jwks_uri: %v", doc["jwks_uri"])
	}
	if doc["userinfo_endpoint"] != "http://localhost:8080/userinfo" {
		t.Errorf("unexpected userinfo_endpoint: %v", doc["userinfo_endpoint"])
	}

	grantTypes := doc["grant_types_supported"].([]any)
	if len(grantTypes) != 2 || grantTypes[0] != "authorization_code" || grantTypes[1] != "refresh_token" {
		t.Errorf("unexpected grant_types_supported: %v", grantTypes)
	}

	challengeMethods := doc["code_challenge_methods_supported"].([]any)
	if len(challengeMethods) != 2 || challengeMethods[0] != "S256" || challengeMethods[1] != "plain" {
		t.Errorf("unexpected code_challenge_methods_supported: %v", challengeMethods)
	}

	scopes := doc["scopes_supported"].([]any)
	if len(scopes) != 4 {
		t.Errorf("expected 4 scopes_supported, got %v", scopes)
	}
}

func TestJWKSEndpoint(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest("GET", "/jwks", nil)
	w := httptest.NewRecorder()

	srv.HandleJWKS(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var jwks map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &jwks); err != nil {
		t.Fatal(err)
	}
	keys, ok := jwks["keys"].([]any)
	if !ok || len(keys) != 1 {
		t.Fatalf("expected 1 key, got %v", jwks["keys"])
	}
	key := keys[0].(map[string]any)
	if key["kty"] != "RSA" {
		t.Errorf("expected kty=RSA, got %v", key["kty"])
	}
	if key["alg"] != "RS256" {
		t.Errorf("expected alg=RS256, got %v", key["alg"])
	}
	if key["kid"] != srv.KeyPair.KID {
		t.Errorf("expected kid=%s, got %v", srv.KeyPair.KID, key["kid"])
	}
	if key["use"] != "sig" {
		t.Errorf("expected use=sig, got %v", key["use"])
	}
}

func TestAuthorizeEndpoint_InvalidClient(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest("GET", "/authorize?client_id=bad&redirect_uri=http://example.com/cb&response_type=code&scope=openid", nil)
	w := httptest.NewRecorder()

	srv.HandleAuthorize(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestAuthorizeEndpoint_RendersPicker(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest("GET", "/authorize?client_id=default&redirect_uri=http://localhost:8080/callback&response_type=code&scope=openid&state=xyz&nonce=abc", nil)
	w := httptest.NewRecorder()

	srv.HandleAuthorize(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "Alice") {
		t.Error("expected Alice in picker")
	}
	if !strings.Contains(body, "Bob") {
		t.Error("expected Bob in picker")
	}
}

func TestAuthorizeEndpoint_InvalidResponseType(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest("GET", "/authorize?client_id=default&redirect_uri=http://localhost:8080/callback&response_type=token&scope=openid", nil)
	w := httptest.NewRecorder()

	srv.HandleAuthorize(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "response_type") {
		t.Error("expected error message to mention response_type")
	}
}

func TestAuthorizeEndpoint_MissingResponseType(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest("GET", "/authorize?client_id=default&redirect_uri=http://localhost:8080/callback&scope=openid", nil)
	w := httptest.NewRecorder()

	srv.HandleAuthorize(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestAuthorizeCallback_RedirectsWithCode(t *testing.T) {
	srv := newTestServer(t)

	form := strings.NewReader("sub=user1&client_id=default&redirect_uri=http://localhost:8080/callback&state=xyz&nonce=abc")
	req := httptest.NewRequest("POST", "/authorize/callback", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	srv.HandleAuthorizeCallback(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", w.Code)
	}
	loc := w.Header().Get("Location")
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatal(err)
	}
	if u.Query().Get("code") == "" {
		t.Error("expected code in redirect")
	}
	if u.Query().Get("state") != "xyz" {
		t.Errorf("expected state=xyz, got %s", u.Query().Get("state"))
	}
}

func TestTokenEndpoint_ValidExchange(t *testing.T) {
	srv := newTestServer(t)

	srv.Store.SaveAuthCode("testcode", AuthCodeData{
		UserSub:     "user1",
		ClientID:    "default",
		RedirectURI: "http://localhost:8080/callback",
		Nonce:       "nonce1",
		Scope:       "openid email profile offline_access",
		ExpiresAt:   time.Now().Add(60 * time.Second),
	})

	form := strings.NewReader("grant_type=authorization_code&code=testcode&client_id=default&client_secret=secret&redirect_uri=http://localhost:8080/callback")
	req := httptest.NewRequest("POST", "/token", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	srv.HandleToken(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["token_type"] != "Bearer" {
		t.Errorf("expected token_type=Bearer, got %v", resp["token_type"])
	}
	if resp["id_token"] == nil || resp["id_token"] == "" {
		t.Error("expected id_token")
	}
	if resp["access_token"] == nil || resp["access_token"] == "" {
		t.Error("expected access_token")
	}
	if resp["refresh_token"] == nil || resp["refresh_token"] == "" {
		t.Error("expected refresh_token")
	}
}

func TestTokenEndpoint_RefreshToken(t *testing.T) {
	srv := newTestServer(t)

	srv.Store.SaveRefreshToken("rt1", RefreshTokenData{
		UserSub:  "user1",
		ClientID: "default",
		Scope:    "openid offline_access",
	})

	form := strings.NewReader("grant_type=refresh_token&refresh_token=rt1&client_id=default&client_secret=secret")
	req := httptest.NewRequest("POST", "/token", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	srv.HandleToken(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["access_token"] == nil || resp["access_token"] == "" {
		t.Error("expected new access_token")
	}
	if resp["refresh_token"] == nil || resp["refresh_token"] == "" {
		t.Error("expected new refresh_token")
	}
	if resp["id_token"] == nil || resp["id_token"] == "" {
		t.Error("expected new id_token")
	}
	if resp["token_type"] != "Bearer" {
		t.Errorf("expected token_type=Bearer, got %v", resp["token_type"])
	}
}

func TestTokenEndpoint_RefreshToken_InvalidToken(t *testing.T) {
	srv := newTestServer(t)

	form := strings.NewReader("grant_type=refresh_token&refresh_token=bad&client_id=default&client_secret=secret")
	req := httptest.NewRequest("POST", "/token", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	srv.HandleToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestTokenEndpoint_RefreshToken_WrongClient(t *testing.T) {
	srv := newTestServer(t)

	srv.Config.Clients = append(srv.Config.Clients, Client{
		ID:     "other",
		Secret: "other-secret",
	})
	srv.Store.SaveRefreshToken("rt1", RefreshTokenData{
		UserSub:  "user1",
		ClientID: "default",
	})

	form := strings.NewReader("grant_type=refresh_token&refresh_token=rt1&client_id=other&client_secret=other-secret")
	req := httptest.NewRequest("POST", "/token", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	srv.HandleToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestTokenEndpoint_NoRefreshTokenWithoutOfflineAccess(t *testing.T) {
	srv := newTestServer(t)

	srv.Store.SaveAuthCode("code1", AuthCodeData{
		UserSub:     "user1",
		ClientID:    "default",
		RedirectURI: "http://localhost:8080/callback",
		Nonce:       "n",
		Scope:       "openid email profile",
		ExpiresAt:   time.Now().Add(60 * time.Second),
	})

	form := strings.NewReader("grant_type=authorization_code&code=code1&client_id=default&client_secret=secret&redirect_uri=http://localhost:8080/callback")
	req := httptest.NewRequest("POST", "/token", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	srv.HandleToken(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)

	if resp["refresh_token"] != nil {
		t.Error("expected no refresh_token without offline_access scope")
	}
}

func TestTokenEndpoint_RefreshTokenWithOfflineAccess(t *testing.T) {
	srv := newTestServer(t)

	srv.Store.SaveAuthCode("code1", AuthCodeData{
		UserSub:     "user1",
		ClientID:    "default",
		RedirectURI: "http://localhost:8080/callback",
		Nonce:       "n",
		Scope:       "openid email profile offline_access",
		ExpiresAt:   time.Now().Add(60 * time.Second),
	})

	form := strings.NewReader("grant_type=authorization_code&code=code1&client_id=default&client_secret=secret&redirect_uri=http://localhost:8080/callback")
	req := httptest.NewRequest("POST", "/token", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	srv.HandleToken(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)

	if resp["refresh_token"] == nil || resp["refresh_token"] == "" {
		t.Error("expected refresh_token with offline_access scope")
	}
}

func TestTokenEndpoint_InvalidClient(t *testing.T) {
	srv := newTestServer(t)

	form := strings.NewReader("grant_type=authorization_code&code=x&client_id=bad&client_secret=bad&redirect_uri=http://x")
	req := httptest.NewRequest("POST", "/token", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	srv.HandleToken(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestTokenEndpoint_CodeAlreadyConsumed(t *testing.T) {
	srv := newTestServer(t)

	srv.Store.SaveAuthCode("once", AuthCodeData{
		UserSub:     "user1",
		ClientID:    "default",
		RedirectURI: "http://localhost:8080/callback",
		Nonce:       "n",
		Scope:       "openid",
		ExpiresAt:   time.Now().Add(60 * time.Second),
	})

	makeReq := func() *httptest.ResponseRecorder {
		form := strings.NewReader("grant_type=authorization_code&code=once&client_id=default&client_secret=secret&redirect_uri=http://localhost:8080/callback")
		req := httptest.NewRequest("POST", "/token", form)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		srv.HandleToken(w, req)
		return w
	}

	w1 := makeReq()
	if w1.Code != http.StatusOK {
		t.Fatalf("first exchange: expected 200, got %d", w1.Code)
	}

	w2 := makeReq()
	if w2.Code != http.StatusBadRequest {
		t.Errorf("second exchange: expected 400, got %d", w2.Code)
	}
}

func TestTokenEndpoint_BasicAuth(t *testing.T) {
	srv := newTestServer(t)

	srv.Store.SaveAuthCode("basiccode", AuthCodeData{
		UserSub:     "user1",
		ClientID:    "default",
		RedirectURI: "http://localhost:8080/callback",
		Nonce:       "n",
		Scope:       "openid offline_access",
		ExpiresAt:   time.Now().Add(60 * time.Second),
	})

	form := strings.NewReader("grant_type=authorization_code&code=basiccode&redirect_uri=http://localhost:8080/callback")
	req := httptest.NewRequest("POST", "/token", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("default", "secret")
	w := httptest.NewRecorder()

	srv.HandleToken(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["id_token"] == nil || resp["id_token"] == "" {
		t.Error("expected id_token")
	}
}

func TestTokenEndpoint_BasicAuth_InvalidSecret(t *testing.T) {
	srv := newTestServer(t)

	form := strings.NewReader("grant_type=authorization_code&code=x&redirect_uri=http://x")
	req := httptest.NewRequest("POST", "/token", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("default", "wrongsecret")
	w := httptest.NewRecorder()

	srv.HandleToken(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestUserinfoEndpoint(t *testing.T) {
	srv := newTestServer(t)

	srv.Store.SaveAccessToken("atok", AccessTokenData{UserSub: "user1", Scope: "openid email profile"})

	req := httptest.NewRequest("GET", "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer atok")
	w := httptest.NewRecorder()

	srv.HandleUserinfo(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	ct := w.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("expected Content-Type application/json, got %q", ct)
	}

	var claims map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &claims); err != nil {
		t.Fatal(err)
	}
	if claims["sub"] != "user1" {
		t.Errorf("expected sub=user1, got %v", claims["sub"])
	}
	if claims["email"] != "alice@example.com" {
		t.Errorf("expected email, got %v", claims["email"])
	}
	if claims["name"] != "Alice" {
		t.Errorf("expected name=Alice, got %v", claims["name"])
	}
}

func TestUserinfoEndpoint_CustomClaims(t *testing.T) {
	srv := newTestServer(t)

	srv.Store.SaveAccessToken("atok", AccessTokenData{UserSub: "user1", Scope: "openid email profile"})

	req := httptest.NewRequest("GET", "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer atok")
	w := httptest.NewRecorder()

	srv.HandleUserinfo(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var claims map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &claims); err != nil {
		t.Fatal(err)
	}

	roles, ok := claims["roles"]
	if !ok {
		t.Fatal("expected custom claim 'roles' in response")
	}
	roleList, ok := roles.([]any)
	if !ok {
		t.Fatalf("expected roles to be a list, got %T", roles)
	}
	if len(roleList) != 1 || roleList[0] != "admin" {
		t.Errorf("expected roles=[admin], got %v", roleList)
	}
}

func TestUserinfoEndpoint_UserNotFound(t *testing.T) {
	srv := newTestServer(t)

	srv.Store.SaveAccessToken("atok", AccessTokenData{UserSub: "nonexistent-user", Scope: "openid"})

	req := httptest.NewRequest("GET", "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer atok")
	w := httptest.NewRecorder()

	srv.HandleUserinfo(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

func TestUserinfoEndpoint_MalformedAuthHeader(t *testing.T) {
	srv := newTestServer(t)

	cases := []struct {
		name string
		auth string
	}{
		{"BasicScheme", "Basic dXNlcjpwYXNz"},
		{"BearerNoSpace", "Bearertoken"},
		{"EmptyValue", "Bearer "},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/userinfo", nil)
			req.Header.Set("Authorization", tc.auth)
			w := httptest.NewRecorder()

			srv.HandleUserinfo(w, req)

			if w.Code != http.StatusUnauthorized {
				t.Errorf("expected 401, got %d", w.Code)
			}
		})
	}
}

func TestUserinfoEndpoint_InvalidToken(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest("GET", "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer badtoken")
	w := httptest.NewRecorder()

	srv.HandleUserinfo(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}

	wwwAuth := w.Header().Get("WWW-Authenticate")
	if wwwAuth != `Bearer error="invalid_token"` {
		t.Errorf("expected WWW-Authenticate with invalid_token error, got %q", wwwAuth)
	}
}

func TestUserinfoEndpoint_MissingToken(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest("GET", "/userinfo", nil)
	w := httptest.NewRecorder()

	srv.HandleUserinfo(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}

	wwwAuth := w.Header().Get("WWW-Authenticate")
	if wwwAuth != "Bearer" {
		t.Errorf("expected WWW-Authenticate: Bearer, got %q", wwwAuth)
	}
}

func TestTokenEndpoint_PKCE_S256(t *testing.T) {
	srv := newTestServer(t)

	// Known test vector: verifier "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	// SHA256 = E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	srv.Store.SaveAuthCode("pkcecode", AuthCodeData{
		UserSub:             "user1",
		ClientID:            "default",
		RedirectURI:         "http://localhost:8080/callback",
		Nonce:               "n",
		Scope:               "openid",
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		ExpiresAt:           time.Now().Add(60 * time.Second),
	})

	form := strings.NewReader("grant_type=authorization_code&code=pkcecode&client_id=default&client_secret=secret&redirect_uri=http://localhost:8080/callback&code_verifier=" + verifier)
	req := httptest.NewRequest("POST", "/token", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	srv.HandleToken(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestTokenEndpoint_PKCE_S256_WrongVerifier(t *testing.T) {
	srv := newTestServer(t)

	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	srv.Store.SaveAuthCode("pkcecode", AuthCodeData{
		UserSub:             "user1",
		ClientID:            "default",
		RedirectURI:         "http://localhost:8080/callback",
		Nonce:               "n",
		Scope:               "openid",
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		ExpiresAt:           time.Now().Add(60 * time.Second),
	})

	form := strings.NewReader("grant_type=authorization_code&code=pkcecode&client_id=default&client_secret=secret&redirect_uri=http://localhost:8080/callback&code_verifier=wrong-verifier")
	req := httptest.NewRequest("POST", "/token", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	srv.HandleToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestTokenEndpoint_PKCE_Plain(t *testing.T) {
	srv := newTestServer(t)

	verifier := "plainverifier123"

	srv.Store.SaveAuthCode("pkcecode", AuthCodeData{
		UserSub:             "user1",
		ClientID:            "default",
		RedirectURI:         "http://localhost:8080/callback",
		Nonce:               "n",
		Scope:               "openid",
		CodeChallenge:       verifier,
		CodeChallengeMethod: "plain",
		ExpiresAt:           time.Now().Add(60 * time.Second),
	})

	form := strings.NewReader("grant_type=authorization_code&code=pkcecode&client_id=default&client_secret=secret&redirect_uri=http://localhost:8080/callback&code_verifier=" + verifier)
	req := httptest.NewRequest("POST", "/token", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	srv.HandleToken(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestTokenEndpoint_PKCE_MissingVerifier(t *testing.T) {
	srv := newTestServer(t)

	srv.Store.SaveAuthCode("pkcecode", AuthCodeData{
		UserSub:             "user1",
		ClientID:            "default",
		RedirectURI:         "http://localhost:8080/callback",
		Nonce:               "n",
		Scope:               "openid",
		CodeChallenge:       "somechallenge",
		CodeChallengeMethod: "S256",
		ExpiresAt:           time.Now().Add(60 * time.Second),
	})

	form := strings.NewReader("grant_type=authorization_code&code=pkcecode&client_id=default&client_secret=secret&redirect_uri=http://localhost:8080/callback")
	req := httptest.NewRequest("POST", "/token", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	srv.HandleToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestTokenEndpoint_PKCE_UnsupportedMethod(t *testing.T) {
	srv := newTestServer(t)

	srv.Store.SaveAuthCode("pkcecode", AuthCodeData{
		UserSub:             "user1",
		ClientID:            "default",
		RedirectURI:         "http://localhost:8080/callback",
		Nonce:               "n",
		Scope:               "openid",
		CodeChallenge:       "somechallenge",
		CodeChallengeMethod: "S512",
		ExpiresAt:           time.Now().Add(60 * time.Second),
	})

	form := strings.NewReader("grant_type=authorization_code&code=pkcecode&client_id=default&client_secret=secret&redirect_uri=http://localhost:8080/callback&code_verifier=somechallenge")
	req := httptest.NewRequest("POST", "/token", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	srv.HandleToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestUserinfoEndpoint_POST(t *testing.T) {
	srv := newTestServer(t)

	srv.Store.SaveAccessToken("atok", AccessTokenData{UserSub: "user1", Scope: "openid email profile"})

	req := httptest.NewRequest("POST", "/userinfo", strings.NewReader("access_token=atok"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	srv.HandleUserinfo(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var claims map[string]any
	json.Unmarshal(w.Body.Bytes(), &claims)

	if claims["sub"] != "user1" {
		t.Errorf("expected sub=user1, got %v", claims["sub"])
	}
	if claims["email"] != "alice@example.com" {
		t.Errorf("expected email, got %v", claims["email"])
	}
}

func TestUserinfoEndpoint_POST_NoToken(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest("POST", "/userinfo", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	srv.HandleUserinfo(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestTokenEndpoint_IDToken_ContainsAtHash(t *testing.T) {
	srv := newTestServer(t)

	srv.Store.SaveAuthCode("hashcode", AuthCodeData{
		UserSub:     "user1",
		ClientID:    "default",
		RedirectURI: "http://localhost:8080/callback",
		Nonce:       "n",
		Scope:       "openid email profile",
		ExpiresAt:   time.Now().Add(60 * time.Second),
	})

	form := strings.NewReader("grant_type=authorization_code&code=hashcode&client_id=default&client_secret=secret&redirect_uri=http://localhost:8080/callback")
	req := httptest.NewRequest("POST", "/token", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	srv.HandleToken(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)

	accessToken := resp["access_token"].(string)
	idTokenStr := resp["id_token"].(string)

	parsed, err := jwt.Parse(idTokenStr, func(token *jwt.Token) (any, error) {
		return &srv.KeyPair.PrivateKey.PublicKey, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	claims := parsed.Claims.(jwt.MapClaims)

	atHash, ok := claims["at_hash"].(string)
	if !ok || atHash == "" {
		t.Fatal("expected at_hash claim in id_token")
	}

	// Verify: left half of SHA-256 of access_token, base64url-encoded
	h := sha256.Sum256([]byte(accessToken))
	expectedAtHash := base64.RawURLEncoding.EncodeToString(h[:16])
	if atHash != expectedAtHash {
		t.Errorf("at_hash mismatch: got %s, expected %s", atHash, expectedAtHash)
	}
}

func TestUserinfoEndpoint_ScopeFiltering_OpenIDOnly(t *testing.T) {
	srv := newTestServer(t)

	srv.Store.SaveAccessToken("atok", AccessTokenData{UserSub: "user1", Scope: "openid"})

	req := httptest.NewRequest("GET", "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer atok")
	w := httptest.NewRecorder()

	srv.HandleUserinfo(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var claims map[string]any
	json.Unmarshal(w.Body.Bytes(), &claims)

	if claims["sub"] != "user1" {
		t.Error("expected sub claim")
	}
	if claims["email"] != nil {
		t.Errorf("expected no email with openid-only scope, got %v", claims["email"])
	}
	if claims["name"] != nil {
		t.Errorf("expected no name with openid-only scope, got %v", claims["name"])
	}
}

func TestUserinfoEndpoint_ScopeFiltering_EmailScope(t *testing.T) {
	srv := newTestServer(t)

	srv.Store.SaveAccessToken("atok", AccessTokenData{UserSub: "user1", Scope: "openid email"})

	req := httptest.NewRequest("GET", "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer atok")
	w := httptest.NewRecorder()

	srv.HandleUserinfo(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var claims map[string]any
	json.Unmarshal(w.Body.Bytes(), &claims)

	if claims["sub"] != "user1" {
		t.Error("expected sub claim")
	}
	if claims["email"] != "alice@example.com" {
		t.Errorf("expected email, got %v", claims["email"])
	}
	if claims["email_verified"] != true {
		t.Errorf("expected email_verified=true, got %v", claims["email_verified"])
	}
	if claims["name"] != nil {
		t.Errorf("expected no name with openid+email scope, got %v", claims["name"])
	}
}

func TestUserinfoEndpoint_ScopeFiltering_ProfileScope(t *testing.T) {
	srv := newTestServer(t)

	srv.Store.SaveAccessToken("atok", AccessTokenData{UserSub: "user1", Scope: "openid profile"})

	req := httptest.NewRequest("GET", "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer atok")
	w := httptest.NewRecorder()

	srv.HandleUserinfo(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var claims map[string]any
	json.Unmarshal(w.Body.Bytes(), &claims)

	if claims["sub"] != "user1" {
		t.Error("expected sub claim")
	}
	if claims["name"] != "Alice" {
		t.Errorf("expected name=Alice, got %v", claims["name"])
	}
	if claims["email"] != nil {
		t.Errorf("expected no email with openid+profile scope, got %v", claims["email"])
	}
	if claims["roles"] == nil {
		t.Error("expected custom claims (roles) with profile scope")
	}
}

func TestTokenEndpoint_IDToken_ScopeFiltering(t *testing.T) {
	srv := newTestServer(t)

	srv.Store.SaveAuthCode("scopecode", AuthCodeData{
		UserSub:     "user1",
		ClientID:    "default",
		RedirectURI: "http://localhost:8080/callback",
		Nonce:       "n",
		Scope:       "openid",
		ExpiresAt:   time.Now().Add(60 * time.Second),
	})

	form := strings.NewReader("grant_type=authorization_code&code=scopecode&client_id=default&client_secret=secret&redirect_uri=http://localhost:8080/callback")
	req := httptest.NewRequest("POST", "/token", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	srv.HandleToken(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)

	idTokenStr := resp["id_token"].(string)
	parsed, _ := jwt.Parse(idTokenStr, func(token *jwt.Token) (any, error) {
		return &srv.KeyPair.PrivateKey.PublicKey, nil
	})
	claims := parsed.Claims.(jwt.MapClaims)

	if claims["sub"] != "user1" {
		t.Error("expected sub")
	}
	if claims["email"] != nil {
		t.Errorf("expected no email in id_token with openid-only scope, got %v", claims["email"])
	}
	if claims["name"] != nil {
		t.Errorf("expected no name in id_token with openid-only scope, got %v", claims["name"])
	}
}

func TestRevokeEndpoint_AccessToken(t *testing.T) {
	srv := newTestServer(t)

	srv.Store.SaveAccessToken("atok", AccessTokenData{UserSub: "user1", Scope: "openid"})

	form := strings.NewReader("token=atok&token_type_hint=access_token")
	req := httptest.NewRequest("POST", "/revoke", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	srv.HandleRevoke(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	if _, ok := srv.Store.GetAccessToken("atok"); ok {
		t.Error("expected access token to be revoked")
	}
}

func TestRevokeEndpoint_RefreshToken(t *testing.T) {
	srv := newTestServer(t)

	srv.Store.SaveRefreshToken("rt1", RefreshTokenData{UserSub: "user1", ClientID: "default", Scope: "openid"})

	form := strings.NewReader("token=rt1&token_type_hint=refresh_token")
	req := httptest.NewRequest("POST", "/revoke", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	srv.HandleRevoke(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	if _, ok := srv.Store.GetRefreshToken("rt1"); ok {
		t.Error("expected refresh token to be revoked")
	}
}

func TestRevokeEndpoint_UnknownToken(t *testing.T) {
	srv := newTestServer(t)

	form := strings.NewReader("token=nonexistent")
	req := httptest.NewRequest("POST", "/revoke", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	srv.HandleRevoke(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 even for unknown token, got %d", w.Code)
	}
}

func TestRevokeEndpoint_NoHint(t *testing.T) {
	srv := newTestServer(t)

	srv.Store.SaveAccessToken("atok", AccessTokenData{UserSub: "user1", Scope: "openid"})
	srv.Store.SaveRefreshToken("atok", RefreshTokenData{UserSub: "user1", ClientID: "default", Scope: "openid"})

	form := strings.NewReader("token=atok")
	req := httptest.NewRequest("POST", "/revoke", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	srv.HandleRevoke(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if _, ok := srv.Store.GetAccessToken("atok"); ok {
		t.Error("expected access token to be revoked")
	}
	if _, ok := srv.Store.GetRefreshToken("atok"); ok {
		t.Error("expected refresh token to be revoked")
	}
}

func TestRevokeEndpoint_EmptyToken(t *testing.T) {
	srv := newTestServer(t)

	form := strings.NewReader("token=")
	req := httptest.NewRequest("POST", "/revoke", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	srv.HandleRevoke(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestEndSessionEndpoint_Redirect(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest("GET", "/end-session?post_logout_redirect_uri=http://localhost:3000/logged-out&state=abc", nil)
	w := httptest.NewRecorder()

	srv.HandleEndSession(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", w.Code)
	}

	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if loc.String() == "" {
		t.Fatal("expected Location header")
	}
	if loc.Query().Get("state") != "abc" {
		t.Errorf("expected state=abc in redirect, got %s", loc.Query().Get("state"))
	}
}

func TestEndSessionEndpoint_NoRedirect(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest("GET", "/end-session", nil)
	w := httptest.NewRecorder()

	srv.HandleEndSession(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func newTestServerWithPassword(t *testing.T) *Server {
	t.Helper()
	srv := newTestServer(t)
	srv.Config.Users = []User{
		{Sub: "user1", Email: "alice@example.com", Name: "Alice", Password: "secret123"},
		{Sub: "user2", Email: "bob@example.com", Name: "Bob"},
	}
	return srv
}

func TestAuthorizeCallback_NoPassword_StillWorks(t *testing.T) {
	srv := newTestServerWithPassword(t)

	form := strings.NewReader("sub=user2&client_id=default&redirect_uri=http://localhost:8080/callback&state=xyz&nonce=abc")
	req := httptest.NewRequest("POST", "/authorize/callback", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	srv.HandleAuthorizeCallback(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", w.Code)
	}
	loc := w.Header().Get("Location")
	u, _ := url.Parse(loc)
	if u.Query().Get("code") == "" {
		t.Error("expected code in redirect for passwordless user")
	}
}

func TestAuthorizeCallback_PasswordRequired_ShowsForm(t *testing.T) {
	srv := newTestServerWithPassword(t)

	form := strings.NewReader("sub=user1&client_id=default&redirect_uri=http://localhost:8080/callback&state=xyz&nonce=abc")
	req := httptest.NewRequest("POST", "/authorize/callback", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	srv.HandleAuthorizeCallback(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (password form), got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "password") {
		t.Error("expected password input in response")
	}
	if !strings.Contains(body, "Alice") {
		t.Error("expected user name in password form")
	}
}

func TestAuthorizeCallback_WrongPassword(t *testing.T) {
	srv := newTestServerWithPassword(t)

	form := strings.NewReader("sub=user1&password=wrong&client_id=default&redirect_uri=http://localhost:8080/callback&state=xyz&nonce=abc")
	req := httptest.NewRequest("POST", "/authorize/callback", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	srv.HandleAuthorizeCallback(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (password form with error), got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "Invalid password") {
		t.Error("expected error message for wrong password")
	}
}

func TestAuthorizeCallback_CorrectPassword(t *testing.T) {
	srv := newTestServerWithPassword(t)

	form := strings.NewReader("sub=user1&password=secret123&client_id=default&redirect_uri=http://localhost:8080/callback&state=xyz&nonce=abc")
	req := httptest.NewRequest("POST", "/authorize/callback", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	srv.HandleAuthorizeCallback(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", w.Code)
	}
	loc := w.Header().Get("Location")
	u, _ := url.Parse(loc)
	if u.Query().Get("code") == "" {
		t.Error("expected code in redirect after correct password")
	}
}

func TestAuthorizeCallback_UnknownUser(t *testing.T) {
	srv := newTestServer(t)

	form := strings.NewReader("sub=nonexistent&client_id=default&redirect_uri=http://localhost:8080/callback&state=xyz&nonce=abc")
	req := httptest.NewRequest("POST", "/authorize/callback", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	srv.HandleAuthorizeCallback(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}
