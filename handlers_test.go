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

func TestAuthorizeEndpoint_InvalidRedirectURI(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest("GET", "/authorize?client_id=default&redirect_uri=http://evil.com/callback&response_type=code&scope=openid", nil)
	w := httptest.NewRecorder()

	srv.HandleAuthorize(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "invalid redirect_uri") {
		t.Error("expected error message about invalid redirect_uri")
	}
}

func TestAuthorizeEndpoint_InvalidResponseType(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest("GET", "/authorize?client_id=default&redirect_uri=http://localhost:8080/callback&response_type=token&scope=openid&state=xyz", nil)
	w := httptest.NewRecorder()

	srv.HandleAuthorize(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", w.Code)
	}
	loc, _ := url.Parse(w.Header().Get("Location"))
	if loc.Query().Get("error") != "unsupported_response_type" {
		t.Errorf("expected error=unsupported_response_type, got %s", loc.Query().Get("error"))
	}
	if loc.Query().Get("state") != "xyz" {
		t.Errorf("expected state=xyz, got %s", loc.Query().Get("state"))
	}
}

func TestAuthorizeEndpoint_MissingResponseType(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest("GET", "/authorize?client_id=default&redirect_uri=http://localhost:8080/callback&scope=openid", nil)
	w := httptest.NewRecorder()

	srv.HandleAuthorize(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", w.Code)
	}
	loc, _ := url.Parse(w.Header().Get("Location"))
	if loc.Query().Get("error") != "unsupported_response_type" {
		t.Errorf("expected error=unsupported_response_type, got %s", loc.Query().Get("error"))
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

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
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

func TestTokenEndpoint_RedirectURIMismatch(t *testing.T) {
	srv := newTestServer(t)

	srv.Store.SaveAuthCode("code1", AuthCodeData{
		UserSub:     "user1",
		ClientID:    "default",
		RedirectURI: "http://localhost:8080/callback",
		Nonce:       "n",
		Scope:       "openid",
		ExpiresAt:   time.Now().Add(60 * time.Second),
	})

	form := strings.NewReader("grant_type=authorization_code&code=code1&client_id=default&client_secret=secret&redirect_uri=http://localhost:8080/other")
	req := httptest.NewRequest("POST", "/token", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	srv.HandleToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for redirect_uri mismatch, got %d", w.Code)
	}
}

func TestTokenEndpoint_UnsupportedGrantType(t *testing.T) {
	srv := newTestServer(t)

	form := strings.NewReader("grant_type=client_credentials&client_id=default&client_secret=secret")
	req := httptest.NewRequest("POST", "/token", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	srv.HandleToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for unsupported grant_type, got %d", w.Code)
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
	if ct != "application/json;charset=UTF-8" {
		t.Errorf("expected Content-Type application/json;charset=UTF-8, got %q", ct)
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

	form := strings.NewReader("grant_type=authorization_code&code=pkcecode&client_id=default&client_secret=secret&redirect_uri=http://localhost:8080/callback&code_verifier=wrong-verifier-padded-to-43-chars-abcdefghijklm")
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

	verifier := "plainverifier1234567890abcdefghijklmnopqrstuvwx"

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

func TestTokenEndpoint_ConcurrentRedemption(t *testing.T) {
	srv := newTestServer(t)

	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	srv.Store.SaveAuthCode("race-code", AuthCodeData{
		UserSub:             "user1",
		ClientID:            "default",
		RedirectURI:         "http://localhost:8080/callback",
		Nonce:               "n",
		Scope:               "openid",
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		ExpiresAt:           time.Now().Add(60 * time.Second),
	})

	results := make(chan int, 10)
	for i := 0; i < 10; i++ {
		go func() {
			form := strings.NewReader("grant_type=authorization_code&code=race-code&client_id=default&client_secret=secret&redirect_uri=http://localhost:8080/callback&code_verifier=" + verifier)
			req := httptest.NewRequest("POST", "/token", form)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()
			srv.HandleToken(w, req)
			results <- w.Code
		}()
	}

	successCount := 0
	for i := 0; i < 10; i++ {
		code := <-results
		if code == http.StatusOK {
			successCount++
		}
	}

	if successCount != 1 {
		t.Errorf("expected exactly 1 successful redemption, got %d", successCount)
	}
}

func TestTokenEndpoint_CodeNotConsumedOnValidationFailure(t *testing.T) {
	srv := newTestServer(t)

	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	srv.Store.SaveAuthCode("mycode", AuthCodeData{
		UserSub:             "user1",
		ClientID:            "default",
		RedirectURI:         "http://localhost:8080/callback",
		Nonce:               "n",
		Scope:               "openid",
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		ExpiresAt:           time.Now().Add(60 * time.Second),
	})

	// First attempt: wrong verifier — should fail but NOT consume the code
	form := strings.NewReader("grant_type=authorization_code&code=mycode&client_id=default&client_secret=secret&redirect_uri=http://localhost:8080/callback&code_verifier=wrong-verifier-padded-to-43-chars-abcdefghijklm")
	req := httptest.NewRequest("POST", "/token", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.HandleToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for wrong verifier, got %d", w.Code)
	}

	// Second attempt: correct verifier — should succeed because code was not consumed
	form = strings.NewReader("grant_type=authorization_code&code=mycode&client_id=default&client_secret=secret&redirect_uri=http://localhost:8080/callback&code_verifier=" + verifier)
	req = httptest.NewRequest("POST", "/token", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	srv.HandleToken(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 on retry with correct verifier, got %d: %s", w.Code, w.Body.String())
	}
}

func TestTokenEndpoint_PKCE_InvalidVerifierFormat(t *testing.T) {
	srv := newTestServer(t)

	srv.Store.SaveAuthCode("pkcecode", AuthCodeData{
		UserSub:             "user1",
		ClientID:            "default",
		RedirectURI:         "http://localhost:8080/callback",
		Nonce:               "n",
		Scope:               "openid",
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: "S256",
		ExpiresAt:           time.Now().Add(60 * time.Second),
	})

	// Too short (< 43 chars)
	form := strings.NewReader("grant_type=authorization_code&code=pkcecode&client_id=default&client_secret=secret&redirect_uri=http://localhost:8080/callback&code_verifier=tooshort")
	req := httptest.NewRequest("POST", "/token", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	srv.HandleToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for short verifier, got %d", w.Code)
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["error_description"] == "" {
		t.Error("expected error_description for invalid verifier format")
	}
	if !strings.Contains(resp["error_description"], "43-128") {
		t.Errorf("expected description to mention '43-128', got: %s", resp["error_description"])
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

	form := strings.NewReader("grant_type=authorization_code&code=pkcecode&client_id=default&client_secret=secret&redirect_uri=http://localhost:8080/callback&code_verifier=somechallenge-padded-to-43-chars-abcdefghij")
	req := httptest.NewRequest("POST", "/token", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	srv.HandleToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func newTestServerWithPublicClient(t *testing.T) *Server {
	t.Helper()
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfig()
	cfg.Clients = append(cfg.Clients, Client{
		ID:           "public-cli",
		Secret:       "",
		RedirectURIs: []string{"http://127.0.0.1:43212/callback"},
	})
	return &Server{
		Config:  cfg,
		KeyPair: kp,
		Store:   NewStore(),
	}
}

func TestTokenEndpoint_PublicClient_PKCE_S256(t *testing.T) {
	srv := newTestServerWithPublicClient(t)

	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	srv.Store.SaveAuthCode("pubcode", AuthCodeData{
		UserSub:             "user1",
		ClientID:            "public-cli",
		RedirectURI:         "http://127.0.0.1:43212/callback",
		Nonce:               "n",
		Scope:               "openid",
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		ExpiresAt:           time.Now().Add(60 * time.Second),
	})

	form := strings.NewReader("grant_type=authorization_code&code=pubcode&client_id=public-cli&redirect_uri=http://127.0.0.1:43212/callback&code_verifier=" + verifier)
	req := httptest.NewRequest("POST", "/token", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	srv.HandleToken(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestTokenEndpoint_PublicClient_NoPKCE_Rejected(t *testing.T) {
	srv := newTestServerWithPublicClient(t)

	srv.Store.SaveAuthCode("pubcode", AuthCodeData{
		UserSub:     "user1",
		ClientID:    "public-cli",
		RedirectURI: "http://127.0.0.1:43212/callback",
		Nonce:       "n",
		Scope:       "openid",
		ExpiresAt:   time.Now().Add(60 * time.Second),
	})

	form := strings.NewReader("grant_type=authorization_code&code=pubcode&client_id=public-cli&redirect_uri=http://127.0.0.1:43212/callback")
	req := httptest.NewRequest("POST", "/token", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	srv.HandleToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for public client without PKCE, got %d", w.Code)
	}
}

func TestTokenEndpoint_PublicClient_WrongVerifier_Rejected(t *testing.T) {
	srv := newTestServerWithPublicClient(t)

	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	srv.Store.SaveAuthCode("pubcode", AuthCodeData{
		UserSub:             "user1",
		ClientID:            "public-cli",
		RedirectURI:         "http://127.0.0.1:43212/callback",
		Nonce:               "n",
		Scope:               "openid",
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		ExpiresAt:           time.Now().Add(60 * time.Second),
	})

	form := strings.NewReader("grant_type=authorization_code&code=pubcode&client_id=public-cli&redirect_uri=http://127.0.0.1:43212/callback&code_verifier=wrong-verifier-padded-to-43-chars-abcdefghijklm")
	req := httptest.NewRequest("POST", "/token", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	srv.HandleToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestTokenEndpoint_PublicClient_SecretRejected(t *testing.T) {
	srv := newTestServerWithPublicClient(t)

	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	srv.Store.SaveAuthCode("pubcode", AuthCodeData{
		UserSub:             "user1",
		ClientID:            "public-cli",
		RedirectURI:         "http://127.0.0.1:43212/callback",
		Nonce:               "n",
		Scope:               "openid",
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		ExpiresAt:           time.Now().Add(60 * time.Second),
	})

	// Public client must not send client_secret
	form := strings.NewReader("grant_type=authorization_code&code=pubcode&client_id=public-cli&client_secret=anything&redirect_uri=http://127.0.0.1:43212/callback&code_verifier=" + verifier)
	req := httptest.NewRequest("POST", "/token", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	srv.HandleToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for public client with client_secret, got %d", w.Code)
	}
}

func TestTokenEndpoint_PublicClient_BasicAuthRejected(t *testing.T) {
	srv := newTestServerWithPublicClient(t)

	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	srv.Store.SaveAuthCode("pubcode", AuthCodeData{
		UserSub:             "user1",
		ClientID:            "public-cli",
		RedirectURI:         "http://127.0.0.1:43212/callback",
		Nonce:               "n",
		Scope:               "openid",
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		ExpiresAt:           time.Now().Add(60 * time.Second),
	})

	// Public client must not use Basic auth
	form := strings.NewReader("grant_type=authorization_code&code=pubcode&redirect_uri=http://127.0.0.1:43212/callback&code_verifier=" + verifier)
	req := httptest.NewRequest("POST", "/token", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("public-cli", "")
	w := httptest.NewRecorder()

	srv.HandleToken(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for public client with Basic auth, got %d", w.Code)
	}
}

func TestTokenEndpoint_PublicClient_RefreshToken(t *testing.T) {
	srv := newTestServerWithPublicClient(t)

	srv.Store.SaveRefreshToken("pub-rt", RefreshTokenData{
		UserSub:  "user1",
		ClientID: "public-cli",
		Scope:    "openid offline_access",
	})

	form := strings.NewReader("grant_type=refresh_token&refresh_token=pub-rt&client_id=public-cli")
	req := httptest.NewRequest("POST", "/token", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	srv.HandleToken(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestTokenEndpoint_PublicClient_PlainPKCE_Rejected(t *testing.T) {
	srv := newTestServerWithPublicClient(t)

	verifier := "plainverifier1234567890abcdefghijklmnopqrstuvwx"

	srv.Store.SaveAuthCode("pubcode", AuthCodeData{
		UserSub:             "user1",
		ClientID:            "public-cli",
		RedirectURI:         "http://127.0.0.1:43212/callback",
		Nonce:               "n",
		Scope:               "openid",
		CodeChallenge:       verifier,
		CodeChallengeMethod: "plain",
		ExpiresAt:           time.Now().Add(60 * time.Second),
	})

	form := strings.NewReader("grant_type=authorization_code&code=pubcode&client_id=public-cli&redirect_uri=http://127.0.0.1:43212/callback&code_verifier=" + verifier)
	req := httptest.NewRequest("POST", "/token", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	srv.HandleToken(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for public client with plain PKCE, got %d", w.Code)
	}
}

func TestTokenEndpoint_PublicClient_PlainPKCE_AllowedWithConfig(t *testing.T) {
	srv := newTestServerWithPublicClient(t)
	for i := range srv.Config.Clients {
		if srv.Config.Clients[i].ID == "public-cli" {
			srv.Config.Clients[i].AllowPlainCodeChallenge = true
		}
	}

	verifier := "plainverifier1234567890abcdefghijklmnopqrstuvwx"

	srv.Store.SaveAuthCode("pubcode", AuthCodeData{
		UserSub:             "user1",
		ClientID:            "public-cli",
		RedirectURI:         "http://127.0.0.1:43212/callback",
		Nonce:               "n",
		Scope:               "openid",
		CodeChallenge:       verifier,
		CodeChallengeMethod: "plain",
		ExpiresAt:           time.Now().Add(60 * time.Second),
	})

	form := strings.NewReader("grant_type=authorization_code&code=pubcode&client_id=public-cli&redirect_uri=http://127.0.0.1:43212/callback&code_verifier=" + verifier)
	req := httptest.NewRequest("POST", "/token", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	srv.HandleToken(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for public client with plain PKCE when allowed, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAuthorize_PublicClient_PlainPKCE_Rejected(t *testing.T) {
	srv := newTestServerWithPublicClient(t)

	req := httptest.NewRequest("GET", "/authorize?client_id=public-cli&redirect_uri=http://127.0.0.1:43212/callback&response_type=code&scope=openid&code_challenge=somechallenge&code_challenge_method=plain&state=xyz", nil)
	w := httptest.NewRecorder()

	srv.HandleAuthorize(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", w.Code)
	}
	loc, _ := url.Parse(w.Header().Get("Location"))
	if loc.Query().Get("error") != "invalid_request" {
		t.Errorf("expected error=invalid_request, got %s", loc.Query().Get("error"))
	}
	if loc.Query().Get("state") != "xyz" {
		t.Errorf("expected state=xyz, got %s", loc.Query().Get("state"))
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

	form := strings.NewReader("token=atok&token_type_hint=access_token&client_id=default&client_secret=secret")
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

	form := strings.NewReader("token=rt1&token_type_hint=refresh_token&client_id=default&client_secret=secret")
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

	form := strings.NewReader("token=nonexistent&client_id=default&client_secret=secret")
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

	form := strings.NewReader("token=atok&client_id=default&client_secret=secret")
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

	form := strings.NewReader("token=&client_id=default&client_secret=secret")
	req := httptest.NewRequest("POST", "/revoke", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	srv.HandleRevoke(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestRevokeEndpoint_NoAuth(t *testing.T) {
	srv := newTestServer(t)

	form := strings.NewReader("token=atok")
	req := httptest.NewRequest("POST", "/revoke", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	srv.HandleRevoke(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 without client auth, got %d", w.Code)
	}
}

func TestEndSessionEndpoint_Redirect(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest("GET", "/end-session?post_logout_redirect_uri=http://localhost:8080/logged-out&state=abc", nil)
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

func TestEndSessionEndpoint_RedirectWithoutState(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest("GET", "/end-session?post_logout_redirect_uri=http://localhost:8080/logged-out", nil)
	w := httptest.NewRecorder()

	srv.HandleEndSession(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", w.Code)
	}
	loc := w.Header().Get("Location")
	if loc != "http://localhost:8080/logged-out" {
		t.Errorf("expected redirect to logout URI without state, got %s", loc)
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

func TestTokenEndpoint_IDToken_ContainsAzpAndAuthTime(t *testing.T) {
	srv := newTestServer(t)

	srv.Store.SaveAuthCode("claimcode", AuthCodeData{
		UserSub:     "user1",
		ClientID:    "default",
		RedirectURI: "http://localhost:8080/callback",
		Nonce:       "n",
		Scope:       "openid",
		AuthTime:    time.Now(),
		ExpiresAt:   time.Now().Add(60 * time.Second),
	})

	form := strings.NewReader("grant_type=authorization_code&code=claimcode&client_id=default&client_secret=secret&redirect_uri=http://localhost:8080/callback")
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
	parsed, err := jwt.Parse(idTokenStr, func(token *jwt.Token) (any, error) {
		return &srv.KeyPair.PrivateKey.PublicKey, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	claims := parsed.Claims.(jwt.MapClaims)

	azp, ok := claims["azp"].(string)
	if !ok || azp == "" {
		t.Fatal("expected azp claim in id_token")
	}
	if azp != "default" {
		t.Errorf("expected azp=default, got %s", azp)
	}

	authTime, ok := claims["auth_time"].(float64)
	if !ok || authTime == 0 {
		t.Fatal("expected auth_time claim in id_token")
	}
	now := float64(time.Now().Unix())
	if authTime < now-10 || authTime > now+10 {
		t.Errorf("auth_time %v not within 10s of now %v", authTime, now)
	}
}

func TestTokenEndpoint_ResponseHeaders(t *testing.T) {
	srv := newTestServer(t)

	srv.Store.SaveAuthCode("hdrcode", AuthCodeData{
		UserSub:     "user1",
		ClientID:    "default",
		RedirectURI: "http://localhost:8080/callback",
		Nonce:       "n",
		Scope:       "openid",
		ExpiresAt:   time.Now().Add(60 * time.Second),
	})

	form := strings.NewReader("grant_type=authorization_code&code=hdrcode&client_id=default&client_secret=secret&redirect_uri=http://localhost:8080/callback")
	req := httptest.NewRequest("POST", "/token", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	srv.HandleToken(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	ct := w.Header().Get("Content-Type")
	if ct != "application/json;charset=UTF-8" {
		t.Errorf("expected Content-Type application/json;charset=UTF-8, got %q", ct)
	}
	cc := w.Header().Get("Cache-Control")
	if cc != "no-store" {
		t.Errorf("expected Cache-Control no-store, got %q", cc)
	}
	pragma := w.Header().Get("Pragma")
	if pragma != "no-cache" {
		t.Errorf("expected Pragma no-cache, got %q", pragma)
	}
}

func TestTokenEndpoint_ErrorDescriptions(t *testing.T) {
	tests := []struct {
		name        string
		setup       func(srv *Server)
		form        string
		wantDesc    string
	}{
		{
			name:     "expired or invalid code",
			setup:    func(srv *Server) {},
			form:     "grant_type=authorization_code&code=nonexistent&client_id=default&client_secret=secret&redirect_uri=http://localhost:8080/callback",
			wantDesc: "authorization code is invalid or expired",
		},
		{
			name: "redirect_uri mismatch",
			setup: func(srv *Server) {
				srv.Store.SaveAuthCode("code1", AuthCodeData{
					UserSub: "user1", ClientID: "default",
					RedirectURI: "http://localhost:8080/callback",
					ExpiresAt:   time.Now().Add(60 * time.Second),
				})
			},
			form:     "grant_type=authorization_code&code=code1&client_id=default&client_secret=secret&redirect_uri=http://wrong/callback",
			wantDesc: "client_id or redirect_uri mismatch",
		},
		{
			name: "missing code_verifier",
			setup: func(srv *Server) {
				srv.Store.SaveAuthCode("code2", AuthCodeData{
					UserSub: "user1", ClientID: "default",
					RedirectURI:         "http://localhost:8080/callback",
					CodeChallenge:       "challenge",
					CodeChallengeMethod: "S256",
					ExpiresAt:           time.Now().Add(60 * time.Second),
				})
			},
			form:     "grant_type=authorization_code&code=code2&client_id=default&client_secret=secret&redirect_uri=http://localhost:8080/callback",
			wantDesc: "code_verifier is required",
		},
		{
			name: "code_verifier too short",
			setup: func(srv *Server) {
				srv.Store.SaveAuthCode("code3", AuthCodeData{
					UserSub: "user1", ClientID: "default",
					RedirectURI:         "http://localhost:8080/callback",
					CodeChallenge:       "challenge",
					CodeChallengeMethod: "S256",
					ExpiresAt:           time.Now().Add(60 * time.Second),
				})
			},
			form:     "grant_type=authorization_code&code=code3&client_id=default&client_secret=secret&redirect_uri=http://localhost:8080/callback&code_verifier=tooshort",
			wantDesc: "43-128",
		},
		{
			name: "PKCE verification failed",
			setup: func(srv *Server) {
				srv.Store.SaveAuthCode("code4", AuthCodeData{
					UserSub: "user1", ClientID: "default",
					RedirectURI:         "http://localhost:8080/callback",
					CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
					CodeChallengeMethod: "S256",
					ExpiresAt:           time.Now().Add(60 * time.Second),
				})
			},
			form:     "grant_type=authorization_code&code=code4&client_id=default&client_secret=secret&redirect_uri=http://localhost:8080/callback&code_verifier=wrongverifier1234567890abcdefghijklmnopqrstuvwx",
			wantDesc: "PKCE verification failed",
		},
		{
			name: "invalid refresh token",
			setup: func(srv *Server) {},
			form:     "grant_type=refresh_token&refresh_token=nonexistent&client_id=default&client_secret=secret",
			wantDesc: "refresh token is invalid or revoked",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newTestServer(t)
			tt.setup(srv)

			req := httptest.NewRequest("POST", "/token", strings.NewReader(tt.form))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()
			srv.HandleToken(w, req)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d", w.Code)
			}
			var resp map[string]string
			json.NewDecoder(w.Body).Decode(&resp)
			if resp["error"] != "invalid_grant" {
				t.Errorf("expected error=invalid_grant, got %s", resp["error"])
			}
			if !strings.Contains(resp["error_description"], tt.wantDesc) {
				t.Errorf("expected error_description containing %q, got %q", tt.wantDesc, resp["error_description"])
			}
		})
	}
}

func TestAuthorizeEndpoint_PromptNone(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest("GET", "/authorize?client_id=default&redirect_uri=http://localhost:8080/callback&response_type=code&scope=openid&state=xyz&prompt=none", nil)
	w := httptest.NewRecorder()

	srv.HandleAuthorize(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", w.Code)
	}
	loc, _ := url.Parse(w.Header().Get("Location"))
	if loc.Query().Get("error") != "login_required" {
		t.Errorf("expected error=login_required, got %s", loc.Query().Get("error"))
	}
	if loc.Query().Get("state") != "xyz" {
		t.Errorf("expected state=xyz, got %s", loc.Query().Get("state"))
	}
}

func TestAuthorizeEndpoint_POST(t *testing.T) {
	srv := newTestServer(t)

	form := strings.NewReader("client_id=default&redirect_uri=http://localhost:8080/callback&response_type=code&scope=openid&state=xyz&nonce=abc")
	req := httptest.NewRequest("POST", "/authorize", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	srv.HandleAuthorize(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Alice") {
		t.Error("expected picker rendered with Alice")
	}
}

func TestAuthorizeEndpoint_InvalidCodeChallengeMethod(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest("GET", "/authorize?client_id=default&redirect_uri=http://localhost:8080/callback&response_type=code&scope=openid&code_challenge=abc&code_challenge_method=bogus", nil)
	w := httptest.NewRecorder()

	srv.HandleAuthorize(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", w.Code)
	}
	loc, _ := url.Parse(w.Header().Get("Location"))
	if loc.Query().Get("error") != "invalid_request" {
		t.Errorf("expected error=invalid_request, got %s", loc.Query().Get("error"))
	}
}

func TestAuthorizeCallback_InvalidClient(t *testing.T) {
	srv := newTestServer(t)

	form := strings.NewReader("sub=user1&client_id=bogus&redirect_uri=http://localhost:8080/callback")
	req := httptest.NewRequest("POST", "/authorize/callback", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	srv.HandleAuthorizeCallback(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestAuthorizeCallback_InvalidRedirectURI(t *testing.T) {
	srv := newTestServer(t)

	form := strings.NewReader("sub=user1&client_id=default&redirect_uri=http://evil.com/cb")
	req := httptest.NewRequest("POST", "/authorize/callback", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	srv.HandleAuthorizeCallback(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestTokenEndpoint_BasicAuth_URLDecoded(t *testing.T) {
	srv := newTestServer(t)
	srv.Config.Clients = append(srv.Config.Clients, Client{
		ID:           "client+id",
		Secret:       "sec ret!",
		RedirectURIs: []string{"http://localhost:8080/callback"},
	})

	srv.Store.SaveAuthCode("urlcode", AuthCodeData{
		UserSub:     "user1",
		ClientID:    "client+id",
		RedirectURI: "http://localhost:8080/callback",
		Scope:       "openid",
		ExpiresAt:   time.Now().Add(60 * time.Second),
	})

	form := strings.NewReader("grant_type=authorization_code&code=urlcode&redirect_uri=http://localhost:8080/callback")
	req := httptest.NewRequest("POST", "/token", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	encoded := base64.StdEncoding.EncodeToString([]byte(url.QueryEscape("client+id") + ":" + url.QueryEscape("sec ret!")))
	req.Header.Set("Authorization", "Basic "+encoded)
	w := httptest.NewRecorder()

	srv.HandleToken(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestTokenEndpoint_BasicAuth_WWWAuthenticateHeader(t *testing.T) {
	srv := newTestServer(t)

	form := strings.NewReader("grant_type=authorization_code&code=x&redirect_uri=http://x")
	req := httptest.NewRequest("POST", "/token", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("default", "wrongsecret")
	w := httptest.NewRecorder()

	srv.HandleToken(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
	if got := w.Header().Get("WWW-Authenticate"); got != `Basic realm="oidc-mock"` {
		t.Errorf("expected WWW-Authenticate header, got %q", got)
	}
}

func TestTokenEndpoint_AuthTimePreservedOnRefresh(t *testing.T) {
	srv := newTestServer(t)
	authTime := time.Now().Add(-2 * time.Hour).Truncate(time.Second)

	srv.Store.SaveAuthCode("authtimecode", AuthCodeData{
		UserSub:     "user1",
		ClientID:    "default",
		RedirectURI: "http://localhost:8080/callback",
		Scope:       "openid offline_access",
		AuthTime:    authTime,
		ExpiresAt:   time.Now().Add(60 * time.Second),
	})

	form := strings.NewReader("grant_type=authorization_code&code=authtimecode&client_id=default&client_secret=secret&redirect_uri=http://localhost:8080/callback")
	req := httptest.NewRequest("POST", "/token", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	srv.HandleToken(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)
	refreshToken, _ := resp["refresh_token"].(string)
	if refreshToken == "" {
		t.Fatal("expected refresh_token in response")
	}

	refreshForm := strings.NewReader("grant_type=refresh_token&refresh_token=" + refreshToken + "&client_id=default&client_secret=secret")
	req2 := httptest.NewRequest("POST", "/token", refreshForm)
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w2 := httptest.NewRecorder()
	srv.HandleToken(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w2.Code, w2.Body.String())
	}

	var resp2 map[string]any
	json.Unmarshal(w2.Body.Bytes(), &resp2)
	idTokenStr, _ := resp2["id_token"].(string)
	parsed, err := jwt.Parse(idTokenStr, func(token *jwt.Token) (any, error) {
		return &srv.KeyPair.PrivateKey.PublicKey, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	claims := parsed.Claims.(jwt.MapClaims)
	gotAuthTime, ok := claims["auth_time"].(float64)
	if !ok {
		t.Fatal("expected auth_time claim in refreshed id_token")
	}
	if int64(gotAuthTime) != authTime.Unix() {
		t.Errorf("expected auth_time=%d (preserved from original login), got %d", authTime.Unix(), int64(gotAuthTime))
	}
}

func TestUserinfoEndpoint_BearerLowercase(t *testing.T) {
	srv := newTestServer(t)
	srv.Store.SaveAccessToken("atok", AccessTokenData{UserSub: "user1", Scope: "openid"})

	req := httptest.NewRequest("GET", "/userinfo", nil)
	req.Header.Set("Authorization", "bearer atok")
	w := httptest.NewRecorder()

	srv.HandleUserinfo(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestTokenEndpoint_JWTAccessToken(t *testing.T) {
	srv := newTestServer(t)

	srv.Store.SaveAuthCode("jwtcode", AuthCodeData{
		UserSub:     "user1",
		ClientID:    "default",
		RedirectURI: "http://localhost:8080/callback",
		Scope:       "openid email",
		ExpiresAt:   time.Now().Add(60 * time.Second),
	})

	form := strings.NewReader("grant_type=authorization_code&code=jwtcode&client_id=default&client_secret=secret&redirect_uri=http://localhost:8080/callback")
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
	accessToken, _ := resp["access_token"].(string)
	if accessToken == "" {
		t.Fatal("expected access_token")
	}

	claims := jwt.MapClaims{}
	parsed, err := jwt.ParseWithClaims(accessToken, claims, func(token *jwt.Token) (any, error) {
		return &srv.KeyPair.PrivateKey.PublicKey, nil
	})
	if err != nil {
		t.Fatalf("failed to parse/verify access token JWT: %v", err)
	}
	if typ, _ := parsed.Header["typ"].(string); typ != "at+jwt" {
		t.Errorf("expected header typ=at+jwt, got %v", parsed.Header["typ"])
	}
	if kid, _ := parsed.Header["kid"].(string); kid != srv.KeyPair.KID {
		t.Errorf("expected header kid=%s, got %v", srv.KeyPair.KID, parsed.Header["kid"])
	}
	if claims["iss"] != "http://localhost:8080" {
		t.Errorf("expected iss claim, got %v", claims["iss"])
	}
	if claims["sub"] != "user1" {
		t.Errorf("expected sub=user1, got %v", claims["sub"])
	}
	aud, ok := claims["aud"].([]any)
	if !ok || len(aud) != 1 || aud[0] != "default" {
		t.Errorf("expected aud=[default], got %v", claims["aud"])
	}
	if claims["client_id"] != "default" {
		t.Errorf("expected client_id=default, got %v", claims["client_id"])
	}
	if claims["scope"] != "openid email" {
		t.Errorf("expected scope=openid email, got %v", claims["scope"])
	}
	if claims["exp"] == nil {
		t.Error("expected exp claim")
	}
	if claims["iat"] == nil {
		t.Error("expected iat claim")
	}
}

func TestAccessTokenStore_Expiry(t *testing.T) {
	store := NewStore()

	store.SaveAccessToken("expired", AccessTokenData{
		UserSub:   "user1",
		ClientID:  "default",
		Scope:     "openid",
		ExpiresAt: time.Now().Add(-time.Minute),
	})
	if _, ok := store.GetAccessToken("expired"); ok {
		t.Error("expected expired access token to be rejected")
	}

	store.SaveAccessToken("valid", AccessTokenData{
		UserSub:   "user1",
		ClientID:  "default",
		Scope:     "openid",
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if _, ok := store.GetAccessToken("valid"); !ok {
		t.Error("expected non-expired access token to be accepted")
	}
}

func TestValidRedirectURI_LoopbackPortFlexibility(t *testing.T) {
	srv := newTestServer(t)
	srv.Config.Clients = append(srv.Config.Clients, Client{
		ID:           "loopback-cli",
		Secret:       "sec",
		RedirectURIs: []string{"http://127.0.0.1:8080/callback"},
	})
	localhostClient := srv.findClient("default")
	loopbackClient := srv.findClient("loopback-cli")

	if !srv.validRedirectURI(localhostClient, "http://localhost:9999/callback") {
		t.Error("expected localhost redirect with different port to be accepted")
	}
	if !srv.validRedirectURI(loopbackClient, "http://127.0.0.1:43212/callback") {
		t.Error("expected 127.0.0.1 redirect with different port to be accepted")
	}
	if srv.validRedirectURI(localhostClient, "http://localhost:8080/other") {
		t.Error("expected different path to be rejected even on loopback")
	}
	if srv.validRedirectURI(localhostClient, "http://example.com:8080/callback") {
		t.Error("expected non-loopback host mismatch to be rejected")
	}
}

func TestValidRedirectURI_NonLoopbackRequiresExactMatch(t *testing.T) {
	srv := newTestServer(t)
	srv.Config.Clients = append(srv.Config.Clients, Client{
		ID:           "remote-cli",
		Secret:       "sec",
		RedirectURIs: []string{"https://example.com:8080/callback"},
	})
	client := srv.findClient("remote-cli")

	if srv.validRedirectURI(client, "https://example.com:9999/callback") {
		t.Error("expected non-loopback host with different port to be rejected")
	}
	if !srv.validRedirectURI(client, "https://example.com:8080/callback") {
		t.Error("expected exact match to be accepted")
	}
}

func TestTokenEndpoint_BasicAuth_InvalidSecret_Revoke(t *testing.T) {
	srv := newTestServer(t)

	form := strings.NewReader("token=sometoken")
	req := httptest.NewRequest("POST", "/revoke", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("default", "wrongsecret")
	w := httptest.NewRecorder()

	srv.HandleRevoke(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
	if got := w.Header().Get("WWW-Authenticate"); got != `Basic realm="oidc-mock"` {
		t.Errorf("expected WWW-Authenticate header, got %q", got)
	}
}

func TestTokenEndpoint_PublicClient_EmptyClientSecretAccepted(t *testing.T) {
	srv := newTestServerWithPublicClient(t)

	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	srv.Store.SaveAuthCode("emptysecretcode", AuthCodeData{
		UserSub:             "user1",
		ClientID:            "public-cli",
		RedirectURI:         "http://127.0.0.1:43212/callback",
		Scope:               "openid",
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		ExpiresAt:           time.Now().Add(60 * time.Second),
	})

	form := strings.NewReader("grant_type=authorization_code&code=emptysecretcode&client_id=public-cli&client_secret=&redirect_uri=http://127.0.0.1:43212/callback&code_verifier=" + verifier)
	req := httptest.NewRequest("POST", "/token", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	srv.HandleToken(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for empty client_secret on public client, got %d: %s", w.Code, w.Body.String())
	}
}

func TestRevokeEndpoint_RefreshTokenCascadesToAccessToken(t *testing.T) {
	srv := newTestServer(t)

	srv.Store.SaveAuthCode("cascadecode", AuthCodeData{
		UserSub:     "user1",
		ClientID:    "default",
		RedirectURI: "http://localhost:8080/callback",
		Scope:       "openid offline_access",
		ExpiresAt:   time.Now().Add(60 * time.Second),
	})

	form := strings.NewReader("grant_type=authorization_code&code=cascadecode&client_id=default&client_secret=secret&redirect_uri=http://localhost:8080/callback")
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
	accessToken, _ := resp["access_token"].(string)
	refreshToken, _ := resp["refresh_token"].(string)
	if accessToken == "" || refreshToken == "" {
		t.Fatal("expected access_token and refresh_token")
	}

	// Sanity: access token works before revocation
	uiReq := httptest.NewRequest("GET", "/userinfo", nil)
	uiReq.Header.Set("Authorization", "Bearer "+accessToken)
	uiW := httptest.NewRecorder()
	srv.HandleUserinfo(uiW, uiReq)
	if uiW.Code != http.StatusOK {
		t.Fatalf("expected 200 before revoke, got %d", uiW.Code)
	}

	revokeForm := strings.NewReader("token=" + refreshToken + "&token_type_hint=refresh_token&client_id=default&client_secret=secret")
	revokeReq := httptest.NewRequest("POST", "/revoke", revokeForm)
	revokeReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	revokeW := httptest.NewRecorder()
	srv.HandleRevoke(revokeW, revokeReq)
	if revokeW.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", revokeW.Code)
	}

	uiReq2 := httptest.NewRequest("GET", "/userinfo", nil)
	uiReq2.Header.Set("Authorization", "Bearer "+accessToken)
	uiW2 := httptest.NewRecorder()
	srv.HandleUserinfo(uiW2, uiReq2)
	if uiW2.Code != http.StatusUnauthorized {
		t.Errorf("expected access token to be invalidated after refresh token revocation, got %d", uiW2.Code)
	}
}

func TestDiscoveryEndpoint_ResponseModesSupported(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest("GET", "/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()
	srv.HandleDiscovery(w, req)

	var doc map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	modes, ok := doc["response_modes_supported"].([]any)
	if !ok || len(modes) != 1 || modes[0] != "query" {
		t.Errorf("expected response_modes_supported=[query], got %v", doc["response_modes_supported"])
	}
}

func TestAuthorizeEndpoint_UnsupportedResponseMode(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest("GET", "/authorize?client_id=default&redirect_uri=http://localhost:8080/callback&response_type=code&scope=openid&state=xyz&response_mode=form_post", nil)
	w := httptest.NewRecorder()

	srv.HandleAuthorize(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", w.Code)
	}
	loc, _ := url.Parse(w.Header().Get("Location"))
	if loc.Query().Get("error") != "invalid_request" {
		t.Errorf("expected error=invalid_request, got %s", loc.Query().Get("error"))
	}
	if loc.Query().Get("state") != "xyz" {
		t.Errorf("expected state=xyz, got %s", loc.Query().Get("state"))
	}
}

func TestAuthorizeEndpoint_RequestParamNotSupported(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest("GET", "/authorize?client_id=default&redirect_uri=http://localhost:8080/callback&response_type=code&scope=openid&state=xyz&request=xxx", nil)
	w := httptest.NewRecorder()

	srv.HandleAuthorize(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", w.Code)
	}
	loc, _ := url.Parse(w.Header().Get("Location"))
	if loc.Query().Get("error") != "request_not_supported" {
		t.Errorf("expected error=request_not_supported, got %s", loc.Query().Get("error"))
	}
}

func TestAuthorizeEndpoint_RequestURIParamNotSupported(t *testing.T) {
	srv := newTestServer(t)

	req := httptest.NewRequest("GET", "/authorize?client_id=default&redirect_uri=http://localhost:8080/callback&response_type=code&scope=openid&state=xyz&request_uri=xxx", nil)
	w := httptest.NewRecorder()

	srv.HandleAuthorize(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", w.Code)
	}
	loc, _ := url.Parse(w.Header().Get("Location"))
	if loc.Query().Get("error") != "request_uri_not_supported" {
		t.Errorf("expected error=request_uri_not_supported, got %s", loc.Query().Get("error"))
	}
}
