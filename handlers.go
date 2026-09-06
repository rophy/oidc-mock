package main

import (
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

//go:embed templates
var templateFS embed.FS

var pickerTmpl = template.Must(template.ParseFS(templateFS, "templates/picker.html"))
var passwordTmpl = template.Must(template.ParseFS(templateFS, "templates/password.html"))

type passwordData struct {
	User                User
	ClientID            string
	RedirectURI         string
	State               string
	Nonce               string
	Scope               string
	CodeChallenge       string
	CodeChallengeMethod string
	Error               string
}

type Server struct {
	Config  Config
	KeyPair *KeyPair
	Store   *Store
}

func (s *Server) HandleDiscovery(w http.ResponseWriter, r *http.Request) {
	doc := map[string]any{
		"issuer":                                s.Config.Issuer,
		"authorization_endpoint":                s.Config.Issuer + "/authorize",
		"token_endpoint":                        s.Config.Issuer + "/token",
		"jwks_uri":                              s.Config.Issuer + "/jwks",
		"userinfo_endpoint":                     s.Config.Issuer + "/userinfo",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "email", "profile", "offline_access"},
		"revocation_endpoint":                   s.Config.Issuer + "/revoke",
		"end_session_endpoint":                  s.Config.Issuer + "/end-session",
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
		"claims_supported":                      []string{"sub", "iss", "aud", "exp", "iat", "nonce", "email", "email_verified", "name", "at_hash"},
		"code_challenge_methods_supported":      []string{"S256", "plain"},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(doc)
}

func (s *Server) HandleJWKS(w http.ResponseWriter, r *http.Request) {
	pub := &s.KeyPair.PrivateKey.PublicKey
	jwks := map[string]any{
		"keys": []map[string]any{
			{
				"kty": "RSA",
				"alg": "RS256",
				"use": "sig",
				"kid": s.KeyPair.KID,
				"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
			},
		},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jwks)
}

type pickerData struct {
	Users               []User
	ClientID            string
	RedirectURI         string
	State               string
	Nonce               string
	Scope               string
	CodeChallenge       string
	CodeChallengeMethod string
}

func (s *Server) HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("client_id")
	redirectURI := r.URL.Query().Get("redirect_uri")
	state := r.URL.Query().Get("state")
	nonce := r.URL.Query().Get("nonce")
	scope := r.URL.Query().Get("scope")

	responseType := r.URL.Query().Get("response_type")
	if responseType != "code" {
		http.Error(w, "unsupported response_type: only 'code' is supported", http.StatusBadRequest)
		return
	}

	client := s.findClient(clientID)
	if client == nil {
		http.Error(w, fmt.Sprintf("unknown client_id: %s", clientID), http.StatusBadRequest)
		return
	}
	if !s.validRedirectURI(client, redirectURI) {
		http.Error(w, fmt.Sprintf("invalid redirect_uri: %s (allowed: %v)", redirectURI, client.RedirectURIs), http.StatusBadRequest)
		return
	}

	codeChallenge := r.URL.Query().Get("code_challenge")
	codeChallengeMethod := r.URL.Query().Get("code_challenge_method")
	if codeChallenge != "" && codeChallengeMethod == "" {
		codeChallengeMethod = "plain"
	}

	w.Header().Set("Content-Type", "text/html")
	pickerTmpl.Execute(w, pickerData{
		Users:               s.Config.Users,
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		State:               state,
		Nonce:               nonce,
		Scope:               scope,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
	})
}

func (s *Server) HandleAuthorizeCallback(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form data", http.StatusBadRequest)
		return
	}

	sub := r.FormValue("sub")
	clientID := r.FormValue("client_id")
	redirectURI := r.FormValue("redirect_uri")
	state := r.FormValue("state")
	nonce := r.FormValue("nonce")
	scope := r.FormValue("scope")
	codeChallenge := r.FormValue("code_challenge")
	codeChallengeMethod := r.FormValue("code_challenge_method")

	user := s.findUser(sub)
	if user == nil {
		http.Error(w, "unknown user", http.StatusBadRequest)
		return
	}

	if user.Password != "" {
		password := r.FormValue("password")
		if password == "" {
			w.Header().Set("Content-Type", "text/html")
			passwordTmpl.Execute(w, passwordData{
				User:                *user,
				ClientID:            clientID,
				RedirectURI:         redirectURI,
				State:               state,
				Nonce:               nonce,
				Scope:               scope,
				CodeChallenge:       codeChallenge,
				CodeChallengeMethod: codeChallengeMethod,
			})
			return
		}
		if password != user.Password {
			w.Header().Set("Content-Type", "text/html")
			passwordTmpl.Execute(w, passwordData{
				User:                *user,
				ClientID:            clientID,
				RedirectURI:         redirectURI,
				State:               state,
				Nonce:               nonce,
				Scope:               scope,
				CodeChallenge:       codeChallenge,
				CodeChallengeMethod: codeChallengeMethod,
				Error:               "Invalid password",
			})
			return
		}
	}

	code := GenerateRandomString(16)
	s.Store.SaveAuthCode(code, AuthCodeData{
		UserSub:             sub,
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		Nonce:               nonce,
		Scope:               scope,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		ExpiresAt:           time.Now().Add(60 * time.Second),
	})

	u, _ := url.Parse(redirectURI)
	q := u.Query()
	q.Set("code", code)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (s *Server) findClient(id string) *Client {
	for i := range s.Config.Clients {
		if s.Config.Clients[i].ID == id {
			return &s.Config.Clients[i]
		}
	}
	return nil
}

func (s *Server) validRedirectURI(c *Client, uri string) bool {
	for _, allowed := range c.RedirectURIs {
		if allowed == uri {
			return true
		}
	}
	return false
}

func (s *Server) HandleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form data", http.StatusBadRequest)
		return
	}

	grantType := r.FormValue("grant_type")

	clientID, clientSecret, basicOk := r.BasicAuth()
	if !basicOk {
		clientID = r.FormValue("client_id")
		clientSecret = r.FormValue("client_secret")
	}

	client := s.findClient(clientID)
	if client == nil {
		jsonError(w, "invalid_client", http.StatusUnauthorized)
		return
	}
	isPublicClient := client.Secret == ""
	if !isPublicClient && client.Secret != clientSecret {
		jsonError(w, "invalid_client", http.StatusUnauthorized)
		return
	}

	var userSub, nonce, scope string

	switch grantType {
	case "authorization_code":
		code := r.FormValue("code")
		redirectURI := r.FormValue("redirect_uri")

		codeData, ok := s.Store.ConsumeAuthCode(code)
		if !ok {
			jsonError(w, "invalid_grant", http.StatusBadRequest)
			return
		}
		if codeData.ClientID != clientID || codeData.RedirectURI != redirectURI {
			jsonError(w, "invalid_grant", http.StatusBadRequest)
			return
		}
		if isPublicClient && codeData.CodeChallenge == "" {
			jsonError(w, "invalid_grant", http.StatusBadRequest)
			return
		}
		if codeData.CodeChallenge != "" {
			codeVerifier := r.FormValue("code_verifier")
			if codeVerifier == "" {
				jsonError(w, "invalid_grant", http.StatusBadRequest)
				return
			}
			if !verifyPKCE(codeData.CodeChallenge, codeData.CodeChallengeMethod, codeVerifier) {
				jsonError(w, "invalid_grant", http.StatusBadRequest)
				return
			}
		}
		userSub = codeData.UserSub
		nonce = codeData.Nonce
		scope = codeData.Scope

	case "refresh_token":
		rt := r.FormValue("refresh_token")
		rtData, ok := s.Store.GetRefreshToken(rt)
		if !ok {
			jsonError(w, "invalid_grant", http.StatusBadRequest)
			return
		}
		if rtData.ClientID != clientID {
			jsonError(w, "invalid_grant", http.StatusBadRequest)
			return
		}
		userSub = rtData.UserSub
		scope = rtData.Scope

	default:
		jsonError(w, "unsupported_grant_type", http.StatusBadRequest)
		return
	}

	user := s.findUser(userSub)
	if user == nil {
		jsonError(w, "invalid_grant", http.StatusBadRequest)
		return
	}

	// Generate access token first
	accessToken := GenerateRandomString(32)
	s.Store.SaveAccessToken(accessToken, AccessTokenData{UserSub: user.Sub, Scope: scope})

	// Compute at_hash: SHA-256 hash of access token, left half, base64url-encoded
	atHashBytes := sha256.Sum256([]byte(accessToken))
	atHash := base64.RawURLEncoding.EncodeToString(atHashBytes[:16])

	now := time.Now()
	idTokenClaims := IDTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.Config.Issuer,
			Subject:   user.Sub,
			Audience:  jwt.ClaimStrings{clientID},
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
		Nonce:  nonce,
		AtHash: atHash,
	}
	if hasScope(scope, "email") {
		idTokenClaims.Email = user.Email
		v := true
		idTokenClaims.EmailVerified = &v
	}
	if hasScope(scope, "profile") {
		idTokenClaims.Name = user.Name
		idTokenClaims.Custom = user.Claims
	}

	idToken, err := s.KeyPair.SignIDToken(idTokenClaims)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	resp := map[string]any{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   3600,
		"id_token":     idToken,
		"scope":        scope,
	}

	if hasScope(scope, "offline_access") {
		refreshToken := GenerateRandomString(32)
		s.Store.SaveRefreshToken(refreshToken, RefreshTokenData{
			UserSub:  user.Sub,
			ClientID: clientID,
			Scope:    scope,
		})
		resp["refresh_token"] = refreshToken
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(resp)
}

func hasScope(scope, target string) bool {
	for _, s := range strings.Fields(scope) {
		if s == target {
			return true
		}
	}
	return false
}

func (s *Server) findUser(sub string) *User {
	for i := range s.Config.Users {
		if s.Config.Users[i].Sub == sub {
			return &s.Config.Users[i]
		}
	}
	return nil
}

func (s *Server) HandleUserinfo(w http.ResponseWriter, r *http.Request) {
	var token string

	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		token = strings.TrimPrefix(auth, "Bearer ")
	} else if r.Method == http.MethodPost {
		r.ParseForm()
		token = r.FormValue("access_token")
	}

	if token == "" {
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, "missing bearer token", http.StatusUnauthorized)
		return
	}

	data, ok := s.Store.GetAccessToken(token)
	if !ok {
		w.Header().Set("WWW-Authenticate", "Bearer error=\"invalid_token\"")
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}

	user := s.findUser(data.UserSub)
	if user == nil {
		http.Error(w, "user not found", http.StatusInternalServerError)
		return
	}

	claims := map[string]any{
		"sub": user.Sub,
	}
	if hasScope(data.Scope, "email") {
		claims["email"] = user.Email
		claims["email_verified"] = true
	}
	if hasScope(data.Scope, "profile") {
		claims["name"] = user.Name
		for k, v := range user.Claims {
			claims[k] = v
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(claims)
}

func (s *Server) HandleRevoke(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form data", http.StatusBadRequest)
		return
	}

	token := r.FormValue("token")
	if token == "" {
		w.WriteHeader(http.StatusOK)
		return
	}

	tokenType := r.FormValue("token_type_hint")
	if tokenType == "refresh_token" {
		s.Store.RevokeRefreshToken(token)
	} else {
		s.Store.RevokeAccessToken(token)
		s.Store.RevokeRefreshToken(token)
	}

	w.WriteHeader(http.StatusOK)
}

func (s *Server) HandleEndSession(w http.ResponseWriter, r *http.Request) {
	redirectURI := r.URL.Query().Get("post_logout_redirect_uri")
	if redirectURI == "" {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("logged out"))
		return
	}

	state := r.URL.Query().Get("state")
	u, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "invalid post_logout_redirect_uri", http.StatusBadRequest)
		return
	}
	if state != "" {
		q := u.Query()
		q.Set("state", state)
		u.RawQuery = q.Encode()
	}
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func jsonError(w http.ResponseWriter, errCode string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": errCode})
}

func verifyPKCE(challenge, method, verifier string) bool {
	switch method {
	case "S256":
		h := sha256.Sum256([]byte(verifier))
		computed := base64.RawURLEncoding.EncodeToString(h[:])
		return computed == challenge
	case "plain":
		return verifier == challenge
	default:
		return false
	}
}
