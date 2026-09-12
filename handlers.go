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
	ResponseMode        string
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
		"response_modes_supported":              []string{"query", "form_post"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "email", "profile", "offline_access"},
		"revocation_endpoint":                   s.Config.Issuer + "/revoke",
		"end_session_endpoint":                  s.Config.Issuer + "/end-session",
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
		"claims_supported":                      []string{"sub", "iss", "aud", "exp", "iat", "nonce", "email", "email_verified", "name", "at_hash", "azp", "auth_time"},
		"code_challenge_methods_supported":      []string{"S256", "plain"},
		"request_parameter_supported":           false,
		"request_uri_parameter_supported":       false,
		"claims_parameter_supported":            false,
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
	ResponseMode        string
}

func redirectError(w http.ResponseWriter, r *http.Request, redirectURI, state, errCode, errDesc string) {
	responseMode := r.FormValue("response_mode")
	params := url.Values{}
	params.Set("error", errCode)
	params.Set("error_description", errDesc)
	if state != "" {
		params.Set("state", state)
	}
	if responseMode == "form_post" {
		renderFormPost(w, redirectURI, params)
		return
	}
	u, _ := url.Parse(redirectURI)
	q := u.Query()
	for k, vs := range params {
		for _, v := range vs {
			q.Set(k, v)
		}
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func renderFormPost(w http.ResponseWriter, action string, params url.Values) {
	w.Header().Set("Content-Type", "text/html;charset=UTF-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	fmt.Fprintf(w, `<!DOCTYPE html><html><body onload="document.forms[0].submit()"><form method="post" action="%s">`, template.HTMLEscapeString(action))
	for k, vs := range params {
		for _, v := range vs {
			fmt.Fprintf(w, `<input type="hidden" name="%s" value="%s">`, template.HTMLEscapeString(k), template.HTMLEscapeString(v))
		}
	}
	fmt.Fprint(w, `<noscript><button type="submit">Continue</button></noscript></form></body></html>`)
}

func (s *Server) HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form data", http.StatusBadRequest)
		return
	}

	clientID := r.FormValue("client_id")
	redirectURI := r.FormValue("redirect_uri")
	state := r.FormValue("state")
	nonce := r.FormValue("nonce")
	scope := r.FormValue("scope")

	client := s.findClient(clientID)
	if client == nil {
		http.Error(w, fmt.Sprintf("unknown client_id: %s", clientID), http.StatusBadRequest)
		return
	}
	if !s.validRedirectURI(client, redirectURI) {
		http.Error(w, fmt.Sprintf("invalid redirect_uri: %s (allowed: %v)", redirectURI, client.RedirectURIs), http.StatusBadRequest)
		return
	}

	if r.FormValue("request") != "" {
		redirectError(w, r, redirectURI, state, "request_not_supported", "request parameter is not supported")
		return
	}
	if r.FormValue("request_uri") != "" {
		redirectError(w, r, redirectURI, state, "request_uri_not_supported", "request_uri parameter is not supported")
		return
	}

	responseType := r.FormValue("response_type")
	if responseType != "code" {
		redirectError(w, r, redirectURI, state, "unsupported_response_type", "only 'code' is supported")
		return
	}

	responseMode := r.FormValue("response_mode")
	if responseMode != "" && responseMode != "query" && responseMode != "form_post" {
		redirectError(w, r, redirectURI, state, "invalid_request", fmt.Sprintf("unsupported response_mode: %s", responseMode))
		return
	}

	prompt := r.FormValue("prompt")
	if prompt == "none" {
		redirectError(w, r, redirectURI, state, "login_required", "prompt=none but no session")
		return
	}

	codeChallenge := r.FormValue("code_challenge")
	codeChallengeMethod := r.FormValue("code_challenge_method")
	if codeChallenge != "" && codeChallengeMethod == "" {
		codeChallengeMethod = "plain"
	}
	if codeChallenge != "" && codeChallengeMethod != "S256" && codeChallengeMethod != "plain" {
		redirectError(w, r, redirectURI, state, "invalid_request", "unsupported code_challenge_method")
		return
	}
	if client.Secret == "" && codeChallenge != "" && codeChallengeMethod == "plain" && !client.AllowPlainCodeChallenge {
		redirectError(w, r, redirectURI, state, "invalid_request", "public clients must use S256 code_challenge_method")
		return
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
		ResponseMode:        responseMode,
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
	responseMode := r.FormValue("response_mode")

	client := s.findClient(clientID)
	if client == nil || !s.validRedirectURI(client, redirectURI) {
		http.Error(w, "invalid client_id or redirect_uri", http.StatusBadRequest)
		return
	}

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
				ResponseMode:        responseMode,
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
				ResponseMode:        responseMode,
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
		AuthTime:            time.Now(),
		ExpiresAt:           time.Now().Add(60 * time.Second),
	})

	params := url.Values{}
	params.Set("code", code)
	if state != "" {
		params.Set("state", state)
	}
	if responseMode == "form_post" {
		renderFormPost(w, redirectURI, params)
		return
	}
	u, _ := url.Parse(redirectURI)
	q := u.Query()
	for k, vs := range params {
		for _, v := range vs {
			q.Set(k, v)
		}
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

func isLoopbackHost(host string) bool {
	h := strings.Split(host, ":")[0]
	return h == "localhost" || h == "127.0.0.1" || h == "[::1]" || h == "::1"
}

func (s *Server) validRedirectURI(c *Client, uri string) bool {
	for _, allowed := range c.RedirectURIs {
		if allowed == uri {
			return true
		}
		// RFC 8252 §7.3: loopback redirects must allow any port
		allowedU, err1 := url.Parse(allowed)
		uriU, err2 := url.Parse(uri)
		if err1 == nil && err2 == nil && isLoopbackHost(allowedU.Host) && isLoopbackHost(uriU.Host) {
			if allowedU.Scheme == uriU.Scheme && allowedU.Hostname() == uriU.Hostname() && allowedU.Path == uriU.Path {
				return true
			}
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
	if basicOk {
		// RFC 6749 §2.3.1: credentials are application/x-www-form-urlencoded before base64
		clientID, _ = url.QueryUnescape(clientID)
		clientSecret, _ = url.QueryUnescape(clientSecret)
	} else {
		clientID = r.FormValue("client_id")
		clientSecret = r.FormValue("client_secret")
	}

	client := s.findClient(clientID)
	if client == nil {
		if basicOk {
			w.Header().Set("WWW-Authenticate", `Basic realm="oidc-mock"`)
			jsonError(w, "invalid_client", http.StatusUnauthorized)
		} else {
			jsonError(w, "invalid_client", http.StatusBadRequest)
		}
		return
	}
	isPublicClient := client.Secret == ""
	if isPublicClient && !basicOk && r.Form.Has("client_secret") && clientSecret != "" {
		jsonError(w, "invalid_client", http.StatusBadRequest)
		return
	}
	if !isPublicClient && client.Secret != clientSecret {
		if basicOk {
			w.Header().Set("WWW-Authenticate", `Basic realm="oidc-mock"`)
			jsonError(w, "invalid_client", http.StatusUnauthorized)
		} else {
			jsonError(w, "invalid_client", http.StatusBadRequest)
		}
		return
	}

	var userSub, nonce, scope string
	var authTime time.Time

	if grantType == "" {
		jsonError(w, "invalid_request", http.StatusBadRequest, "missing grant_type parameter")
		return
	}

	switch grantType {
	case "authorization_code":
		code := r.FormValue("code")
		redirectURI := r.FormValue("redirect_uri")

		codeData, ok := s.Store.GetAuthCode(code)
		if !ok {
			jsonError(w, "invalid_grant", http.StatusBadRequest, "authorization code is invalid or expired")
			return
		}
		if codeData.ClientID != clientID || codeData.RedirectURI != redirectURI {
			jsonError(w, "invalid_grant", http.StatusBadRequest, "client_id or redirect_uri mismatch")
			return
		}
		if isPublicClient && codeData.CodeChallenge == "" {
			jsonError(w, "invalid_grant", http.StatusBadRequest, "public clients must use PKCE")
			return
		}
		if isPublicClient && codeData.CodeChallengeMethod == "plain" && !client.AllowPlainCodeChallenge {
			jsonError(w, "invalid_grant", http.StatusBadRequest, "public clients must use S256 code_challenge_method")
			return
		}
		if codeData.CodeChallenge != "" {
			codeVerifier := r.FormValue("code_verifier")
			if codeVerifier == "" {
				jsonError(w, "invalid_grant", http.StatusBadRequest, "code_verifier is required when code_challenge was used")
				return
			}
			if !validCodeVerifier(codeVerifier) {
				jsonError(w, "invalid_grant", http.StatusBadRequest, "code_verifier must be 43-128 characters using [A-Za-z0-9._~-] (RFC 7636 Section 4.1)")
				return
			}
			if !verifyPKCE(codeData.CodeChallenge, codeData.CodeChallengeMethod, codeVerifier) {
				jsonError(w, "invalid_grant", http.StatusBadRequest, "PKCE verification failed")
				return
			}
		}
		// Atomically consume to prevent concurrent redemption
		if _, ok := s.Store.ConsumeAuthCode(code); !ok {
			jsonError(w, "invalid_grant", http.StatusBadRequest, "authorization code already consumed")
			return
		}
		userSub = codeData.UserSub
		nonce = codeData.Nonce
		scope = codeData.Scope
		authTime = codeData.AuthTime

	case "refresh_token":
		rt := r.FormValue("refresh_token")
		if rt == "" {
			jsonError(w, "invalid_request", http.StatusBadRequest, "missing refresh_token parameter")
			return
		}
		rtData, ok := s.Store.GetRefreshToken(rt)
		if !ok {
			jsonError(w, "invalid_grant", http.StatusBadRequest, "refresh token is invalid or revoked")
			return
		}
		if rtData.ClientID != clientID {
			jsonError(w, "invalid_grant", http.StatusBadRequest, "refresh token was issued to a different client")
			return
		}
		userSub = rtData.UserSub
		scope = rtData.Scope
		authTime = rtData.AuthTime

	default:
		jsonError(w, "unsupported_grant_type", http.StatusBadRequest)
		return
	}

	user := s.findUser(userSub)
	if user == nil {
		jsonError(w, "invalid_grant", http.StatusBadRequest, "user not found")
		return
	}

	// Generate JWT access token (RFC 9068)
	accessTokenExpiry := time.Now().Add(time.Hour)
	atClaims := jwt.RegisteredClaims{
		Issuer:    s.Config.Issuer,
		Subject:   user.Sub,
		Audience:  jwt.ClaimStrings{clientID},
		ExpiresAt: jwt.NewNumericDate(accessTokenExpiry),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ID:        GenerateRandomString(16),
	}
	atToken := jwt.NewWithClaims(jwt.SigningMethodRS256, struct {
		jwt.RegisteredClaims
		Scope    string `json:"scope,omitempty"`
		ClientID string `json:"client_id"`
	}{atClaims, scope, clientID})
	atToken.Header["kid"] = s.KeyPair.KID
	atToken.Header["typ"] = "at+jwt"
	accessToken, err := atToken.SignedString(s.KeyPair.PrivateKey)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.Store.SaveAccessToken(accessToken, AccessTokenData{UserSub: user.Sub, ClientID: clientID, Scope: scope, ExpiresAt: accessTokenExpiry})

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
		Nonce:    nonce,
		AtHash:   atHash,
		Azp:      clientID,
		AuthTime: jwt.NewNumericDate(authTime),
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
			AuthTime: authTime,
		})
		resp["refresh_token"] = refreshToken
	}

	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
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
	if len(auth) > 7 && strings.EqualFold(auth[:7], "bearer ") {
		token = auth[7:]
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

	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(claims)
}

func (s *Server) HandleRevoke(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form data", http.StatusBadRequest)
		return
	}

	clientID, clientSecret, basicOk := r.BasicAuth()
	if basicOk {
		clientID, _ = url.QueryUnescape(clientID)
		clientSecret, _ = url.QueryUnescape(clientSecret)
	} else {
		clientID = r.FormValue("client_id")
		clientSecret = r.FormValue("client_secret")
	}

	client := s.findClient(clientID)
	if client == nil {
		if basicOk {
			w.Header().Set("WWW-Authenticate", `Basic realm="oidc-mock"`)
			jsonError(w, "invalid_client", http.StatusUnauthorized)
		} else {
			jsonError(w, "invalid_client", http.StatusBadRequest)
		}
		return
	}
	isPublicClient := client.Secret == ""
	if !isPublicClient && client.Secret != clientSecret {
		if basicOk {
			w.Header().Set("WWW-Authenticate", `Basic realm="oidc-mock"`)
			jsonError(w, "invalid_client", http.StatusUnauthorized)
		} else {
			jsonError(w, "invalid_client", http.StatusBadRequest)
		}
		return
	}

	token := r.FormValue("token")
	if token == "" {
		w.WriteHeader(http.StatusOK)
		return
	}

	tokenType := r.FormValue("token_type_hint")
	switch tokenType {
	case "refresh_token":
		s.Store.RevokeRefreshTokenAndAccessTokens(token)
		s.Store.RevokeAccessToken(token) // hint fallback: search all types
	default:
		s.Store.RevokeAccessToken(token)
		s.Store.RevokeRefreshTokenAndAccessTokens(token) // search all types
	}

	w.WriteHeader(http.StatusOK)
}

func (s *Server) HandleEndSession(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form data", http.StatusBadRequest)
		return
	}

	redirectURI := r.FormValue("post_logout_redirect_uri")
	if redirectURI == "" {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("logged out"))
		return
	}

	if !s.validPostLogoutURI(redirectURI) {
		http.Error(w, "invalid post_logout_redirect_uri", http.StatusBadRequest)
		return
	}

	state := r.FormValue("state")
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

func (s *Server) validPostLogoutURI(uri string) bool {
	for _, c := range s.Config.Clients {
		for _, allowed := range c.PostLogoutRedirectURIs {
			if allowed == uri {
				return true
			}
		}
		// Fall back to matching redirect_uris origin for convenience
		for _, allowed := range c.RedirectURIs {
			allowedParsed, err := url.Parse(allowed)
			if err != nil {
				continue
			}
			uriParsed, err := url.Parse(uri)
			if err != nil {
				continue
			}
			if allowedParsed.Scheme == uriParsed.Scheme && allowedParsed.Host == uriParsed.Host {
				return true
			}
		}
	}
	return false
}

func jsonError(w http.ResponseWriter, errCode string, status int, description ...string) {
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	resp := map[string]string{"error": errCode}
	if len(description) > 0 && description[0] != "" {
		resp["error_description"] = description[0]
	}
	json.NewEncoder(w).Encode(resp)
}

func validCodeVerifier(v string) bool {
	if len(v) < 43 || len(v) > 128 {
		return false
	}
	for _, c := range v {
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' || c == '~') {
			return false
		}
	}
	return true
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
