//go:build e2e

package e2e

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/mxschmitt/playwright-go"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

var (
	baseURL     string
	redirectURI string
	browser     playwright.Browser
)

const hostPort = "19090"

func TestMain(m *testing.M) {
	ctx := context.Background()

	baseURL = "http://localhost:" + hostPort
	redirectURI = baseURL + "/callback"

	oidcConfig := fmt.Sprintf(`port: 8080
issuer: %s
clients:
  - id: default
    secret: secret
    redirect_uris:
      - %s
  - id: public-cli
    redirect_uris:
      - %s
users:
  - sub: user1
    email: alice@example.com
    name: Alice
    roles: [admin]
  - sub: user2
    email: bob@example.com
    name: Bob
    roles: [viewer]
  - sub: user3
    email: carol@example.com
    name: Carol
    password: pass123
    roles: [editor]
`, baseURL, redirectURI, redirectURI)

	coverDir := os.Getenv("GOCOVERDIR")
	env := map[string]string{"OIDC_CONFIG": oidcConfig}
	var hostConfigMod func(*container.HostConfig)
	if coverDir != "" {
		env["GOCOVERDIR"] = "/coverdir"
		hostConfigMod = func(hc *container.HostConfig) {
			hc.Mounts = append(hc.Mounts, mount.Mount{
				Type:   mount.TypeBind,
				Source: coverDir,
				Target: "/coverdir",
			})
		}
	}

	ctr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			FromDockerfile: testcontainers.FromDockerfile{
				Context:    "..",
				Dockerfile: "Dockerfile",
				BuildArgs:  map[string]*string{"COVER": ptr("true")},
				BuildOptionsModifier: func(opts *types.ImageBuildOptions) {
					opts.Target = "dev"
				},
			},
			ExposedPorts:       []string{hostPort + ":8080/tcp"},
			Env:                env,
			Cmd:                []string{"serve"},
			WaitingFor:         wait.ForHTTP("/.well-known/openid-configuration").WithPort("8080/tcp"),
			HostConfigModifier: hostConfigMod,
		},
		Started: true,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to start container: %v\n", err)
		os.Exit(1)
	}

	// Install and launch Playwright
	if err := playwright.Install(&playwright.RunOptions{Browsers: []string{"chromium"}}); err != nil {
		fmt.Fprintf(os.Stderr, "failed to install playwright: %v\n", err)
		os.Exit(1)
	}

	pw, err := playwright.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to start playwright: %v\n", err)
		os.Exit(1)
	}

	browser, err = pw.Chromium.Launch(playwright.BrowserTypeLaunchOptions{
		Headless: playwright.Bool(true),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to launch browser: %v\n", err)
		os.Exit(1)
	}

	exitCode := m.Run()

	browser.Close()
	pw.Stop()
	ctr.Terminate(ctx)
	os.Exit(exitCode)
}

func ptr(s string) *string { return &s }

func authorizeURL(clientID, redirURI string) string {
	params := url.Values{
		"client_id":     {clientID},
		"redirect_uri":  {redirURI},
		"response_type": {"code"},
		"scope":         {"openid"},
		"state":         {"teststate"},
		"nonce":         {"testnonce"},
	}
	return baseURL + "/authorize?" + params.Encode()
}

func TestPickerDisplaysUsers(t *testing.T) {
	page, err := browser.NewPage()
	if err != nil {
		t.Fatal(err)
	}
	defer page.Close()

	_, err = page.Goto(authorizeURL("default", redirectURI))
	if err != nil {
		t.Fatal(err)
	}

	heading := page.Locator("h1")
	text, err := heading.TextContent()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "oidc-mock") {
		t.Errorf("expected heading to contain 'oidc-mock', got %q", text)
	}

	aliceVisible, err := page.Locator(".user-name:has-text('Alice')").IsVisible()
	if err != nil {
		t.Fatal(err)
	}
	if !aliceVisible {
		t.Error("expected Alice to be visible")
	}

	aliceEmailVisible, err := page.Locator(".user-email:has-text('alice@example.com')").IsVisible()
	if err != nil {
		t.Fatal(err)
	}
	if !aliceEmailVisible {
		t.Error("expected alice@example.com to be visible")
	}

	bobVisible, err := page.Locator(".user-name:has-text('Bob')").IsVisible()
	if err != nil {
		t.Fatal(err)
	}
	if !bobVisible {
		t.Error("expected Bob to be visible")
	}

	bobEmailVisible, err := page.Locator(".user-email:has-text('bob@example.com')").IsVisible()
	if err != nil {
		t.Fatal(err)
	}
	if !bobEmailVisible {
		t.Error("expected bob@example.com to be visible")
	}
}

func TestFullLoginFlow(t *testing.T) {
	page, err := browser.NewPage()
	if err != nil {
		t.Fatal(err)
	}
	defer page.Close()

	_, err = page.Goto(authorizeURL("default", redirectURI))
	if err != nil {
		t.Fatal(err)
	}

	// Click Alice's card
	aliceButton := page.Locator("button.user-card:has-text('Alice')")
	if err := aliceButton.Click(); err != nil {
		t.Fatal(err)
	}

	// Wait for navigation to callback URL (will 404 but URL will have code)
	if err := page.WaitForURL("**/callback**"); err != nil {
		t.Fatal(err)
	}

	currentURL := page.URL()
	parsed, err := url.Parse(currentURL)
	if err != nil {
		t.Fatal(err)
	}

	code := parsed.Query().Get("code")
	if code == "" {
		t.Fatalf("expected code in URL, got: %s", currentURL)
	}

	state := parsed.Query().Get("state")
	if state != "teststate" {
		t.Errorf("expected state=teststate, got %s", state)
	}

	// Exchange code for tokens via HTTP
	tokenForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {"default"},
		"client_secret": {"secret"},
		"redirect_uri":  {redirectURI},
	}
	resp, err := http.PostForm(baseURL+"/token", tokenForm)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token exchange: expected 200, got %d", resp.StatusCode)
	}

	var tokenResp map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		t.Fatal(err)
	}

	if tokenResp["id_token"] == nil || tokenResp["id_token"] == "" {
		t.Error("expected non-empty id_token")
	}
	if tokenResp["access_token"] == nil || tokenResp["access_token"] == "" {
		t.Error("expected non-empty access_token")
	}
	if tokenResp["token_type"] != "Bearer" {
		t.Errorf("expected token_type=Bearer, got %v", tokenResp["token_type"])
	}
}

func TestInvalidClientShowsError(t *testing.T) {
	page, err := browser.NewPage()
	if err != nil {
		t.Fatal(err)
	}
	defer page.Close()

	resp, err := page.Goto(authorizeURL("nonexistent", redirectURI))
	if err != nil {
		t.Fatal(err)
	}

	if resp.Status() != 400 {
		t.Errorf("expected status 400, got %d", resp.Status())
	}

	content, err := page.Content()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(content, "unknown client_id") {
		t.Errorf("expected error message about unknown client_id, got: %s", content)
	}
}

func TestInvalidRedirectURIShowsError(t *testing.T) {
	page, err := browser.NewPage()
	if err != nil {
		t.Fatal(err)
	}
	defer page.Close()

	resp, err := page.Goto(authorizeURL("default", "http://evil.com/callback"))
	if err != nil {
		t.Fatal(err)
	}

	if resp.Status() != 400 {
		t.Errorf("expected status 400, got %d", resp.Status())
	}

	content, err := page.Content()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(content, "invalid redirect_uri") {
		t.Errorf("expected error message about invalid redirect_uri, got: %s", content)
	}
}

func TestPublicClientPKCEFlow(t *testing.T) {
	page, err := browser.NewPage()
	if err != nil {
		t.Fatal(err)
	}
	defer page.Close()

	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	authParams := url.Values{
		"client_id":             {"public-cli"},
		"redirect_uri":          {redirectURI},
		"response_type":         {"code"},
		"scope":                 {"openid email profile"},
		"state":                 {"teststate"},
		"nonce":                 {"testnonce"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	_, err = page.Goto(baseURL + "/authorize?" + authParams.Encode())
	if err != nil {
		t.Fatal(err)
	}

	// Click Alice's card
	aliceButton := page.Locator("button.user-card:has-text('Alice')")
	if err := aliceButton.Click(); err != nil {
		t.Fatal(err)
	}

	// Wait for redirect to callback with code
	if err := page.WaitForURL("**/callback**"); err != nil {
		t.Fatal(err)
	}

	currentURL := page.URL()
	parsed, err := url.Parse(currentURL)
	if err != nil {
		t.Fatal(err)
	}

	code := parsed.Query().Get("code")
	if code == "" {
		t.Fatalf("expected code in URL, got: %s", currentURL)
	}

	// Exchange code — no client_secret, only PKCE verifier
	tokenForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {"public-cli"},
		"redirect_uri":  {redirectURI},
		"code_verifier": {verifier},
	}
	resp, err := http.PostForm(baseURL+"/token", tokenForm)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token exchange: expected 200, got %d", resp.StatusCode)
	}

	var tokenResp map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		t.Fatal(err)
	}

	if tokenResp["id_token"] == nil || tokenResp["id_token"] == "" {
		t.Error("expected non-empty id_token")
	}
	if tokenResp["access_token"] == nil || tokenResp["access_token"] == "" {
		t.Error("expected non-empty access_token")
	}
	if tokenResp["token_type"] != "Bearer" {
		t.Errorf("expected token_type=Bearer, got %v", tokenResp["token_type"])
	}
}

// loginAndGetTokens performs a full browser login flow and returns the token response.
func loginAndGetTokens(t *testing.T, clientID, secret, scope string) map[string]any {
	t.Helper()

	page, err := browser.NewPage()
	if err != nil {
		t.Fatal(err)
	}
	defer page.Close()

	params := url.Values{
		"client_id":     {clientID},
		"redirect_uri":  {redirectURI},
		"response_type": {"code"},
		"scope":         {scope},
		"state":         {"teststate"},
		"nonce":         {"testnonce"},
	}
	_, err = page.Goto(baseURL + "/authorize?" + params.Encode())
	if err != nil {
		t.Fatal(err)
	}

	aliceButton := page.Locator("button.user-card:has-text('Alice')")
	if err := aliceButton.Click(); err != nil {
		t.Fatal(err)
	}

	if err := page.WaitForURL("**/callback**"); err != nil {
		t.Fatal(err)
	}

	parsed, err := url.Parse(page.URL())
	if err != nil {
		t.Fatal(err)
	}
	code := parsed.Query().Get("code")
	if code == "" {
		t.Fatalf("expected code in URL, got: %s", page.URL())
	}

	tokenForm := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"client_id":    {clientID},
		"redirect_uri": {redirectURI},
	}
	if secret != "" {
		tokenForm.Set("client_secret", secret)
	}
	resp, err := http.PostForm(baseURL+"/token", tokenForm)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("token exchange: expected 200, got %d: %s", resp.StatusCode, body)
	}

	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestUserinfoEndpoint(t *testing.T) {
	tokens := loginAndGetTokens(t, "default", "secret", "openid email profile")

	accessToken := tokens["access_token"].(string)

	req, _ := http.NewRequest("GET", baseURL+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("userinfo: expected 200, got %d", resp.StatusCode)
	}

	var claims map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&claims); err != nil {
		t.Fatal(err)
	}

	if claims["sub"] != "user1" {
		t.Errorf("expected sub=user1, got %v", claims["sub"])
	}
	if claims["email"] != "alice@example.com" {
		t.Errorf("expected email=alice@example.com, got %v", claims["email"])
	}
	if claims["name"] != "Alice" {
		t.Errorf("expected name=Alice, got %v", claims["name"])
	}
}

func TestRefreshTokenFlow(t *testing.T) {
	tokens := loginAndGetTokens(t, "default", "secret", "openid offline_access")

	refreshToken, ok := tokens["refresh_token"].(string)
	if !ok || refreshToken == "" {
		t.Fatal("expected refresh_token in response")
	}

	refreshForm := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {"default"},
		"client_secret": {"secret"},
	}
	resp, err := http.PostForm(baseURL+"/token", refreshForm)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("refresh: expected 200, got %d: %s", resp.StatusCode, body)
	}

	var refreshResp map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&refreshResp); err != nil {
		t.Fatal(err)
	}

	if refreshResp["access_token"] == nil || refreshResp["access_token"] == "" {
		t.Error("expected new access_token from refresh")
	}
	if refreshResp["id_token"] == nil || refreshResp["id_token"] == "" {
		t.Error("expected new id_token from refresh")
	}
}

func TestRevocationFlow(t *testing.T) {
	tokens := loginAndGetTokens(t, "default", "secret", "openid")

	accessToken := tokens["access_token"].(string)

	// Verify token works before revocation
	req, _ := http.NewRequest("GET", baseURL+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("userinfo before revoke: expected 200, got %d", resp.StatusCode)
	}

	// Revoke the token
	revokeForm := url.Values{
		"token":           {accessToken},
		"token_type_hint": {"access_token"},
	}
	resp, err = http.PostForm(baseURL+"/revoke", revokeForm)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("revoke: expected 200, got %d", resp.StatusCode)
	}

	// Verify token no longer works
	req, _ = http.NewRequest("GET", baseURL+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("userinfo after revoke: expected 401, got %d", resp.StatusCode)
	}
}

func TestEndSessionFlow(t *testing.T) {
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// With post_logout_redirect_uri and state
	resp, err := client.Get(baseURL + "/end-session?post_logout_redirect_uri=" + url.QueryEscape(redirectURI) + "&state=logoutstate")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("end-session: expected 302, got %d", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	parsed, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("invalid Location header: %v", err)
	}
	if parsed.Query().Get("state") != "logoutstate" {
		t.Errorf("expected state=logoutstate in redirect, got %s", parsed.Query().Get("state"))
	}

	// Without redirect URI
	resp, err = client.Get(baseURL + "/end-session")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("end-session without redirect: expected 200, got %d", resp.StatusCode)
	}
}

func TestPasswordProtectedUserFlow(t *testing.T) {
	page, err := browser.NewPage()
	if err != nil {
		t.Fatal(err)
	}
	defer page.Close()

	_, err = page.Goto(authorizeURL("default", redirectURI))
	if err != nil {
		t.Fatal(err)
	}

	// Click Carol's card (password-protected)
	carolButton := page.Locator("button.user-card:has-text('Carol')")
	if err := carolButton.Click(); err != nil {
		t.Fatal(err)
	}

	// Should see password form
	passwordInput := page.Locator("input[type='password']")
	visible, err := passwordInput.IsVisible()
	if err != nil {
		t.Fatal(err)
	}
	if !visible {
		t.Fatal("expected password input to be visible")
	}

	// Submit wrong password
	if err := passwordInput.Fill("wrongpass"); err != nil {
		t.Fatal(err)
	}
	submitBtn := page.Locator("button[type='submit']")
	if err := submitBtn.Click(); err != nil {
		t.Fatal(err)
	}

	// Should see error message
	errorVisible, err := page.Locator("text=Invalid password").IsVisible()
	if err != nil {
		t.Fatal(err)
	}
	if !errorVisible {
		t.Error("expected 'Invalid password' error after wrong password")
	}

	// Submit correct password
	passwordInput = page.Locator("input[type='password']")
	if err := passwordInput.Fill("pass123"); err != nil {
		t.Fatal(err)
	}
	submitBtn = page.Locator("button[type='submit']")
	if err := submitBtn.Click(); err != nil {
		t.Fatal(err)
	}

	// Should redirect to callback with code
	if err := page.WaitForURL("**/callback**"); err != nil {
		t.Fatal(err)
	}

	parsedURL, err := url.Parse(page.URL())
	if err != nil {
		t.Fatal(err)
	}
	code := parsedURL.Query().Get("code")
	if code == "" {
		t.Fatalf("expected code in URL after password login, got: %s", page.URL())
	}

	// Exchange code for tokens
	tokenForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {"default"},
		"client_secret": {"secret"},
		"redirect_uri":  {redirectURI},
	}
	resp, err := http.PostForm(baseURL+"/token", tokenForm)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("token exchange: expected 200, got %d: %s", resp.StatusCode, body)
	}

	var tokenResp map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		t.Fatal(err)
	}
	if tokenResp["id_token"] == nil || tokenResp["id_token"] == "" {
		t.Error("expected non-empty id_token")
	}
}

func TestDiscoveryAndJWKSVerification(t *testing.T) {
	// Fetch discovery document
	resp, err := http.Get(baseURL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("discovery: expected 200, got %d", resp.StatusCode)
	}

	var discovery map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&discovery); err != nil {
		t.Fatal(err)
	}

	// Validate discovery fields
	if discovery["issuer"] != baseURL {
		t.Errorf("expected issuer=%s, got %v", baseURL, discovery["issuer"])
	}
	expectedEndpoints := map[string]string{
		"authorization_endpoint": baseURL + "/authorize",
		"token_endpoint":         baseURL + "/token",
		"jwks_uri":               baseURL + "/jwks",
		"userinfo_endpoint":      baseURL + "/userinfo",
		"revocation_endpoint":    baseURL + "/revoke",
		"end_session_endpoint":   baseURL + "/end-session",
	}
	for key, want := range expectedEndpoints {
		if discovery[key] != want {
			t.Errorf("discovery[%s]: expected %s, got %v", key, want, discovery[key])
		}
	}

	// Fetch JWKS
	jwksResp, err := http.Get(baseURL + "/jwks")
	if err != nil {
		t.Fatal(err)
	}
	defer jwksResp.Body.Close()

	var jwks struct {
		Keys []struct {
			Kty string `json:"kty"`
			Alg string `json:"alg"`
			Use string `json:"use"`
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(jwksResp.Body).Decode(&jwks); err != nil {
		t.Fatal(err)
	}
	if len(jwks.Keys) == 0 {
		t.Fatal("expected at least one key in JWKS")
	}
	key := jwks.Keys[0]
	if key.Kty != "RSA" {
		t.Errorf("expected kty=RSA, got %s", key.Kty)
	}
	if key.Alg != "RS256" {
		t.Errorf("expected alg=RS256, got %s", key.Alg)
	}

	// Build RSA public key from JWKS
	nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil {
		t.Fatalf("failed to decode n: %v", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
	if err != nil {
		t.Fatalf("failed to decode e: %v", err)
	}
	pubKey := &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(new(big.Int).SetBytes(eBytes).Int64()),
	}

	// Get an ID token to verify
	tokens := loginAndGetTokens(t, "default", "secret", "openid email")
	idToken := tokens["id_token"].(string)

	// Parse and verify the JWT signature
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT parts, got %d", len(parts))
	}

	signingInput := []byte(parts[0] + "." + parts[1])
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("failed to decode signature: %v", err)
	}

	hash := sha256.Sum256(signingInput)
	if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hash[:], signature); err != nil {
		t.Fatalf("ID token signature verification failed: %v", err)
	}

	// Decode and validate claims
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		t.Fatal(err)
	}
	if claims["iss"] != baseURL {
		t.Errorf("expected iss=%s, got %v", baseURL, claims["iss"])
	}
	if claims["sub"] != "user1" {
		t.Errorf("expected sub=user1, got %v", claims["sub"])
	}
	if claims["email"] != "alice@example.com" {
		t.Errorf("expected email=alice@example.com, got %v", claims["email"])
	}
}

func TestSingleAudIsString(t *testing.T) {
	tokens := loginAndGetTokens(t, "default", "secret", "openid")
	idToken := tokens["id_token"].(string)

	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT parts, got %d", len(parts))
	}

	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(claimsJSON, &raw); err != nil {
		t.Fatal(err)
	}

	audRaw, ok := raw["aud"]
	if !ok {
		t.Fatal("expected aud claim in ID token")
	}

	// Single audience must be serialized as a JSON string, not an array
	var audStr string
	if err := json.Unmarshal(audRaw, &audStr); err != nil {
		t.Fatalf("expected aud to be a JSON string (RFC 7519 §4.1.3), got: %s", string(audRaw))
	}
	if audStr != "default" {
		t.Errorf("expected aud=default, got %q", audStr)
	}
}

func TestScopeFiltering(t *testing.T) {
	// openid only — no email or name
	tokens := loginAndGetTokens(t, "default", "secret", "openid")
	accessToken := tokens["access_token"].(string)

	req, _ := http.NewRequest("GET", baseURL+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var claims map[string]any
	json.NewDecoder(resp.Body).Decode(&claims)

	if claims["sub"] != "user1" {
		t.Errorf("expected sub=user1, got %v", claims["sub"])
	}
	if _, ok := claims["email"]; ok {
		t.Error("expected no email claim with openid-only scope")
	}
	if _, ok := claims["name"]; ok {
		t.Error("expected no name claim with openid-only scope")
	}

	// openid email — email but no name
	tokens = loginAndGetTokens(t, "default", "secret", "openid email")
	accessToken = tokens["access_token"].(string)

	req, _ = http.NewRequest("GET", baseURL+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()

	var claims2 map[string]any
	json.NewDecoder(resp2.Body).Decode(&claims2)

	if claims2["email"] != "alice@example.com" {
		t.Errorf("expected email with email scope, got %v", claims2["email"])
	}
	if _, ok := claims2["name"]; ok {
		t.Error("expected no name claim with openid+email scope")
	}

	// openid profile — name and custom claims but no email
	tokens = loginAndGetTokens(t, "default", "secret", "openid profile")
	accessToken = tokens["access_token"].(string)

	req, _ = http.NewRequest("GET", baseURL+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp3, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp3.Body.Close()

	var claims3 map[string]any
	json.NewDecoder(resp3.Body).Decode(&claims3)

	if claims3["name"] != "Alice" {
		t.Errorf("expected name=Alice with profile scope, got %v", claims3["name"])
	}
	if _, ok := claims3["email"]; ok {
		t.Error("expected no email claim with openid+profile scope")
	}
}
