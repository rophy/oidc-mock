//go:build e2e

package e2e

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
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
