//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mxschmitt/playwright-go"
)

const baseURL = "http://localhost:19090"
const redirectURI = baseURL + "/callback"

var browser playwright.Browser

func TestMain(m *testing.M) {
	// Build the binary
	build := exec.Command("go", "build", "-o", "/tmp/oidc-mock-e2e", ".")
	build.Dir = ".."
	build.Stdout = os.Stdout
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to build: %v\n", err)
		os.Exit(1)
	}
	defer os.Remove("/tmp/oidc-mock-e2e")

	// Write a config file with redirect_uri matching our test port
	configContent := fmt.Sprintf(`port: 19090
issuer: %s
clients:
  - id: default
    secret: secret
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
`, baseURL, redirectURI)

	configPath := filepath.Join(os.TempDir(), "oidc-mock-e2e-config.yaml")
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write config: %v\n", err)
		os.Exit(1)
	}
	defer os.Remove(configPath)

	// Start the server with config
	srv := exec.Command("/tmp/oidc-mock-e2e", "--config", configPath)
	if err := srv.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to start server: %v\n", err)
		os.Exit(1)
	}
	defer srv.Process.Kill()

	// Wait for server to be ready
	ready := false
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(baseURL + "/.well-known/openid-configuration")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				ready = true
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		fmt.Fprintf(os.Stderr, "server not ready after 10s\n")
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
	defer pw.Stop()

	browser, err = pw.Chromium.Launch(playwright.BrowserTypeLaunchOptions{
		Headless: playwright.Bool(true),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to launch browser: %v\n", err)
		os.Exit(1)
	}
	defer browser.Close()

	os.Exit(m.Run())
}

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
