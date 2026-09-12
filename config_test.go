package main

import (
	"os"
	"strings"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Port != 8080 {
		t.Errorf("expected port 8080, got %d", cfg.Port)
	}
	if cfg.Issuer != "http://localhost:8080" {
		t.Errorf("expected default issuer, got %s", cfg.Issuer)
	}
	if len(cfg.Clients) != 1 {
		t.Fatalf("expected 1 default client, got %d", len(cfg.Clients))
	}
	if cfg.Clients[0].ID != "default" || cfg.Clients[0].Secret != "secret" {
		t.Errorf("unexpected default client: %+v", cfg.Clients[0])
	}
	if len(cfg.Users) != 2 {
		t.Fatalf("expected 2 default users, got %d", len(cfg.Users))
	}
	if cfg.Users[0].Sub != "user1" || cfg.Users[0].Email != "alice@example.com" {
		t.Errorf("unexpected first user: %+v", cfg.Users[0])
	}
}

func TestLoadConfigFromFile(t *testing.T) {
	yamlContent := `
port: 9090
issuer: http://myapp:9090
clients:
  - id: my-app
    secret: my-secret
    redirect_uris:
      - http://localhost:3000/callback
users:
  - sub: u1
    email: test@test.com
    name: Tester
    department: engineering
`
	tmpFile := t.TempDir() + "/config.yaml"
	if err := os.WriteFile(tmpFile, []byte(yamlContent), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(tmpFile)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Port != 9090 {
		t.Errorf("expected port 9090, got %d", cfg.Port)
	}
	if cfg.Issuer != "http://myapp:9090" {
		t.Errorf("expected issuer http://myapp:9090, got %s", cfg.Issuer)
	}
	if len(cfg.Clients) != 1 || cfg.Clients[0].ID != "my-app" {
		t.Errorf("unexpected clients: %+v", cfg.Clients)
	}
	if len(cfg.Users) != 1 || cfg.Users[0].Sub != "u1" {
		t.Errorf("unexpected users: %+v", cfg.Users)
	}
	if cfg.Users[0].Claims["department"] != "engineering" {
		t.Errorf("expected custom claim department=engineering, got %v", cfg.Users[0].Claims["department"])
	}
}

func TestInlineConfigViaEnvVar(t *testing.T) {
	t.Setenv("OIDC_CONFIG", `
port: 7777
issuer: http://inline:7777
clients:
  - id: inline-app
    secret: inline-secret
    redirect_uris:
      - http://localhost:7777/callback
users:
  - sub: u1
    email: inline@test.com
    name: Inline User
`)

	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Port != 7777 {
		t.Errorf("expected port 7777, got %d", cfg.Port)
	}
	if cfg.Issuer != "http://inline:7777" {
		t.Errorf("expected issuer http://inline:7777, got %s", cfg.Issuer)
	}
	if len(cfg.Clients) != 1 || cfg.Clients[0].ID != "inline-app" {
		t.Errorf("unexpected clients: %+v", cfg.Clients)
	}
	if len(cfg.Users) != 1 || cfg.Users[0].Email != "inline@test.com" {
		t.Errorf("unexpected users: %+v", cfg.Users)
	}
}

func TestConfigFileViaEnvVar(t *testing.T) {
	yamlContent := `
port: 6666
issuer: http://filecfg:6666
`
	tmpFile := t.TempDir() + "/config.yaml"
	if err := os.WriteFile(tmpFile, []byte(yamlContent), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OIDC_CONFIG_FILE", tmpFile)

	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Port != 6666 {
		t.Errorf("expected port 6666, got %d", cfg.Port)
	}
}

func TestMultipleConfigSourcesError(t *testing.T) {
	tmpFile := t.TempDir() + "/config.yaml"
	os.WriteFile(tmpFile, []byte("port: 1111"), 0644)
	t.Setenv("OIDC_CONFIG_FILE", tmpFile)
	t.Setenv("OIDC_CONFIG", "port: 2222")

	_, err := LoadConfig("")
	if err == nil {
		t.Fatal("expected error when both OIDC_CONFIG and OIDC_CONFIG_FILE are set")
	}
}

func TestSchemaRejectsUnknownClientField(t *testing.T) {
	t.Setenv("OIDC_CONFIG", `
clients:
  - id: my-app
    secret: s
    public: true
    redirect_uris:
      - http://localhost/cb
users:
  - sub: u1
`)
	_, err := LoadConfig("")
	if err == nil {
		t.Fatal("expected error for unknown client field 'public'")
	}
	if !strings.Contains(err.Error(), "public") {
		t.Errorf("expected error mentioning 'public', got: %v", err)
	}
}

func TestSchemaRejectsUnknownTopLevelField(t *testing.T) {
	t.Setenv("OIDC_CONFIG", `
debug: true
clients:
  - id: app
    redirect_uris: [http://localhost/cb]
users:
  - sub: u1
`)
	_, err := LoadConfig("")
	if err == nil {
		t.Fatal("expected error for unknown top-level field 'debug'")
	}
	if !strings.Contains(err.Error(), "debug") {
		t.Errorf("expected error mentioning 'debug', got: %v", err)
	}
}

func TestSchemaAllowsCustomUserClaims(t *testing.T) {
	t.Setenv("OIDC_CONFIG", `
clients:
  - id: app
    redirect_uris: [http://localhost/cb]
users:
  - sub: u1
    email: a@b.com
    roles: [admin]
    department: engineering
`)
	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatalf("expected custom user claims to be allowed, got: %v", err)
	}
	if cfg.Users[0].Claims["department"] != "engineering" {
		t.Errorf("expected department=engineering, got %v", cfg.Users[0].Claims["department"])
	}
}

func TestLoadConfigTrimsTrailingSlashFromIssuer(t *testing.T) {
	t.Setenv("OIDC_CONFIG", `
issuer: http://example.com/
clients:
  - id: app
    redirect_uris: [http://localhost/cb]
users:
  - sub: u1
`)
	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Issuer != "http://example.com" {
		t.Errorf("expected trailing slash trimmed from issuer, got %q", cfg.Issuer)
	}
}

func TestEnvVarOverrides(t *testing.T) {
	t.Setenv("OIDC_PORT", "3333")

	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Port != 3333 {
		t.Errorf("expected port 3333, got %d", cfg.Port)
	}
}
