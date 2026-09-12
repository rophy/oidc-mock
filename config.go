package main

import (
	_ "embed"
	"fmt"
	"os"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"
)

//go:embed config_schema.json
var configSchemaJSON string

type Config struct {
	Port    int      `yaml:"port"`
	Issuer  string   `yaml:"issuer"`
	Clients []Client `yaml:"clients"`
	Users   []User   `yaml:"users"`
}

type Client struct {
	ID                      string   `yaml:"id"`
	Secret                  string   `yaml:"secret"`
	RedirectURIs            []string `yaml:"redirect_uris"`
	PostLogoutRedirectURIs  []string `yaml:"post_logout_redirect_uris"`
	AllowPlainCodeChallenge bool     `yaml:"allow_plain_code_challenge"`
}

type User struct {
	Sub      string         `yaml:"sub"`
	Email    string         `yaml:"email"`
	Name     string         `yaml:"name"`
	Password string         `yaml:"password,omitempty"`
	Claims   map[string]any `yaml:",inline"`
}

func DefaultConfig() Config {
	return Config{
		Port:   8080,
		Issuer: "http://localhost:8080",
		Clients: []Client{
			{
				ID:           "default",
				Secret:       "secret",
				RedirectURIs: []string{"http://localhost:8080/callback"},
			},
		},
		Users: []User{
			{Sub: "user1", Email: "alice@example.com", Name: "Alice", Claims: map[string]any{"roles": []any{"admin"}}},
			{Sub: "user2", Email: "bob@example.com", Name: "Bob", Claims: map[string]any{"roles": []any{"viewer"}}},
		},
	}
}

func LoadConfig(path string) (Config, error) {
	cfg := DefaultConfig()

	hasInline := os.Getenv("OIDC_CONFIG") != ""
	hasFile := os.Getenv("OIDC_CONFIG_FILE") != ""
	hasFlag := path != ""

	sources := 0
	if hasInline {
		sources++
	}
	if hasFile {
		sources++
	}
	if hasFlag {
		sources++
	}
	if sources > 1 {
		return Config{}, fmt.Errorf("only one config source allowed, but got multiple: set exactly one of OIDC_CONFIG, OIDC_CONFIG_FILE, or --config")
	}

	var data []byte
	if hasInline {
		data = []byte(os.Getenv("OIDC_CONFIG"))
	} else if hasFile {
		var err error
		data, err = os.ReadFile(os.Getenv("OIDC_CONFIG_FILE"))
		if err != nil {
			return Config{}, err
		}
	} else if hasFlag {
		var err error
		data, err = os.ReadFile(path)
		if err != nil {
			return Config{}, err
		}
	}

	if data != nil {
		var raw any
		if err := yaml.Unmarshal(data, &raw); err != nil {
			return Config{}, err
		}
		if err := validateConfigSchema(raw); err != nil {
			return Config{}, err
		}
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return Config{}, err
		}
	}

	cfg.Issuer = strings.TrimSuffix(cfg.Issuer, "/")

	if v := os.Getenv("OIDC_PORT"); v != "" {
		var port int
		if _, err := fmt.Sscanf(v, "%d", &port); err == nil {
			cfg.Port = port
		}
	}

	return cfg, nil
}

func validateConfigSchema(data any) error {
	doc, err := jsonschema.UnmarshalJSON(strings.NewReader(configSchemaJSON))
	if err != nil {
		return fmt.Errorf("failed to parse config schema: %w", err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource("config_schema.json", doc); err != nil {
		return fmt.Errorf("failed to load config schema: %w", err)
	}
	sch, err := c.Compile("config_schema.json")
	if err != nil {
		return fmt.Errorf("failed to compile config schema: %w", err)
	}
	return sch.Validate(data)
}
