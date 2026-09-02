package main

import (
	_ "embed"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"gopkg.in/yaml.v3"
)

//go:embed README.md
var readme string

func main() {
	flag.Usage = func() { fmt.Fprint(os.Stderr, readme) }
	configPath := flag.String("config", "", "path to config YAML file")
	flag.Parse()

	if flag.Arg(0) == "help" {
		fmt.Print(readme)
		os.Exit(0)
	}

	cfg, err := LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	kp, err := GenerateKeyPair()
	if err != nil {
		log.Fatalf("failed to generate key pair: %v", err)
	}

	srv := &Server{
		Config:  cfg,
		KeyPair: kp,
		Store:   NewStore(),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", srv.HandleDiscovery)
	mux.HandleFunc("GET /authorize", srv.HandleAuthorize)
	mux.HandleFunc("POST /authorize/callback", srv.HandleAuthorizeCallback)
	mux.HandleFunc("POST /token", srv.HandleToken)
	mux.HandleFunc("GET /jwks", srv.HandleJWKS)
	mux.HandleFunc("GET /userinfo", srv.HandleUserinfo)
	mux.HandleFunc("POST /userinfo", srv.HandleUserinfo)
	mux.HandleFunc("POST /revoke", srv.HandleRevoke)
	mux.HandleFunc("GET /end-session", srv.HandleEndSession)

	addr := fmt.Sprintf(":%d", cfg.Port)
	cfgYAML, _ := yaml.Marshal(cfg)
	log.Printf("Runtime OIDC_CONFIG:\n---\n%s---", cfgYAML)
	log.Printf("oidc-mock listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}
