package main

import (
	"context"
	_ "embed"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"
)

//go:embed README.md
var readme string

const usage = `Usage: oidc-mock <command>

Commands:
  serve   Start the OIDC mock server
  help    Show full documentation

Run "oidc-mock help" for configuration details and examples.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Print(usage)
		os.Exit(0)
	}

	switch os.Args[1] {
	case "help", "--help", "-h":
		fmt.Print(readme)
	case "serve":
		serve(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n%s", os.Args[1], usage)
		os.Exit(1)
	}
}

func serve(args []string) {
	var configPath string
	for i := 0; i < len(args)-1; i++ {
		if args[i] == "--config" {
			configPath = args[i+1]
			break
		}
	}

	cfg, err := LoadConfig(configPath)
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

	server := &http.Server{Addr: addr, Handler: mux}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	shutdownDone := make(chan error, 1)
	go func() {
		<-quit
		log.Println("shutting down...")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		shutdownDone <- server.Shutdown(ctx)
	}()

	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatal(err)
	}
	if err := <-shutdownDone; err != nil {
		log.Printf("HTTP server shutdown: %v", err)
	}
}
