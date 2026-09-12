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
	os.Exit(run(context.Background(), os.Args, os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr *os.File) int {
	if len(args) < 2 {
		fmt.Fprint(stdout, usage)
		return 0
	}

	switch args[1] {
	case "help", "--help", "-h":
		fmt.Fprint(stdout, readme)
		return 0
	case "serve":
		ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		if err := serve(ctx, args[2:]); err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 1
		}
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command: %s\n\n%s", args[1], usage)
		return 1
	}
}

func parseConfigPath(args []string) string {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == "--config" {
			return args[i+1]
		}
	}
	return ""
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func newServerMux(cfg Config) (*http.ServeMux, error) {
	kp, err := GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
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

	return mux, nil
}

func listenAndServe(ctx context.Context, addr string, handler http.Handler) error {
	server := &http.Server{Addr: addr, Handler: handler}

	shutdownDone := make(chan error, 1)
	go func() {
		<-ctx.Done()
		log.Println("shutting down...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		shutdownDone <- server.Shutdown(shutdownCtx)
	}()

	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		return err
	}
	if err := <-shutdownDone; err != nil {
		return fmt.Errorf("HTTP server shutdown: %w", err)
	}
	return nil
}

func serve(ctx context.Context, args []string) error {
	cfg, err := LoadConfig(parseConfigPath(args))
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	mux, err := newServerMux(cfg)
	if err != nil {
		return err
	}

	addr := fmt.Sprintf(":%d", cfg.Port)
	cfgYAML, _ := yaml.Marshal(cfg)
	log.Printf("Runtime OIDC_CONFIG:\n---\n%s---", cfgYAML)
	log.Printf("oidc-mock listening on %s", addr)

	return listenAndServe(ctx, addr, corsMiddleware(mux))
}
