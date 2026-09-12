package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestRun_NoArgs(t *testing.T) {
	code := run(context.Background(), []string{"oidc-mock"}, os.Stdout, os.Stderr)
	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}
}

func TestRun_Help(t *testing.T) {
	for _, arg := range []string{"help", "--help", "-h"} {
		t.Run(arg, func(t *testing.T) {
			code := run(context.Background(), []string{"oidc-mock", arg}, os.Stdout, os.Stderr)
			if code != 0 {
				t.Errorf("expected exit code 0, got %d", code)
			}
		})
	}
}

func TestRun_UnknownCommand(t *testing.T) {
	code := run(context.Background(), []string{"oidc-mock", "bogus"}, os.Stdout, os.Stderr)
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestRun_Serve(t *testing.T) {
	t.Setenv("OIDC_PORT", "19093")

	ctx, cancel := context.WithCancel(context.Background())

	codeCh := make(chan int, 1)
	go func() {
		codeCh <- run(ctx, []string{"oidc-mock", "serve"}, os.Stdout, os.Stderr)
	}()

	ready := false
	for i := 0; i < 200; i++ {
		resp, err := http.Get("http://localhost:19093/.well-known/openid-configuration")
		if err == nil {
			resp.Body.Close()
			ready = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !ready {
		t.Fatal("server did not start in time")
	}

	cancel()

	select {
	case code := <-codeCh:
		if code != 0 {
			t.Errorf("expected exit code 0, got %d", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not shut down in time")
	}
}

func TestRun_Serve_InvalidConfig(t *testing.T) {
	t.Setenv("OIDC_CONFIG", "invalid: [yaml")

	code := run(context.Background(), []string{"oidc-mock", "serve"}, os.Stdout, os.Stderr)
	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
}

func TestListenAndServe(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Port = 19091
	mux, err := newServerMux(cfg)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- listenAndServe(ctx, ":19091", mux)
	}()

	ready := false
	for i := 0; i < 200; i++ {
		resp, err := http.Get("http://localhost:19091/.well-known/openid-configuration")
		if err == nil {
			resp.Body.Close()
			ready = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !ready {
		t.Fatal("server did not start in time")
	}

	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("listenAndServe returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not shut down in time")
	}
}

func TestServe(t *testing.T) {
	t.Setenv("OIDC_PORT", "19092")

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- serve(ctx, nil)
	}()

	ready := false
	for i := 0; i < 200; i++ {
		resp, err := http.Get("http://localhost:19092/.well-known/openid-configuration")
		if err == nil {
			resp.Body.Close()
			ready = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !ready {
		t.Fatal("server did not start in time")
	}

	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("serve returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not shut down in time")
	}
}

func TestServe_InvalidConfig(t *testing.T) {
	t.Setenv("OIDC_CONFIG", "invalid: [yaml")

	ctx := context.Background()
	err := serve(ctx, nil)
	if err == nil {
		t.Fatal("expected error for invalid config")
	}
}

func TestParseConfigPath(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"no args", nil, ""},
		{"no config flag", []string{"--port", "9090"}, ""},
		{"with config", []string{"--config", "my.yaml"}, "my.yaml"},
		{"config at end without value", []string{"--config"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseConfigPath(tt.args)
			if got != tt.want {
				t.Errorf("parseConfigPath(%v) = %q, want %q", tt.args, got, tt.want)
			}
		})
	}
}

func TestCORSMiddleware(t *testing.T) {
	cfg := DefaultConfig()
	mux, err := newServerMux(cfg)
	if err != nil {
		t.Fatal(err)
	}
	handler := corsMiddleware(mux)

	t.Run("GET adds CORS headers", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/.well-known/openid-configuration", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Header().Get("Access-Control-Allow-Origin") != "*" {
			t.Errorf("expected ACAO=*, got %q", w.Header().Get("Access-Control-Allow-Origin"))
		}
		if w.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", w.Code)
		}
	})

	t.Run("OPTIONS preflight returns 204", func(t *testing.T) {
		req := httptest.NewRequest("OPTIONS", "/token", nil)
		req.Header.Set("Origin", "http://example.com")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusNoContent {
			t.Errorf("expected 204, got %d", w.Code)
		}
		if w.Header().Get("Access-Control-Allow-Methods") == "" {
			t.Error("expected Access-Control-Allow-Methods header")
		}
		if w.Header().Get("Access-Control-Allow-Headers") == "" {
			t.Error("expected Access-Control-Allow-Headers header")
		}
	})
}

func TestNewServerMux(t *testing.T) {
	cfg := DefaultConfig()
	mux, err := newServerMux(cfg)
	if err != nil {
		t.Fatalf("newServerMux: %v", err)
	}

	routes := []struct {
		method string
		path   string
		expect int
	}{
		{"GET", "/.well-known/openid-configuration", http.StatusOK},
		{"GET", "/jwks", http.StatusOK},
		{"GET", "/authorize?client_id=default&redirect_uri=http://localhost:8080/callback&response_type=code&scope=openid", http.StatusOK},
		{"GET", "/end-session", http.StatusOK},
	}

	for _, rt := range routes {
		t.Run(rt.method+" "+rt.path, func(t *testing.T) {
			req := httptest.NewRequest(rt.method, rt.path, nil)
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, req)
			if w.Code != rt.expect {
				t.Errorf("%s %s: expected %d, got %d", rt.method, rt.path, rt.expect, w.Code)
			}
		})
	}
}
