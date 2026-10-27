package main

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr error
		wantOut string
	}{
		{"no command", nil, errUsage, "Usage: dispatcher"},
		{"unknown command", []string{"nope"}, errUsage, `unknown command "nope"`},
		{"help", []string{"help"}, nil, "serve"},
		{"bad flag", []string{"serve", "-nope"}, errUsage, ""},
		{"subcommand help", []string{"serve", "-h"}, nil, ""},
		{"version", []string{"version"}, nil, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stderr bytes.Buffer
			err := run(context.Background(), tt.args, &stderr)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if !strings.Contains(stderr.String(), tt.wantOut) {
				t.Errorf("stderr = %q, want it to contain %q", stderr.String(), tt.wantOut)
			}
		})
	}
}

func TestHealth(t *testing.T) {
	srv := httptest.NewServer(routes())
	defer srv.Close()

	if err := healthcheck(context.Background(), []string{"-url", srv.URL + "/health"}); err != nil {
		t.Fatalf("healthcheck: %v", err)
	}

	resp, err := http.Post(srv.URL+"/health", "text/plain", nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST /health status = %d, want 405", resp.StatusCode)
	}

	if err := healthcheck(context.Background(), []string{"-url", srv.URL + "/missing"}); err == nil {
		t.Error("healthcheck on a 404 endpoint: want an error")
	}
}
