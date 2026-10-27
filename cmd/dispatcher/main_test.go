package main

import (
	"bytes"
	"context"
	"errors"
	"io"
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
	t.Run("serve with a missing configuration file", func(t *testing.T) {
		err := run(context.Background(), []string{"serve", "-config", "/nonexistent/dispatcher.yaml"}, io.Discard)
		if err == nil || !strings.Contains(err.Error(), "configuration") {
			t.Errorf("err = %v, want a configuration error", err)
		}
	})
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
