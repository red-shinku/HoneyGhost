package client

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"honeyghost/cli/internal/api"
)

func TestDialMissingSocketIsUnavailable(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "missing.sock")
	c, err := Dial(context.Background(), socket, Options{UserAgent: "hghost/test"})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, _, err = c.Services().Roles.Which(ctx, 1)
	var se *api.StatusError
	if !errors.As(err, &se) {
		t.Fatalf("got %T (%v), want *api.StatusError", err, err)
	}
	if se.Kind != api.ErrorUnavailable {
		t.Errorf("Kind = %v, want ErrorUnavailable", se.Kind)
	}
	if se.Op != "WhichRole" {
		t.Errorf("Op = %q, want WhichRole", se.Op)
	}
}
