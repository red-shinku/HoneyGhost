package cmd

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	"honeyghost/cli/internal/api"
)

var testBuild = BuildInfo{Version: "1.2.3", Commit: "abc", Date: "2026-01-02"}

func execute(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	t.Setenv("HGHOST_SOCKET", "")
	app := NewApp(func(context.Context, string) (api.Services, io.Closer, error) {
		t.Fatalf("dial must not be called for %v", args)
		return api.Services{}, nil, nil
	})
	out, errOut := new(bytes.Buffer), new(bytes.Buffer)
	root := NewRootCommand(app, testBuild)
	root.SetOut(out)
	root.SetErr(errOut)
	root.SetArgs(args)
	err := root.ExecuteContext(context.Background())
	return out.String(), errOut.String(), err
}

func TestVersionCommand(t *testing.T) {
	out, _, err := execute(t, "version")
	if err != nil {
		t.Fatalf("version: %v", err)
	}
	want := "hghost 1.2.3 (abc, 2026-01-02)\n"
	if out != want {
		t.Errorf("stdout = %q, want %q", out, want)
	}
}

func TestVersionFlag(t *testing.T) {
	out, _, err := execute(t, "--version")
	if err != nil {
		t.Fatalf("--version: %v", err)
	}
	want := "hghost 1.2.3 (abc, 2026-01-02)\n"
	if out != want {
		t.Errorf("stdout = %q, want %q", out, want)
	}
}

func TestNoArgsPrintsHelp(t *testing.T) {
	out, _, err := execute(t)
	if err != nil {
		t.Fatalf("no args: %v", err)
	}
	if !strings.Contains(out, "Usage:") || !strings.Contains(out, "Available Commands:") {
		t.Errorf("stdout does not look like help:\n%s", out)
	}
}

func TestHelpFlag(t *testing.T) {
	out, _, err := execute(t, "--help")
	if err != nil {
		t.Fatalf("--help: %v", err)
	}
	for _, flag := range []string{"--socket", "--timeout", "--output", "--no-headers"} {
		if !strings.Contains(out, flag) {
			t.Errorf("help output missing %s:\n%s", flag, out)
		}
	}
}

func TestCompletion(t *testing.T) {
	out, _, err := execute(t, "completion", "bash")
	if err != nil {
		t.Fatalf("completion bash: %v", err)
	}
	if out == "" {
		t.Error("completion bash produced no output")
	}
}

func TestUsageErrors(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"relative socket", []string{"--socket", "relative.sock", "version"}},
		{"grpc target", []string{"--socket", "unix:/tmp/x.sock", "version"}},
		{"negative timeout", []string{"--timeout", "-1s", "version"}},
		{"bad output", []string{"--output", "yaml", "version"}},
		{"unknown command", []string{"bogus"}},
		{"unknown flag", []string{"--bogus", "version"}},
		{"version args", []string{"version", "extra"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := execute(t, tt.args...)
			if err == nil {
				t.Fatal("expected an error")
			}
			if code := ExitCode(err, false); code != 2 {
				t.Errorf("ExitCode = %d, want 2 (err: %v)", code, err)
			}
		})
	}
}

func TestSocketFromEnv(t *testing.T) {
	t.Setenv("HGHOST_SOCKET", "/tmp/from-env.sock")
	app := NewApp(nil)
	if app.opts.Socket != "/tmp/from-env.sock" {
		t.Errorf("Socket = %q, want /tmp/from-env.sock", app.opts.Socket)
	}
}
