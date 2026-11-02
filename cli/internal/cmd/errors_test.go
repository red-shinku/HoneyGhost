package cmd

import (
	"context"
	"errors"
	"syscall"
	"testing"
	"time"

	"honeyghost/cli/internal/api"
)

func testApp() *App {
	app := NewApp(nil)
	app.opts.Socket = "/run/x.sock"
	app.opts.Timeout = 5 * time.Second
	return app
}

func TestDescribe(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "unavailable",
			err:  &api.StatusError{Op: "GetRoles", Kind: api.ErrorUnavailable, Message: "boom"},
			want: "cannot connect to the CLI service (socket: /run/x.sock): boom; " +
				"the daemon may not be running or --socket is incorrect",
		},
		{
			name: "deadline",
			err:  &api.StatusError{Op: "GetRoles", Kind: api.ErrorDeadlineExceeded, Message: "boom"},
			want: "request timed out (--timeout=5s)",
		},
		{
			name: "unimplemented",
			err:  &api.StatusError{Op: "GetRoles", Kind: api.ErrorUnimplemented, Message: "boom"},
			want: "GetRoles is not implemented by the server: boom",
		},
		{
			name: "invalid argument",
			err:  &api.StatusError{Op: "GetRoles", Kind: api.ErrorInvalidArgument, Message: "boom"},
			want: "boom",
		},
		{
			name: "permission denied",
			err:  &api.StatusError{Op: "GetRoles", Kind: api.ErrorPermissionDenied, Message: "boom"},
			want: "permission denied for socket /run/x.sock: boom",
		},
		{
			name: "resource exhausted",
			err:  &api.StatusError{Op: "ReceiveEvent", Kind: api.ErrorResourceExhausted, Message: "boom"},
			want: "stream limit reached: boom",
		},
		{
			name: "canceled",
			err:  &api.StatusError{Op: "GetRoles", Kind: api.ErrorCanceled, Message: "boom"},
			want: "GetRoles canceled",
		},
		{
			name: "other",
			err: &api.StatusError{
				Op: "GetRoles", Kind: api.ErrorOther, Code: "Unknown", Message: "boom",
			},
			want: "GetRoles failed (Unknown): boom",
		},
		{
			name: "non status",
			err:  errors.New("plain"),
			want: "plain",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := testApp().describe(tt.err); got != tt.want {
				t.Errorf("describe() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExitCode(t *testing.T) {
	canceled := &api.StatusError{Op: "GetRoles", Kind: api.ErrorCanceled}
	other := &api.StatusError{Op: "GetRoles", Kind: api.ErrorOther, Code: "Unknown"}

	tests := []struct {
		name        string
		err         error
		interrupted bool
		want        int
	}{
		{"nil", nil, false, 0},
		{"epipe", runtimeError{err: syscall.EPIPE, msg: "x"}, false, 0},
		{"usage", usageErrorf("bad"), false, 2},
		{"unwrapped", errors.New("unknown command"), false, 2},
		{"runtime", runtimeError{err: other, msg: "x"}, false, 1},
		{"canceled", runtimeError{err: canceled, msg: "x"}, false, 1},
		{"interrupted canceled", runtimeError{err: canceled, msg: "x"}, true, 130},
		{"interrupted other", runtimeError{err: other, msg: "x"}, true, 1},
		{"context canceled", runtimeError{err: context.Canceled, msg: "x"}, true, 130},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ExitCode(tt.err, tt.interrupted); got != tt.want {
				t.Errorf("ExitCode = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestWrapRuntimePreservesUsageError(t *testing.T) {
	app := testApp()
	usage := usageErrorf("bad flag")
	wrapped := app.wrapRuntime(usage)
	if code := ExitCode(wrapped, false); code != 2 {
		t.Errorf("ExitCode = %d, want 2", code)
	}
}

func TestWrapRuntimeFormatsStatusError(t *testing.T) {
	app := testApp()
	err := app.wrapRuntime(&api.StatusError{Op: "GetRoles", Kind: api.ErrorCanceled})
	want := "GetRoles canceled"
	if err.Error() != want {
		t.Errorf("Error() = %q, want %q", err.Error(), want)
	}
}
