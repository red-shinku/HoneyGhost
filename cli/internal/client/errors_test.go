package client

import (
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"honeyghost/cli/internal/api"
)

func TestErrorKind(t *testing.T) {
	tests := []struct {
		code codes.Code
		want api.ErrorKind
	}{
		{codes.Unavailable, api.ErrorUnavailable},
		{codes.DeadlineExceeded, api.ErrorDeadlineExceeded},
		{codes.Unimplemented, api.ErrorUnimplemented},
		{codes.InvalidArgument, api.ErrorInvalidArgument},
		{codes.PermissionDenied, api.ErrorPermissionDenied},
		{codes.ResourceExhausted, api.ErrorResourceExhausted},
		{codes.Canceled, api.ErrorCanceled},
		{codes.Internal, api.ErrorOther},
		{codes.Unknown, api.ErrorOther},
	}

	for _, tt := range tests {
		err := statusError("GetRoles", status.Error(tt.code, "boom"))
		var se *api.StatusError
		if !errors.As(err, &se) {
			t.Fatalf("%s: got %T, want *api.StatusError", tt.code, err)
		}
		if se.Kind != tt.want {
			t.Errorf("%s: Kind = %v, want %v", tt.code, se.Kind, tt.want)
		}
		if se.Op != "GetRoles" {
			t.Errorf("%s: Op = %q, want GetRoles", tt.code, se.Op)
		}
		if se.Code != tt.code.String() {
			t.Errorf("%s: Code = %q, want %q", tt.code, se.Code, tt.code.String())
		}
		if se.Message != "boom" {
			t.Errorf("%s: Message = %q, want boom", tt.code, se.Message)
		}
	}
}

func TestErrorKindNonStatus(t *testing.T) {
	err := statusError("GetRoles", errors.New("plain failure"))
	var se *api.StatusError
	if !errors.As(err, &se) {
		t.Fatalf("got %T, want *api.StatusError", err)
	}
	if se.Kind != api.ErrorOther {
		t.Errorf("Kind = %v, want ErrorOther", se.Kind)
	}
	if se.Code != "" {
		t.Errorf("Code = %q, want empty", se.Code)
	}
	if se.Message != "plain failure" {
		t.Errorf("Message = %q, want plain failure", se.Message)
	}
}
