package client

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"honeyghost/cli/internal/api"
)

// statusError 把 RPC 错误投影成 api.StatusError，保留 RPC 名与原始消息。
func statusError(op string, err error) error {
	st, ok := status.FromError(err)
	if !ok {
		return &api.StatusError{Op: op, Kind: api.ErrorOther, Message: err.Error()}
	}
	return &api.StatusError{
		Op:      op,
		Kind:    errorKind(st.Code()),
		Code:    st.Code().String(),
		Message: st.Message(),
	}
}

func errorKind(code codes.Code) api.ErrorKind {
	switch code {
	case codes.Unavailable:
		return api.ErrorUnavailable
	case codes.DeadlineExceeded:
		return api.ErrorDeadlineExceeded
	case codes.Unimplemented:
		return api.ErrorUnimplemented
	case codes.InvalidArgument:
		return api.ErrorInvalidArgument
	case codes.PermissionDenied:
		return api.ErrorPermissionDenied
	case codes.ResourceExhausted:
		return api.ErrorResourceExhausted
	case codes.Canceled:
		return api.ErrorCanceled
	default:
		return api.ErrorOther
	}
}
