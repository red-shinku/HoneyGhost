package cmd

import (
	"context"
	"errors"
	"fmt"
	"syscall"

	"honeyghost/cli/internal/api"
)

// usageError 标记用法错误，退出码 2。
type usageError struct{ err error }

func (e usageError) Error() string { return e.err.Error() }

func (e usageError) Unwrap() error { return e.err }

func usageErrorf(format string, args ...any) error {
	return usageError{fmt.Errorf(format, args...)}
}

// runtimeError 标记运行期失败，退出码 1（被信号中断的一元命令为 130）。
type runtimeError struct {
	err error
	msg string
}

func (e runtimeError) Error() string { return e.msg }

func (e runtimeError) Unwrap() error { return e.err }

// wrapRuntime 把 api / 渲染 / 输出的错误包成运行期失败，并组装用户文案。
func (a *App) wrapRuntime(err error) error {
	if err == nil {
		return nil
	}
	var ue usageError
	if errors.As(err, &ue) {
		return err
	}
	var re runtimeError
	if errors.As(err, &re) {
		return err
	}
	return runtimeError{err: err, msg: a.describe(err)}
}

// describe 按 api.ErrorKind 组装面向用户的英文文案。
func (a *App) describe(err error) string {
	var se *api.StatusError
	if !errors.As(err, &se) {
		return err.Error()
	}
	switch se.Kind {
	case api.ErrorUnavailable:
		return fmt.Sprintf(
			"cannot connect to the CLI service (socket: %s): %s; the daemon may not be running or --socket is incorrect",
			a.opts.Socket, se.Message)
	case api.ErrorDeadlineExceeded:
		return fmt.Sprintf("request timed out (--timeout=%s)", a.opts.Timeout)
	case api.ErrorUnimplemented:
		return fmt.Sprintf("%s is not implemented by the server: %s", se.Op, se.Message)
	case api.ErrorInvalidArgument:
		return se.Message
	case api.ErrorPermissionDenied:
		return fmt.Sprintf("permission denied for socket %s: %s", a.opts.Socket, se.Message)
	case api.ErrorResourceExhausted:
		return fmt.Sprintf("stream limit reached: %s", se.Message)
	case api.ErrorCanceled:
		return fmt.Sprintf("%s canceled", se.Op)
	default:
		return fmt.Sprintf("%s failed (%s): %s", se.Op, se.Code, se.Message)
	}
}

// ExitCode 把命令返回的错误归类为进程退出码。
func ExitCode(err error, interrupted bool) int {
	if err == nil {
		return 0
	}
	// 下游提前关闭管道不是失败。
	if errors.Is(err, syscall.EPIPE) {
		return 0
	}
	var re runtimeError
	if !errors.As(err, &re) {
		return 2
	}
	if interrupted && isCanceled(re.err) {
		return 130
	}
	return 1
}

func isCanceled(err error) bool {
	var se *api.StatusError
	if errors.As(err, &se) {
		return se.Kind == api.ErrorCanceled
	}
	return errors.Is(err, context.Canceled)
}
