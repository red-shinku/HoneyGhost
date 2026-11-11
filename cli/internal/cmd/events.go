package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"honeyghost/cli/internal/api"
	"honeyghost/cli/internal/model"
	"honeyghost/cli/internal/render"
	"honeyghost/cli/internal/selector"
)

type eventsOptions struct {
	Types     []string
	Info      []string
	Duration  time.Duration
	WritePath string
	Tee       bool
}

func newEventsCommand(app *App) *cobra.Command {
	var opts eventsOptions
	var types []model.EventType
	var runtimeSelector model.RuntimeSelector

	cmd := &cobra.Command{
		Use:   "events",
		Short: "Stream runtime events",
		Args:  cobra.NoArgs,
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			if flag := cmd.Flags().Lookup("timeout"); flag != nil && flag.Changed {
				return usageErrorf("--timeout is not supported for events; use --duration instead")
			}
			if opts.Duration < 0 {
				return usageErrorf("--duration must not be negative: %s", opts.Duration)
			}
			if flag := cmd.Flags().Lookup("write"); flag != nil && flag.Changed && opts.WritePath == "" {
				return usageErrorf("--write requires a non-empty file path")
			}
			if opts.Tee && opts.WritePath == "" {
				return usageErrorf("--tee requires --write")
			}
			parsedTypes, err := selector.ParseTypes(opts.Types)
			if err != nil {
				return usageError{err}
			}
			parsedSelector, err := selector.ParseSelector(opts.Info)
			if err != nil {
				return usageError{err}
			}
			types = parsedTypes
			runtimeSelector = parsedSelector
			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) (err error) {
			svcs, err := app.Services(cmd.Context())
			if err != nil {
				return app.wrapRuntime(err)
			}

			// 文件在拨号成功后、订阅前创建/截断：连接失败不触碰目标文件。
			var file *os.File
			if opts.WritePath != "" {
				file, err = openEventsFile(opts.WritePath)
				if err != nil {
					return app.wrapRuntime(err)
				}
				defer func() {
					if closeErr := file.Close(); closeErr != nil && err == nil {
						err = app.wrapRuntime(fmt.Errorf("close events file %q: %w", opts.WritePath, closeErr))
					}
				}()
			}

			var out io.Writer
			if opts.WritePath == "" || opts.Tee {
				out = cmd.OutOrStdout()
			}
			var fileWriter io.Writer
			if file != nil {
				fileWriter = file
			}

			err = runEvents(cmd.Context(), eventsRun{
				Out:      out,
				ErrOut:   cmd.ErrOrStderr(),
				Renderer: app.renderer(),
				Format:   app.opts.Format,
				Service:  svcs.Events,
				Selector: runtimeSelector,
				Types:    types,
				Duration: opts.Duration,
				File:     fileWriter,
			})
			if cmd.Context().Err() != nil {
				app.restoreSignals()
			}
			return app.wrapRuntime(err)
		},
	}

	cmd.Flags().StringSliceVarP(&opts.Types, "type", "t", nil,
		"event types: syscall, file, network, ipc (repeatable or comma-separated; default all)")
	cmd.Flags().StringArrayVarP(&opts.Info, "info", "i", nil,
		"runtime filter key=value[,value...] (repeatable; keys: roleID, role, contextID, pid)")
	cmd.Flags().DurationVar(&opts.Duration, "duration", 0,
		"maximum stream duration; 0 means until interrupted")
	cmd.Flags().StringVarP(&opts.WritePath, "write", "w", "",
		"write the event stream to this file instead of stdout")
	cmd.Flags().BoolVar(&opts.Tee, "tee", false,
		"also write the event stream to stdout (requires --write)")
	return cmd
}

// openEventsFile 创建或截断事件数据文件。
//
// 新建文件权限为 0600；已存在的文件保留原权限。父目录不创建。
func openEventsFile(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open events file %q: %w", path, err)
	}
	return file, nil
}

// eventsRun 是事件流命令的运行参数。
type eventsRun struct {
	Out      io.Writer // nil 表示不写 stdout
	ErrOut   io.Writer
	Renderer render.Renderer
	Format   render.Format
	Service  api.EventService
	Selector model.RuntimeSelector
	Types    []model.EventType
	Duration time.Duration
	File     io.Writer // nil 表示不落盘
}

// runEvents 订阅事件流，把每条记录渲染后写入 Out 与 File。
//
// EOF 与上下文取消/到期是正常结束。stdout 的 EPIPE 只在该目标之外没有其他可写
// 目标时按正常结束处理；存在 File 时继续写文件。接收与文件写入错误原样返回。
func runEvents(parent context.Context, run eventsRun) (err error) {
	ctx, cancel := streamContext(parent, run.Duration)
	defer cancel()

	stream, err := run.Service.Subscribe(ctx, run.Selector, run.Types)
	if err != nil {
		return err
	}
	defer stream.Close()

	sink := newRecordSink(run.Renderer, run.Out, run.File)
	defer func() {
		if closeErr := sink.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
	}()

	received := 0
	dropped := uint64(0)
	if run.Format == render.FormatTable {
		defer func() {
			fmt.Fprintf(run.ErrOut, "events: %d received, %d dropped\n", received, dropped)
		}()
	}

	for {
		item, err := stream.Recv()
		if err != nil {
			// 取消时传输层可能先返回 Canceled / DeadlineExceeded，
			// 而 context.Err() 尚未置位；两者都按正常终止处理。
			if errors.Is(err, io.EOF) || ctx.Err() != nil || streamEnded(err) {
				return nil
			}
			return err
		}

		if item.Stats != nil {
			changed := item.Stats.DroppedEvents != dropped
			dropped = item.Stats.DroppedEvents
			if run.Format == render.FormatJSON {
				if err := sink.Stats(*item.Stats); err != nil {
					return err
				}
			} else if changed {
				fmt.Fprintf(run.ErrOut, "dropped events: %d\n", dropped)
			}
			if !sink.Active() {
				return nil
			}
			continue
		}

		if item.Event == nil {
			continue
		}
		if err := sink.Event(*item.Event); err != nil {
			return err
		}
		if !sink.Active() {
			return nil
		}
		received++
	}
}

func streamContext(parent context.Context, duration time.Duration) (context.Context, context.CancelFunc) {
	if duration > 0 {
		return context.WithTimeout(parent, duration)
	}
	return context.WithCancel(parent)
}

func isEPIPE(err error) bool {
	return errors.Is(err, syscall.EPIPE)
}

// streamEnded 报告错误是否表示本次订阅被取消或到期。
func streamEnded(err error) bool {
	var statusErr *api.StatusError
	if errors.As(err, &statusErr) {
		return statusErr.Kind == api.ErrorCanceled ||
			statusErr.Kind == api.ErrorDeadlineExceeded
	}
	return errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded)
}
