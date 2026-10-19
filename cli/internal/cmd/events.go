package cmd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"honeyghost/cli/internal/api"
	"honeyghost/cli/internal/model"
	"honeyghost/cli/internal/render"
	"honeyghost/cli/internal/selector"
)

type eventsOptions struct {
	Types    []string
	Info     []string
	Duration time.Duration
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
		RunE: func(cmd *cobra.Command, _ []string) error {
			svcs, err := app.Services(cmd.Context())
			if err != nil {
				return app.wrapRuntime(err)
			}
			err = runEvents(cmd.Context(), cmd.OutOrStdout(), cmd.ErrOrStderr(),
				app.renderer(), app.opts.Format, svcs.Events, runtimeSelector, types, opts.Duration)
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
	return cmd
}

func runEvents(parent context.Context, out, errOut io.Writer, r render.Renderer,
	format render.Format, svc api.EventService, sel model.RuntimeSelector,
	types []model.EventType, duration time.Duration) error {
	ctx, cancel := streamContext(parent, duration)
	defer cancel()

	stream, err := svc.Subscribe(ctx, sel, types)
	if err != nil {
		return err
	}
	defer stream.Close()

	buffered := bufio.NewWriter(out)
	received := 0
	dropped := uint64(0)
	if format == render.FormatTable {
		defer func() {
			fmt.Fprintf(errOut, "events: %d received, %d dropped\n", received, dropped)
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
			if format == render.FormatJSON {
				if err := r.StreamStats(buffered, *item.Stats); err != nil {
					if isEPIPE(err) {
						return nil
					}
					return err
				}
				if err := buffered.Flush(); err != nil {
					if isEPIPE(err) {
						return nil
					}
					return err
				}
			} else if changed {
				fmt.Fprintf(errOut, "dropped events: %d\n", dropped)
			}
			continue
		}

		if item.Event == nil {
			continue
		}
		if err := r.Event(buffered, *item.Event); err != nil {
			if isEPIPE(err) {
				return nil
			}
			return err
		}
		if err := buffered.Flush(); err != nil {
			if isEPIPE(err) {
				return nil
			}
			return err
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
