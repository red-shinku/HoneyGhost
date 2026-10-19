package cmd

import (
	"context"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"honeyghost/cli/internal/api"
	"honeyghost/cli/internal/model"
	"honeyghost/cli/internal/render"
)

func newContextCommand(app *App) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "context",
		Short: "Inspect contexts",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}
	cmd.AddCommand(
		newContextListCommand(app),
		newContextStatsCommand(app),
		newContextWhichCommand(app),
	)
	return cmd
}

type contextKinds struct {
	Exception bool
	Extra     bool
}

type contextListOptions struct {
	Kinds  []string
	parsed contextKinds
}

func newContextListCommand(app *App) *cobra.Command {
	var opts contextListOptions
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List exception or extra contexts",
		Args:  cobra.NoArgs,
		PreRunE: func(_ *cobra.Command, _ []string) error {
			kinds, err := parseContextKinds(opts.Kinds)
			if err != nil {
				return err
			}
			opts.parsed = kinds
			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			svcs, err := app.Services(cmd.Context())
			if err != nil {
				return app.wrapRuntime(err)
			}
			ctx, cancel := app.QueryContext(cmd.Context())
			defer cancel()
			return app.wrapRuntime(runContextList(ctx, cmd.OutOrStdout(), cmd.ErrOrStderr(),
				app.renderer(), app.opts.Format, svcs.Contexts, opts))
		},
	}
	cmd.Flags().StringSliceVarP(&opts.Kinds, "kind", "k", []string{model.ContextKindException},
		"context kinds: excep, extra, or all (repeatable or comma-separated)")
	return cmd
}

func parseContextKinds(values []string) (contextKinds, error) {
	var kinds contextKinds
	for _, value := range values {
		switch value {
		case model.ContextKindException:
			kinds.Exception = true
		case model.ContextKindExtra:
			kinds.Extra = true
		case "all":
			kinds.Exception = true
			kinds.Extra = true
		default:
			return contextKinds{}, usageErrorf(
				"invalid context kind %q (want excep, extra, or all)", value)
		}
	}
	return kinds, nil
}

func runContextList(ctx context.Context, out, errOut io.Writer, r render.Renderer,
	format render.Format, svc api.ContextService, opts contextListOptions) error {
	var refs []model.ContextRef
	var failures partialError
	succeeded := 0

	if opts.parsed.Exception {
		ids, err := svc.ExceptionIDs(ctx)
		if err != nil {
			failures = append(failures, failure{Label: "excep contexts", Err: err})
		} else {
			succeeded++
			for _, id := range ids {
				refs = append(refs, model.ContextRef{Kind: model.ContextKindException, ID: id})
			}
		}
	}
	if opts.parsed.Extra {
		ids, err := svc.ExtraIDs(ctx)
		if err != nil {
			failures = append(failures, failure{Label: "extra contexts", Err: err})
		} else {
			succeeded++
			for _, id := range ids {
				refs = append(refs, model.ContextRef{Kind: model.ContextKindExtra, ID: id})
			}
		}
	}

	// 没有任何一类成功时不输出数据，避免把失败伪装成空结果。
	if succeeded > 0 {
		if err := r.ContextList(out, refs); err != nil {
			return err
		}
	}
	if len(refs) == 0 && len(failures) == 0 && format == render.FormatTable {
		fmt.Fprintln(errOut, "no matching entries")
	}
	if len(failures) > 0 {
		return failures
	}
	return nil
}

func newContextStatsCommand(app *App) *cobra.Command {
	return &cobra.Command{
		Use:   "stats",
		Short: "Show context manager counters",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			svcs, err := app.Services(cmd.Context())
			if err != nil {
				return app.wrapRuntime(err)
			}
			ctx, cancel := app.QueryContext(cmd.Context())
			defer cancel()
			return app.wrapRuntime(runContextStats(ctx, cmd.OutOrStdout(), app.renderer(), svcs.Contexts))
		},
	}
}

func runContextStats(ctx context.Context, out io.Writer, r render.Renderer,
	svc api.ContextService) error {
	stats, err := svc.Stats(ctx)
	if err != nil {
		return err
	}
	return r.ContextStats(out, stats)
}

func newContextWhichCommand(app *App) *cobra.Command {
	var pid uint32
	cmd := &cobra.Command{
		Use:   "which <pid>",
		Short: "Find the context that owns a pid",
		Args:  cobra.ExactArgs(1),
		PreRunE: func(_ *cobra.Command, args []string) error {
			parsed, err := parsePID(args[0])
			if err != nil {
				return err
			}
			pid = parsed
			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			svcs, err := app.Services(cmd.Context())
			if err != nil {
				return app.wrapRuntime(err)
			}
			ctx, cancel := app.QueryContext(cmd.Context())
			defer cancel()
			return app.wrapRuntime(runContextWhich(ctx, cmd.OutOrStdout(), cmd.ErrOrStderr(),
				app.renderer(), app.opts.Format, svcs.Contexts, pid))
		},
	}
	return cmd
}

func runContextWhich(ctx context.Context, out, errOut io.Writer, r render.Renderer,
	format render.Format, svc api.ContextService, pid uint32) error {
	contextID, found, err := svc.Which(ctx, pid)
	if err != nil {
		return err
	}
	if err := r.WhichContext(out, contextID, found); err != nil {
		return err
	}
	if !found && format == render.FormatTable {
		fmt.Fprintf(errOut, "pid %d has no context\n", pid)
	}
	return nil
}
