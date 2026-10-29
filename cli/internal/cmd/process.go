package cmd

import (
	"context"
	"io"

	"github.com/spf13/cobra"

	"honeyghost/cli/internal/api"
	"honeyghost/cli/internal/render"
)

func newProcessCommand(app *App) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "process",
		Short: "Inspect processes",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}
	cmd.AddCommand(newProcessStatsCommand(app))
	return cmd
}

func newProcessStatsCommand(app *App) *cobra.Command {
	return &cobra.Command{
		Use:   "stats",
		Short: "Show process manager counters",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			svcs, err := app.Services(cmd.Context())
			if err != nil {
				return app.wrapRuntime(err)
			}
			ctx, cancel := app.QueryContext(cmd.Context())
			defer cancel()
			return app.wrapRuntime(runProcessStats(ctx, cmd.OutOrStdout(),
				app.renderer(), svcs.Process))
		},
	}
}

func runProcessStats(ctx context.Context, out io.Writer, r render.Renderer,
	svc api.ProcessService) error {
	stats, err := svc.Stats(ctx)
	if err != nil {
		return err
	}
	return r.ProcessStats(out, stats)
}
