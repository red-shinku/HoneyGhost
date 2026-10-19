package cmd

import (
	"context"
	"io"

	"github.com/spf13/cobra"

	"honeyghost/cli/internal/api"
	"honeyghost/cli/internal/model"
	"honeyghost/cli/internal/render"
)

func newStatusCommand(app *App) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show an overview of the runtime",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			svcs, err := app.Services(cmd.Context())
			if err != nil {
				return app.wrapRuntime(err)
			}
			ctx, cancel := app.QueryContext(cmd.Context())
			defer cancel()
			return app.wrapRuntime(runStatus(ctx, cmd.OutOrStdout(), app.renderer(), svcs))
		},
	}
}

func runStatus(ctx context.Context, out io.Writer, r render.Renderer, svcs api.Services) error {
	var status model.Status
	var failures partialError

	if roles, err := svcs.Roles.List(ctx, model.RoleScopeSupervision); err != nil {
		failures = append(failures, failure{Label: "supervised roles", Err: err})
	} else {
		count := len(roles)
		status.SupervisedRoleCount = &count
	}

	if ids, err := svcs.Contexts.ExceptionIDs(ctx); err != nil {
		failures = append(failures, failure{Label: "exception contexts", Err: err})
	} else {
		count := len(ids)
		status.ExceptionContextCount = &count
	}

	if ids, err := svcs.Contexts.ExtraIDs(ctx); err != nil {
		failures = append(failures, failure{Label: "extra contexts", Err: err})
	} else {
		count := len(ids)
		status.ExtraContextCount = &count
	}

	if stats, err := svcs.Roles.Stats(ctx); err != nil {
		failures = append(failures, failure{Label: "role stats", Err: err})
	} else {
		status.RoleStats = &stats
	}

	if stats, err := svcs.Contexts.Stats(ctx); err != nil {
		failures = append(failures, failure{Label: "context stats", Err: err})
	} else {
		status.ContextStats = &stats
	}

	if err := r.Status(out, status); err != nil {
		return err
	}
	if len(failures) > 0 {
		return failures
	}
	return nil
}
