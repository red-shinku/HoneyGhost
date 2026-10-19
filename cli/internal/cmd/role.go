package cmd

import (
	"context"
	"fmt"
	"io"
	"strconv"

	"github.com/spf13/cobra"

	"honeyghost/cli/internal/api"
	"honeyghost/cli/internal/model"
	"honeyghost/cli/internal/render"
)

func newRoleCommand(app *App) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "role",
		Short: "Inspect roles",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}
	cmd.AddCommand(
		newRoleListCommand(app),
		newRoleStatsCommand(app),
		newRoleWhichCommand(app),
	)
	return cmd
}

type roleListOptions struct {
	All bool
}

func newRoleListCommand(app *App) *cobra.Command {
	var opts roleListOptions
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List roles",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			svcs, err := app.Services(cmd.Context())
			if err != nil {
				return app.wrapRuntime(err)
			}
			ctx, cancel := app.QueryContext(cmd.Context())
			defer cancel()
			return app.wrapRuntime(runRoleList(ctx, cmd.OutOrStdout(), cmd.ErrOrStderr(),
				app.renderer(), app.opts.Format, svcs.Roles, opts))
		},
	}
	cmd.Flags().BoolVarP(&opts.All, "all", "a", false,
		"list all roles instead of supervised roles only")
	return cmd
}

func runRoleList(ctx context.Context, out, errOut io.Writer, r render.Renderer,
	format render.Format, svc api.RoleService, opts roleListOptions) error {
	scope := model.RoleScopeSupervision
	if opts.All {
		scope = model.RoleScopeAll
	}
	roles, err := svc.List(ctx, scope)
	if err != nil {
		return err
	}
	if err := r.Roles(out, roles); err != nil {
		return err
	}
	if len(roles) == 0 && format == render.FormatTable {
		fmt.Fprintln(errOut, "no matching entries")
	}
	return nil
}

func newRoleStatsCommand(app *App) *cobra.Command {
	return &cobra.Command{
		Use:   "stats",
		Short: "Show role manager counters",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			svcs, err := app.Services(cmd.Context())
			if err != nil {
				return app.wrapRuntime(err)
			}
			ctx, cancel := app.QueryContext(cmd.Context())
			defer cancel()
			return app.wrapRuntime(runRoleStats(ctx, cmd.OutOrStdout(), app.renderer(), svcs.Roles))
		},
	}
}

func runRoleStats(ctx context.Context, out io.Writer, r render.Renderer, svc api.RoleService) error {
	stats, err := svc.Stats(ctx)
	if err != nil {
		return err
	}
	return r.RoleStats(out, stats)
}

func newRoleWhichCommand(app *App) *cobra.Command {
	var pid uint32
	cmd := &cobra.Command{
		Use:   "which <pid>",
		Short: "Find the role that owns a pid",
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
			return app.wrapRuntime(runRoleWhich(ctx, cmd.OutOrStdout(), cmd.ErrOrStderr(),
				app.renderer(), app.opts.Format, svcs.Roles, pid))
		},
	}
	return cmd
}

func runRoleWhich(ctx context.Context, out, errOut io.Writer, r render.Renderer,
	format render.Format, svc api.RoleService, pid uint32) error {
	roleID, found, err := svc.Which(ctx, pid)
	if err != nil {
		return err
	}
	if err := r.WhichRole(out, roleID, found); err != nil {
		return err
	}
	if !found && format == render.FormatTable {
		fmt.Fprintf(errOut, "pid %d has no role\n", pid)
	}
	return nil
}

func parsePID(arg string) (uint32, error) {
	value, err := strconv.ParseUint(arg, 10, 32)
	if err != nil {
		return 0, usageErrorf("pid must be a positive integer: %q", arg)
	}
	if value == 0 {
		return 0, usageErrorf("pid must be greater than 0: %q", arg)
	}
	return uint32(value), nil
}
