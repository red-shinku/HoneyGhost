package cmd

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"

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
		newRoleShowCommand(app),
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

type roleTarget struct {
	roleID uint32
	label  string
	byID   bool
}

type roleShowOptions struct {
	Label bool
}

func newRoleShowCommand(app *App) *cobra.Command {
	var opts roleShowOptions
	var target roleTarget
	cmd := &cobra.Command{
		Use:   "show <id|label>",
		Short: "Show a role's label, processes, and contexts",
		Args:  cobra.ExactArgs(1),
		PreRunE: func(_ *cobra.Command, args []string) error {
			parsed, err := parseRoleTarget(args[0], opts.Label)
			if err != nil {
				return err
			}
			target = parsed
			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			svcs, err := app.Services(cmd.Context())
			if err != nil {
				return app.wrapRuntime(err)
			}
			ctx, cancel := app.QueryContext(cmd.Context())
			defer cancel()
			return app.wrapRuntime(runRoleShow(ctx, cmd.OutOrStdout(), app.renderer(),
				svcs.Roles, target))
		},
	}
	cmd.Flags().BoolVar(&opts.Label, "label", false,
		"treat the argument as a role label")
	return cmd
}

func parseRoleTarget(arg string, forceLabel bool) (roleTarget, error) {
	if forceLabel {
		return roleTarget{label: arg}, nil
	}
	if !isDecimal(arg) {
		return roleTarget{label: arg}, nil
	}
	id, err := parsePositiveUint32("role id", arg)
	if err != nil {
		return roleTarget{}, err
	}
	return roleTarget{roleID: id, byID: true}, nil
}

func isDecimal(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func runRoleShow(ctx context.Context, out io.Writer, r render.Renderer,
	svc api.RoleService, target roleTarget) error {
	var detail model.RoleDetail
	var failures partialError

	if target.byID {
		detail.RoleID = target.roleID
		roles, err := svc.List(ctx, model.RoleScopeAll)
		if err != nil {
			failures = append(failures, failure{Label: "label", Err: err})
		} else {
			role, found := findRole(roles, target.roleID)
			if !found {
				return fmt.Errorf("role %d not found", target.roleID)
			}
			label := role.Label
			detail.Label = &label
		}
	} else {
		roles, err := svc.List(ctx, model.RoleScopeAll)
		if err != nil {
			return err
		}
		matches := matchRoles(roles, target.label)
		switch len(matches) {
		case 0:
			return fmt.Errorf("role %q not found", target.label)
		case 1:
			detail.RoleID = matches[0].ID
			label := matches[0].Label
			detail.Label = &label
		default:
			return fmt.Errorf("role label %q matches multiple roles: %s",
				target.label, formatRoleIDs(matches))
		}
	}

	if processes, err := svc.Processes(ctx, detail.RoleID); err != nil {
		failures = append(failures, failure{Label: "processes", Err: err})
	} else {
		detail.Processes = &processes
	}
	if contextIDs, err := svc.ContextIDs(ctx, detail.RoleID); err != nil {
		failures = append(failures, failure{Label: "contexts", Err: err})
	} else {
		detail.ContextIDs = &contextIDs
	}

	if err := r.RoleDetail(out, detail); err != nil {
		return err
	}
	if len(failures) > 0 {
		return failures
	}
	return nil
}

func findRole(roles []model.Role, id uint32) (model.Role, bool) {
	for _, role := range roles {
		if role.ID == id {
			return role, true
		}
	}
	return model.Role{}, false
}

func matchRoles(roles []model.Role, label string) []model.Role {
	var matches []model.Role
	for _, role := range roles {
		if role.Label == label {
			matches = append(matches, role)
		}
	}
	return matches
}

func formatRoleIDs(roles []model.Role) string {
	ids := make([]string, 0, len(roles))
	for _, role := range roles {
		ids = append(ids, strconv.FormatUint(uint64(role.ID), 10))
	}
	return strings.Join(ids, ", ")
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
	return parsePositiveUint32("pid", arg)
}

func parsePositiveUint32(name, arg string) (uint32, error) {
	value, err := strconv.ParseUint(arg, 10, 32)
	if err != nil {
		return 0, usageErrorf("%s must be a positive integer: %q", name, arg)
	}
	if value == 0 {
		return 0, usageErrorf("%s must be greater than 0: %q", name, arg)
	}
	return uint32(value), nil
}
