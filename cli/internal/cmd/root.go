// Package cmd 组织 Cobra 命令树并承载命令逻辑。
//
// 本包只依赖 api 与 model；传输层由 main 通过 DialFunc 注入。
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// BuildInfo 是由 -ldflags -X 注入的版本信息。
type BuildInfo struct {
	Version string
	Commit  string
	Date    string
}

// String 返回 version 命令与 --version 共用的格式。
func (b BuildInfo) String() string {
	return fmt.Sprintf("%s (%s, %s)", b.Version, b.Commit, b.Date)
}

// NewRootCommand 构建根命令。无参数执行时打印帮助并以 0 退出。
func NewRootCommand(app *App, info BuildInfo) *cobra.Command {
	root := &cobra.Command{
		Use:           "hghost",
		Short:         "Query and observe the HoneyGhost runtime",
		Long:          "hghost queries the HoneyGhost runtime over a local Unix socket.",
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       info.String(),
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}
	root.SetVersionTemplate("hghost {{.Version}}\n")
	// 预定义 --version 以阻止 Cobra 自动附加 -v 简写（设计只提供长选项）。
	root.Flags().Bool("version", false, "print version information and exit")
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return usageError{err}
	})
	root.PersistentPreRunE = func(*cobra.Command, []string) error {
		return app.validateFlags()
	}

	flags := root.PersistentFlags()
	flags.StringVar(&app.opts.Socket, "socket", app.opts.Socket,
		"path to the server's Unix socket (env HGHOST_SOCKET)")
	flags.DurationVar(&app.opts.Timeout, "timeout", app.opts.Timeout,
		"total timeout for one-shot commands; 0 means no limit")
	flags.StringVarP(&app.output, "output", "o", app.output,
		"output format: table or json")
	flags.BoolVar(&app.opts.NoHeaders, "no-headers", false,
		"omit table headers (ignored in JSON mode)")

	root.AddCommand(newVersionCommand(info))
	return root
}

func newVersionCommand(info BuildInfo) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmt.Fprintf(cmd.OutOrStdout(), "hghost %s\n", info.String())
			return nil
		},
	}
}
