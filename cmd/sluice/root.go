package main

import "github.com/spf13/cobra"

func rootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "sluice",
		Short:         "Collect software supply-chain metadata into Varve, the bitemporal graph database",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.AddCommand(versionCmd())
	cmd.AddCommand(ingestCmd())
	cmd.AddCommand(runCmd())
	cmd.AddCommand(benchCmd())
	return cmd
}
