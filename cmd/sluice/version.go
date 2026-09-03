package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

const version = "0.0.0-dev"

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the sluice version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := fmt.Fprintln(cmd.OutOrStdout(), version); err != nil {
				return fmt.Errorf("writing version: %w", err)
			}
			return nil
		},
	}
}
