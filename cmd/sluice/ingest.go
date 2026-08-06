package main

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/ravan/sluice/internal/config"
	"github.com/ravan/sluice/internal/pipeline"
	"github.com/ravan/sluice/internal/varve"
)

// ingestFlags carries the shared persistent flag values of the `ingest` command.
type ingestFlags struct {
	varveAddr      string
	validFloor     string
	validSkew      time.Duration
	enrichVulns    bool
	enrichLicenses bool
	enrichEOL      bool
	enrichDepsDev  bool
	expandDepsDev  bool
	expandMaxDocs  int
}

func filesReceivers(dir string) config.Receivers {
	return config.Receivers{Files: &config.FilesReceiver{Path: dir}}
}

func ociReceivers(refs []string, registry, insecure bool) config.Receivers {
	return config.Receivers{OCI: &config.OCIReceiver{Refs: refs, Registry: registry, Insecure: insecure}}
}

func s3Receivers(bucket, url, region, path string) config.Receivers {
	return config.Receivers{S3: &config.S3Receiver{Bucket: bucket, URL: url, Region: region, Path: path}}
}

func gcsReceivers(bucket string) config.Receivers {
	return config.Receivers{GCS: &config.GCSReceiver{Bucket: bucket}}
}

// buildIngestConfig assembles the one-shot config.Config from a receiver set and
// the shared flags (parses --valid-floor; wires Processors + Sink).
func buildIngestConfig(recv config.Receivers, f ingestFlags) (config.Config, error) {
	floor, err := time.Parse(time.RFC3339, f.validFloor)
	if err != nil {
		return config.Config{}, fmt.Errorf("parsing --valid-floor: %w", err)
	}
	return config.Config{
		Receivers: recv,
		Processors: config.Processors{
			ValidTime: config.ValidTimeProcessor{Floor: floor.UTC(), FutureSkew: f.validSkew},
			Enrich:    config.EnrichProcessor{Vulns: f.enrichVulns, Licenses: f.enrichLicenses, EOL: f.enrichEOL, DepsDev: f.enrichDepsDev},
			Expand:    config.ExpandProcessor{DepsDev: f.expandDepsDev, MaxDocs: f.expandMaxDocs},
		},
		Sink: config.Sink{Varve: config.VarveSink{Addr: f.varveAddr, TokenEnv: "VARVE_TOKEN"}},
	}, nil
}

// runIngest performs the token-check → client → pipeline.Run → print-receipt flow
// shared by every ingest subcommand. Returns a non-nil error when documents were
// skipped so the CLI exits non-zero.
func runIngest(cmd *cobra.Command, cfg config.Config, varveAddr string) error {
	token := os.Getenv("VARVE_TOKEN")
	if token == "" {
		return fmt.Errorf("VARVE_TOKEN environment variable is not set")
	}
	now := time.Now().UTC()
	client, err := varve.NewClient(varve.ClientConfig{Addr: varveAddr, Token: token})
	if err != nil {
		return fmt.Errorf("configuring Varve client: %w", err)
	}
	receipt, runErr := pipeline.Run(cmd.Context(), cfg, pipeline.Deps{Sink: client, Now: func() time.Time { return now }})
	fmt.Fprintln(cmd.OutOrStdout(), receipt.String())
	if runErr != nil {
		return runErr
	}
	if len(receipt.Skipped) > 0 {
		return fmt.Errorf("%d document(s) skipped", len(receipt.Skipped))
	}
	return nil
}

func ingestCmd() *cobra.Command {
	var flags ingestFlags

	cmd := &cobra.Command{
		Use:   "ingest",
		Short: "Ingest supply-chain documents into Varve",
	}
	cmd.PersistentFlags().StringVar(&flags.varveAddr, "varve-addr", "http://127.0.0.1:8080",
		"Varve writer base URL")
	cmd.PersistentFlags().StringVar(&flags.validFloor, "valid-floor", "2000-01-01T00:00:00Z",
		"reject document timestamps earlier than this RFC3339 instant")
	cmd.PersistentFlags().DurationVar(&flags.validSkew, "valid-skew", 5*time.Minute,
		"reject document timestamps later than now plus this tolerance")
	cmd.PersistentFlags().BoolVar(&flags.enrichVulns, "enrich-vulns", false,
		"scan document purls for vulnerabilities (OSV) and fold the evidence in")
	cmd.PersistentFlags().BoolVar(&flags.enrichLicenses, "enrich-licenses", false,
		"scan document purls for license/source facts (ClearlyDefined)")
	cmd.PersistentFlags().BoolVar(&flags.enrichEOL, "enrich-eol", false,
		"scan document purls for end-of-life metadata (endoflife.date)")
	cmd.PersistentFlags().BoolVar(&flags.enrichDepsDev, "enrich-deps-dev", false,
		"scan document purls for scorecard/source facts (deps.dev)")
	cmd.PersistentFlags().BoolVar(&flags.expandDepsDev, "expand-deps-dev", false,
		"fetch transitive dependencies of document purls (deps.dev) as new documents")
	cmd.PersistentFlags().IntVar(&flags.expandMaxDocs, "expand-max-docs", 500,
		"per-run budget for deps.dev expansion documents")

	files := &cobra.Command{
		Use:   "files <dir>",
		Short: "Ingest every document in a directory in a single pass",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := buildIngestConfig(filesReceivers(args[0]), flags)
			if err != nil {
				return err
			}
			return runIngest(cmd, cfg, flags.varveAddr)
		},
	}

	var ociRegistry, ociInsecure bool
	oci := &cobra.Command{
		Use:   "oci <ref> [<ref>...]",
		Short: "Ingest SBOMs attached to OCI artifacts in a single pass",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := buildIngestConfig(ociReceivers(args, ociRegistry, ociInsecure), flags)
			if err != nil {
				return err
			}
			return runIngest(cmd, cfg, flags.varveAddr)
		},
	}
	oci.Flags().BoolVar(&ociRegistry, "oci-registry", false, "treat refs as registry hosts and collect whole registries")
	oci.Flags().BoolVar(&ociInsecure, "oci-insecure", false, "use plain HTTP / skip TLS verification (for local registries)")

	var s3URL, s3Region, s3Path string
	s3 := &cobra.Command{
		Use:   "s3 <bucket>",
		Short: "Ingest SBOMs from an S3 bucket in a single pass",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := buildIngestConfig(s3Receivers(args[0], s3URL, s3Region, s3Path), flags)
			if err != nil {
				return err
			}
			return runIngest(cmd, cfg, flags.varveAddr)
		},
	}
	s3.Flags().StringVar(&s3URL, "s3-url", "", "custom S3 endpoint (e.g. MinIO); empty for AWS SDK defaults")
	s3.Flags().StringVar(&s3Region, "s3-region", "", "S3 region; empty for the collector default")
	s3.Flags().StringVar(&s3Path, "s3-path", "", "folder prefix within the bucket")

	gcs := &cobra.Command{
		Use:   "gcs <bucket>",
		Short: "Ingest SBOMs from a GCS bucket in a single pass",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := buildIngestConfig(gcsReceivers(args[0]), flags)
			if err != nil {
				return err
			}
			return runIngest(cmd, cfg, flags.varveAddr)
		},
	}

	cmd.AddCommand(files, oci, s3, gcs)
	return cmd
}
