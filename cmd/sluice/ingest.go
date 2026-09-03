package main

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/ravan/sluice/pkg/config"
	"github.com/ravan/sluice/pkg/enrich"
	"github.com/ravan/sluice/pkg/enrich/euvd"
	"github.com/ravan/sluice/pkg/enrich/vulnerablecode"
	"github.com/ravan/sluice/pkg/pipeline"
	"github.com/ravan/sluice/pkg/varve"
)

// ingestFlags carries the shared persistent flag values of the `ingest` command.
type ingestFlags struct {
	varveAddr      string
	varveGraph     string
	validFloor     string
	validSkew      time.Duration
	enrichSources  []string
	enrichEUOnly   bool
	euvdURL        string
	vcURL          string
	vcJurisdiction string
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
	jurisdiction, err := enrich.ParseJurisdiction(f.vcJurisdiction)
	if err != nil {
		return config.Config{}, fmt.Errorf("parsing --vulnerablecode-jurisdiction: %w", err)
	}
	hosted := map[enrich.Source]enrich.Jurisdiction{enrich.SourceVulnerableCode: jurisdiction}
	policy, err := enrich.ParsePolicy(f.enrichSources, f.enrichEUOnly, hosted)
	if err != nil {
		return config.Config{}, fmt.Errorf("parsing --enrich: %w", err)
	}
	return config.Config{
		Receivers: recv,
		Processors: config.Processors{
			ValidTime: config.ValidTimeProcessor{Floor: floor.UTC(), FutureSkew: f.validSkew},
			Enrich: config.EnrichProcessor{
				Policy:         policy,
				EUVDURL:        f.euvdURL,
				VulnerableCode: config.VulnerableCodeProcessor{URL: f.vcURL, Jurisdiction: jurisdiction},
			},
			Expand: config.ExpandProcessor{DepsDev: f.expandDepsDev, MaxDocs: f.expandMaxDocs},
		},
		Sink: config.Sink{Varve: config.VarveSink{Addr: f.varveAddr, TokenEnv: "VARVE_TOKEN", Graph: f.varveGraph}},
	}, nil
}

// clientConfigFrom maps the config's sink declaration plus the resolved token
// to a varve.ClientConfig. Both front-ends build their client through it.
func clientConfigFrom(sink config.VarveSink, token string) varve.ClientConfig {
	return varve.ClientConfig{Addr: sink.Addr, Token: token, Graph: sink.Graph}
}

// runIngest performs the token-check → client → pipeline.Run → print-receipt flow
// shared by every ingest subcommand. Returns a non-nil error when documents were
// skipped so the CLI exits non-zero.
func runIngest(cmd *cobra.Command, cfg config.Config) error {
	token := os.Getenv(cfg.Sink.Varve.TokenEnv)
	if token == "" {
		return fmt.Errorf("%s environment variable is not set", cfg.Sink.Varve.TokenEnv)
	}
	now := time.Now().UTC()
	client, err := varve.NewClient(clientConfigFrom(cfg.Sink.Varve, token))
	if err != nil {
		return fmt.Errorf("configuring Varve client: %w", err)
	}
	euvdEnricher, err := euvd.New(cfg.Processors.Enrich.EUVDURL, nil)
	if err != nil {
		return fmt.Errorf("configuring the EUVD enricher: %w", err)
	}
	vcEnricher, err := vulnerablecode.New(cfg.Processors.Enrich.VulnerableCode.URL, nil)
	if err != nil {
		return fmt.Errorf("configuring the VulnerableCode enricher: %w", err)
	}
	receipt, runErr := pipeline.Run(cmd.Context(), cfg, pipeline.Deps{
		Sink:      client,
		Now:       func() time.Time { return now },
		Enrichers: []enrich.Enricher{euvdEnricher, vcEnricher},
	})
	if _, werr := fmt.Fprintln(cmd.OutOrStdout(), receipt.String()); werr != nil && runErr == nil {
		return fmt.Errorf("writing receipt: %w", werr)
	}
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
	cmd.PersistentFlags().StringVar(&flags.varveGraph, "varve-graph", "",
		"named Varve graph to ingest into (empty: the writer's default graph)")
	cmd.PersistentFlags().StringVar(&flags.validFloor, "valid-floor", "2000-01-01T00:00:00Z",
		"reject document timestamps earlier than this RFC3339 instant")
	cmd.PersistentFlags().DurationVar(&flags.validSkew, "valid-skew", 5*time.Minute,
		"reject document timestamps later than now plus this tolerance")
	cmd.PersistentFlags().StringSliceVar(&flags.enrichSources, "enrich", nil,
		"enrichment source to run, in priority order; repeatable (euvd|vulnerablecode|osv|clearlydefined|eol|deps_dev)")
	cmd.PersistentFlags().BoolVar(&flags.enrichEUOnly, "eu-only", false,
		"run only enrichment sources whose host sits in the EU")
	cmd.PersistentFlags().StringVar(&flags.euvdURL, "euvd-url", euvd.DefaultURL,
		"EUVD API base URL")
	cmd.PersistentFlags().StringVar(&flags.vcURL, "vulnerablecode-url", vulnerablecode.DefaultURL,
		"VulnerableCode API base URL")
	cmd.PersistentFlags().StringVar(&flags.vcJurisdiction, "vulnerablecode-jurisdiction", string(enrich.US),
		"jurisdiction of the VulnerableCode host --vulnerablecode-url names (eu|us|other)")
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
			return runIngest(cmd, cfg)
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
			return runIngest(cmd, cfg)
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
			return runIngest(cmd, cfg)
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
			return runIngest(cmd, cfg)
		},
	}

	cmd.AddCommand(files, oci, s3, gcs)
	return cmd
}
