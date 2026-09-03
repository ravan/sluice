package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/ravan/sluice/pkg/config"
	"github.com/ravan/sluice/pkg/enrich"
	"github.com/ravan/sluice/pkg/enrich/euvd"
	"github.com/ravan/sluice/pkg/metrics"
	"github.com/ravan/sluice/pkg/pipeline"
	"github.com/ravan/sluice/pkg/varve"
)

var _ pipeline.Observer = (*metrics.Metrics)(nil)

func parseLogLevel(s string) (slog.Level, error) {
	switch s {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("unknown --log-level %q (want debug|info|warn|error)", s)
	}
}

func newLogger(format string, level slog.Level) (*slog.Logger, error) {
	opts := &slog.HandlerOptions{Level: level}
	switch format {
	case "json":
		return slog.New(slog.NewJSONHandler(os.Stderr, opts)), nil
	case "text":
		return slog.New(slog.NewTextHandler(os.Stderr, opts)), nil
	default:
		return nil, fmt.Errorf("unknown --log-format %q (want json|text)", format)
	}
}

func receiverKinds(r config.Receivers) []string {
	var kinds []string
	if r.Files != nil {
		kinds = append(kinds, "files")
	}
	if r.OCI != nil {
		kinds = append(kinds, "oci")
	}
	if r.S3 != nil {
		kinds = append(kinds, "s3")
	}
	if r.GCS != nil {
		kinds = append(kinds, "gcs")
	}
	return kinds
}

func runCmd() *cobra.Command {
	var configPath string
	var metricsAddr string
	var logLevel string
	var logFormat string

	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run the config-driven collector daemon",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			level, err := parseLogLevel(logLevel)
			if err != nil {
				return err
			}
			logger, err := newLogger(logFormat, level)
			if err != nil {
				return err
			}

			cfg, err := config.LoadFile(configPath)
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}

			token := os.Getenv(cfg.Sink.Varve.TokenEnv)
			if token == "" {
				return fmt.Errorf("%s environment variable is not set", cfg.Sink.Varve.TokenEnv)
			}

			m := metrics.New()
			cc := clientConfigFrom(cfg.Sink.Varve, token)
			cc.OnRetry = func(int, time.Duration) { m.SinkRetry() }
			client, err := varve.NewClient(cc)
			if err != nil {
				return fmt.Errorf("configuring Varve client: %w", err)
			}

			ln, err := net.Listen("tcp", metricsAddr)
			if err != nil {
				return fmt.Errorf("binding metrics listener on %s: %w", metricsAddr, err)
			}
			mux := http.NewServeMux()
			mux.Handle("/metrics", m.Handler())
			mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("ok"))
			})
			srv := &http.Server{Handler: mux}
			go func() {
				if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
					logger.Error("metrics server", "error", err)
				}
			}()

			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			logger.Info("daemon started",
				"metrics_addr", ln.Addr().String(),
				"graph", cfg.Sink.Varve.Graph,
				"receivers", strings.Join(receiverKinds(cfg.Receivers), ","))

			euvdEnricher, err := euvd.New(cfg.Processors.Enrich.EUVDURL, nil)
			if err != nil {
				return fmt.Errorf("configuring the EUVD enricher: %w", err)
			}
			rec, runErr := pipeline.Run(ctx, cfg, pipeline.Deps{
				Sink:      client,
				Observer:  m,
				Now:       func() time.Time { return time.Now().UTC() },
				Logger:    logger,
				Enrichers: []enrich.Enricher{euvdEnricher},
			})
			logger.Info("drained",
				"documents", rec.Documents,
				"skipped", len(rec.Skipped),
				"fallbacks", rec.Fallbacks)

			shCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = srv.Shutdown(shCtx)
			return runErr
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to pipeline.yaml (required)")
	cmd.Flags().StringVar(&metricsAddr, "metrics-addr", ":9464", "address for the /metrics and /healthz HTTP server")
	cmd.Flags().StringVar(&logLevel, "log-level", "info", "log level: debug|info|warn|error")
	cmd.Flags().StringVar(&logFormat, "log-format", "json", "log format: json|text")
	_ = cmd.MarkFlagRequired("config")
	return cmd
}
