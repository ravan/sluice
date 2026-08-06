package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/spf13/cobra"

	"github.com/ravan/sluice/internal/assemble"
	"github.com/ravan/sluice/internal/guacseam"
	"github.com/ravan/sluice/internal/validtime"
	"github.com/ravan/sluice/internal/varve"
)

// Reference throughput rates, quoted from the spec — never guessed. Only
// branchEdgesPerSec is a gate (we must strictly beat the branch's per-edge
// path); ingestCapRecordsPerSec is printed for context and never asserted (it
// is a reference-machine figure, not reproducible on an arbitrary laptop).
const (
	branchEdgesPerSec      = 409.0    // spec §7: feat/varve-backend branch, evidence edges over /v1/tx
	ingestCapRecordsPerSec = 166000.0 // spec §1: Varve /v1/ingest bulk capability (reference machine)
)

// benchResult is one bulk-ingest measurement. Elapsed is measured by the shell
// and passed in, so the throughput math stays pure and testable.
type benchResult struct {
	Nodes   int
	Edges   int
	Elapsed time.Duration
}

func (r benchResult) records() int { return r.Nodes + r.Edges }

func (r benchResult) recordsPerSec() float64 {
	if r.Elapsed <= 0 {
		return 0
	}
	return float64(r.records()) / r.Elapsed.Seconds()
}

func (r benchResult) edgesPerSec() float64 {
	if r.Elapsed <= 0 {
		return 0
	}
	return float64(r.Edges) / r.Elapsed.Seconds()
}

func (r benchResult) beatsBranch() bool { return r.edgesPerSec() >= branchEdgesPerSec }

func (r benchResult) report() string {
	gate := "FAIL"
	if r.beatsBranch() {
		gate = "PASS"
	}
	return fmt.Sprintf(
		"bulk /v1/ingest benchmark\n"+
			"  nodes=%d edges=%d records=%d elapsed=%s\n"+
			"  %.0f records/s, %.0f edges/s\n"+
			"  vs ~%.0f evidence-edges/s over /v1/tx (spec §7): %.1fx\n"+
			"  vs ~%.0f records/s /v1/ingest capability (spec §1, reference machine)\n"+
			"  gate (edges/s >= %.0f): %s",
		r.Nodes, r.Edges, r.records(), r.Elapsed,
		r.recordsPerSec(), r.edgesPerSec(),
		branchEdgesPerSec, r.edgesPerSec()/branchEdgesPerSec,
		ingestCapRecordsPerSec,
		branchEdgesPerSec, gate,
	)
}

// benchCmd builds `sluice bench files <dir>`.
func benchCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "bench",
		Short: "Benchmark bulk ingest throughput against the spec reference numbers",
	}
	var varveAddr string
	files := &cobra.Command{
		Use:   "files <dir>",
		Short: "Assemble a whole corpus into one stream, POST it once, and report throughput",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runBench(cmd, args[0], varveAddr)
		},
	}
	files.Flags().StringVar(&varveAddr, "varve-addr", "http://127.0.0.1:8080", "Varve writer base URL")
	cmd.AddCommand(files)
	return cmd
}

// runBench collects every document's predicates from dir, assembles them into
// ONE record stream, times a single client.Ingest, prints result.report(), and
// returns a non-nil error when !result.beatsBranch().
func runBench(cmd *cobra.Command, dir, varveAddr string) error {
	token := os.Getenv("VARVE_TOKEN")
	if token == "" {
		return fmt.Errorf("VARVE_TOKEN environment variable is not set")
	}
	client, err := varve.NewClient(varve.ClientConfig{Addr: varveAddr, Token: token})
	if err != nil {
		return fmt.Errorf("configuring Varve client: %w", err)
	}
	ctx := cmd.Context()
	var all []assembler.IngestPredicates
	fn := func(_ context.Context, _ string, preds []assembler.IngestPredicates, _ []string) error {
		all = append(all, preds...)
		return nil
	}
	if _, err := guacseam.Collect(ctx, guacseam.Sources{Files: &guacseam.FilesReceiver{Path: dir}}, fn); err != nil {
		return fmt.Errorf("collecting %s: %w", dir, err)
	}
	res := assemble.Assemble(ctx, all, validtime.Default(), time.Now().UTC())
	t0 := time.Now()
	_, ingestErr := client.Ingest(ctx, res.Stream)
	elapsed := time.Since(t0)
	if ingestErr != nil {
		return fmt.Errorf("ingesting benchmark stream: %w", ingestErr)
	}
	br := benchResult{Nodes: len(res.Stream.Nodes), Edges: len(res.Stream.Edges), Elapsed: elapsed}
	fmt.Fprintln(cmd.OutOrStdout(), br.report())
	if !br.beatsBranch() {
		return fmt.Errorf("throughput below the branch baseline: %.0f edges/s < %.0f", br.edgesPerSec(), branchEdgesPerSec)
	}
	return nil
}
