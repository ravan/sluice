package pipeline

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ravan/sluice/pkg/config"
	"github.com/ravan/sluice/pkg/guacseam"
	"github.com/ravan/sluice/pkg/varve"
)

type accountingSink struct {
	calls  int
	failOn int
}

func (s *accountingSink) Ingest(context.Context, varve.Stream) (varve.Receipt, error) {
	s.calls++
	if s.calls == s.failOn {
		return varve.Receipt{}, &varve.IngestError{Status: 503, Committed: varve.Receipt{Nodes: 2, Transactions: 1, Basis: 9}}
	}
	return varve.Receipt{Nodes: 3, Transactions: 1, Basis: 8}, nil
}

func TestExpansionFailuresReachPipelineReceipt(t *testing.T) {
	cfg := config.Config{Receivers: config.Receivers{Files: &config.FilesReceiver{Path: "../../testdata/sboms/small-spdx.json"}}}
	cfg.Processors.Expand.DepsDev = true
	cfg.Processors.Expand.MaxDocs = 5
	sink := &accountingSink{}
	want := errors.New("malformed expansion")
	rec, err := run(context.Background(), cfg, Deps{Sink: sink}, func(context.Context, []string, int, guacseam.DocumentFunc) (guacseam.Expansion, error) {
		return guacseam.Expansion{Collected: 1, Failed: []guacseam.FailedDocument{{Source: "deps.dev:bad", Err: want}}}, nil
	})
	if err != nil || len(rec.Skipped) != 1 || !errors.Is(rec.Skipped[0].Err, want) || sink.calls != 1 {
		t.Fatalf("receipt=%+v, err=%v calls=%d", rec, err, sink.calls)
	}
}

func TestExpansionSinkFailureStopsPollWithCommittedProgress(t *testing.T) {
	cfg := config.Config{Receivers: config.Receivers{Files: &config.FilesReceiver{Path: "../../testdata/sboms/small-spdx.json", Poll: time.Millisecond}}}
	cfg.Processors.Expand.DepsDev = true
	cfg.Processors.Expand.MaxDocs = 5
	sink := &accountingSink{failOn: 2}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	rec, err := run(ctx, cfg, Deps{Sink: sink}, func(ctx context.Context, _ []string, _ int, handle guacseam.DocumentFunc) (guacseam.Expansion, error) {
		return guacseam.Expansion{}, handle(ctx, guacseam.Parsed{Source: "expansion", Origin: guacseam.OriginExpansion})
	})
	var ingestErr *varve.IngestError
	if !errors.As(err, &ingestErr) || rec.Nodes != 5 || rec.Transactions != 2 || rec.Basis != 9 || sink.calls != 2 {
		t.Fatalf("receipt=%+v, err=%v calls=%d", rec, err, sink.calls)
	}
}

type cancelDecorator struct{ cancel context.CancelFunc }

func (d cancelDecorator) Decorate(context.Context, DecorateInput) (varve.Stream, error) {
	d.cancel()
	return varve.Stream{}, nil
}

type contextSink struct{ calls int }

func (s *contextSink) Ingest(ctx context.Context, _ varve.Stream) (varve.Receipt, error) {
	s.calls++
	return varve.Receipt{}, ctx.Err()
}
func TestOneShotFinalFlushUsesDrainContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cfg := config.Config{Receivers: config.Receivers{Files: &config.FilesReceiver{Path: "../../testdata/sboms/small-spdx.json"}}}
	sink := &contextSink{}
	_, err := Run(ctx, cfg, Deps{Sink: sink, Decorators: []Decorator{cancelDecorator{cancel}}})
	if err != nil || sink.calls != 1 {
		t.Fatalf("flush calls=%d err=%v", sink.calls, err)
	}
}

func run(ctx context.Context, cfg config.Config, deps Deps, expand expandFunc) (Receipt, error) {
	deps.expand = expand
	return Run(ctx, cfg, deps)
}

type drainingSink struct {
	cancel    context.CancelFunc
	completed bool
}

func (s *drainingSink) Ingest(ctx context.Context, _ varve.Stream) (varve.Receipt, error) {
	s.cancel()
	select {
	case <-ctx.Done():
		return varve.Receipt{}, ctx.Err()
	case <-time.After(20 * time.Millisecond):
		s.completed = true
		return varve.Receipt{Transactions: 1}, nil
	}
}
func TestPollingSinkDrainsAcceptedWrite(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cfg := config.Config{Receivers: config.Receivers{Files: &config.FilesReceiver{Path: "../../testdata/sboms/small-spdx.json", Poll: time.Millisecond}}}
	sink := &drainingSink{cancel: cancel}
	rec, err := Run(ctx, cfg, Deps{Sink: sink})
	if err != nil || !sink.completed || rec.Transactions != 1 {
		t.Fatalf("completed=%v receipt=%+v err=%v", sink.completed, rec, err)
	}
}
