package pipeline_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ravan/sluice/pkg/config"
	"github.com/ravan/sluice/pkg/enrich"
	"github.com/ravan/sluice/pkg/guacseam"
	"github.com/ravan/sluice/pkg/pipeline"
	"github.com/ravan/sluice/pkg/validtime"
	"github.com/ravan/sluice/pkg/varve"
)

const fixtureDir = "../../testdata/sboms"

var pipeTestNow = time.Date(2026, 8, 7, 0, 0, 0, 0, time.UTC)

type response struct {
	receipt varve.Receipt
	err     error
}

type fakeSink struct {
	responses []response
	streams   []varve.Stream
	calls     int
}

func (f *fakeSink) Ingest(_ context.Context, s varve.Stream) (varve.Receipt, error) {
	f.streams = append(f.streams, s)
	var resp response
	if f.calls < len(f.responses) {
		resp = f.responses[f.calls]
	}
	f.calls++
	return resp.receipt, resp.err
}

func copyFixture(t *testing.T, dir, name string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(fixtureDir, "small-spdx.json"))
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
		t.Fatalf("writing fixture copy %s: %v", name, err)
	}
}

func runOneShot(t *testing.T, dir string, sink pipeline.Sink) (pipeline.Receipt, error) {
	t.Helper()
	return runOneShotPolicy(t, dir, sink, enrich.Policy{}, pipeline.Deps{})
}

// runOneShotWith is runOneShot with an enrichment policy and caller-supplied
// deps; deps.Sink and deps.Now are filled in.
func runOneShotPolicy(t *testing.T, dir string, sink pipeline.Sink, policy enrich.Policy, deps pipeline.Deps) (pipeline.Receipt, error) {
	t.Helper()
	d := validtime.Default()
	cfg := config.Config{
		Receivers: config.Receivers{Files: &config.FilesReceiver{Path: dir}},
		Processors: config.Processors{
			ValidTime: config.ValidTimeProcessor{Floor: d.Floor, FutureSkew: d.Skew},
			Enrich:    config.EnrichProcessor{Policy: policy},
		},
		Sink: config.Sink{Varve: config.VarveSink{Addr: "http://x", TokenEnv: "T"}},
	}
	deps.Sink = sink
	if deps.Now == nil {
		deps.Now = func() time.Time { return pipeTestNow }
	}
	return pipeline.Run(context.Background(), cfg, deps)
}

func TestRunRequiresAReceiver(t *testing.T) {
	cfg := config.Config{
		Receivers:  config.Receivers{},
		Processors: config.Processors{ValidTime: config.ValidTimeProcessor{Floor: validtime.Default().Floor, FutureSkew: validtime.Default().Skew}},
		Sink:       config.Sink{Varve: config.VarveSink{Addr: "http://x", TokenEnv: "T"}},
	}
	_, err := pipeline.Run(context.Background(), cfg, pipeline.Deps{Sink: &fakeSink{}})
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if !strings.Contains(err.Error(), "at least one receiver") {
		t.Errorf("error = %q, want it to contain %q", err.Error(), "at least one receiver")
	}
}

func TestRunFixture(t *testing.T) {
	fake := &fakeSink{responses: []response{
		{receipt: varve.Receipt{Nodes: 6, Edges: 3, Transactions: 1, Basis: 11}},
	}}

	rec, err := runOneShot(t, fixtureDir, fake)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	want := pipeline.Receipt{Documents: 1, Nodes: 6, Edges: 3, Transactions: 1, Basis: 11}
	if rec.Documents != want.Documents || rec.Nodes != want.Nodes || rec.Edges != want.Edges ||
		rec.Transactions != want.Transactions || rec.Basis != want.Basis {
		t.Errorf("receipt = %+v, want %+v", rec, want)
	}
	if len(rec.Skipped) != 0 {
		t.Errorf("Skipped = %+v, want empty", rec.Skipped)
	}
	// small-spdx's created (2020-11-24T01:12:27Z) is in bounds, so its 3 HasSBOM
	// assertions do not fall back.
	if rec.Fallbacks != 0 {
		t.Errorf("Fallbacks = %d, want 0", rec.Fallbacks)
	}
	if fake.calls != 1 {
		t.Fatalf("sink called %d times, want 1", fake.calls)
	}
	s := fake.streams[0]
	if len(s.Nodes) != 9 || len(s.Edges) != 6 {
		t.Errorf("stream has %d nodes / %d edges, want 9 / 6", len(s.Nodes), len(s.Edges))
	}
	var pkgVersion, pkgName, hasSBOM int
	for _, n := range s.Nodes {
		for _, l := range n.Labels {
			switch l {
			case "PkgVersion":
				pkgVersion++
			case "PkgName":
				pkgName++
			case "HasSBOM":
				hasSBOM++
			}
		}
	}
	if pkgVersion != 3 || pkgName != 3 || hasSBOM != 3 {
		t.Errorf("node labels: %d PkgVersion / %d PkgName / %d HasSBOM, want 3 / 3 / 3", pkgVersion, pkgName, hasSBOM)
	}
	var pkgHasVersion, hasSbomSubject int
	for _, e := range s.Edges {
		switch e.Label {
		case "PkgHasVersion":
			pkgHasVersion++
		case "HasSbomSubject":
			hasSbomSubject++
		}
	}
	if pkgHasVersion != 3 || hasSbomSubject != 3 {
		t.Errorf("edge labels: %d PkgHasVersion / %d HasSbomSubject, want 3 / 3", pkgHasVersion, hasSbomSubject)
	}
}

func TestRunBatchesOneShotIntoASingleIngest(t *testing.T) {
	dir := t.TempDir()
	copyFixture(t, dir, "a.json")
	copyFixture(t, dir, "b.json")

	fake := &fakeSink{responses: []response{
		{receipt: varve.Receipt{Nodes: 12, Edges: 9, Transactions: 1, Basis: 11}},
	}}

	rec, err := runOneShot(t, dir, fake)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	want := pipeline.Receipt{Documents: 2, Nodes: 12, Edges: 9, Transactions: 1, Basis: 11}
	if rec.Documents != want.Documents || rec.Nodes != want.Nodes || rec.Edges != want.Edges ||
		rec.Transactions != want.Transactions || rec.Basis != want.Basis {
		t.Errorf("receipt = %+v, want %+v", rec, want)
	}
	if len(rec.Skipped) != 0 {
		t.Errorf("Skipped = %+v, want empty", rec.Skipped)
	}
	// One pass ⇒ one sink call. The two copies share identity nodes (3 PkgVersion
	// + 3 PkgName dedup away) while HasSBOM evidence stays per-document (its id
	// folds Origin, the source path): 12 nodes / 9 edges, not 2×(9 / 6).
	if fake.calls != 1 {
		t.Fatalf("sink called %d times, want 1 (one-shot batches the pass)", fake.calls)
	}
	s := fake.streams[0]
	if len(s.Nodes) != 12 || len(s.Edges) != 9 {
		t.Errorf("batched stream has %d nodes / %d edges, want 12 / 9 (identity dedup, per-document evidence)", len(s.Nodes), len(s.Edges))
	}
	if got := countPkgVersion(s); got != 3 {
		t.Errorf("batched stream PkgVersion = %d, want 3 (cross-document identity dedup)", got)
	}
}

func TestRunSkipsBadDocument(t *testing.T) {
	dir := t.TempDir()
	copyFixture(t, dir, "small-spdx.json")
	if err := os.WriteFile(filepath.Join(dir, "bad.json"), []byte(`{"not":"a document"}`), 0o600); err != nil {
		t.Fatalf("writing bad.json: %v", err)
	}

	fake := &fakeSink{responses: []response{
		{receipt: varve.Receipt{Nodes: 6, Edges: 3, Transactions: 1, Basis: 11}},
	}}

	rec, err := runOneShot(t, dir, fake)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rec.Documents != 2 {
		t.Errorf("Documents = %d, want 2", rec.Documents)
	}
	if len(rec.Skipped) != 1 {
		t.Fatalf("Skipped len = %d, want 1: %+v", len(rec.Skipped), rec.Skipped)
	}
	if !strings.Contains(rec.Skipped[0].Source, "bad.json") {
		t.Errorf("skipped source = %q, want it to contain bad.json", rec.Skipped[0].Source)
	}
	if fake.calls != 1 {
		t.Fatalf("sink called %d times, want 1 (the good document only)", fake.calls)
	}
	if len(fake.streams[0].Nodes) != 9 {
		t.Errorf("good stream has %d nodes, want 9", len(fake.streams[0].Nodes))
	}
}

func TestRunSinkFailureFailsRun(t *testing.T) {
	fake := &fakeSink{responses: []response{
		{err: &varve.IngestError{Status: 422, Message: "bad record", Committed: varve.Receipt{Nodes: 4}}},
	}}

	rec, err := runOneShot(t, fixtureDir, fake)
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	var ie *varve.IngestError
	if !errors.As(err, &ie) {
		t.Fatalf("error does not unwrap to *varve.IngestError: %v", err)
	}
	if rec.Documents != 1 {
		t.Errorf("Documents = %d, want 1", rec.Documents)
	}
	if rec.Nodes != 4 {
		t.Errorf("Nodes = %d, want 4 (committed progress, not zero)", rec.Nodes)
	}
	if len(rec.Skipped) != 0 {
		t.Errorf("Skipped = %+v, want empty (a sink failure is not a skipped document)", rec.Skipped)
	}
}

func TestReceiptString(t *testing.T) {
	r := pipeline.Receipt{
		Documents: 2, Nodes: 6, Edges: 3, Transactions: 1, Basis: 11, Fallbacks: 3,
		Skipped: []guacseam.FailedDocument{{Source: "bad.json", Err: errors.New("boom")}},
	}
	s := r.String()
	for _, want := range []string{"documents=2", "nodes=6", "edges=3", "transactions=1", "basis=11", "skipped=1", "fallbacks=3", "expanded=0", "bad.json"} {
		if !strings.Contains(s, want) {
			t.Errorf("String() = %q, missing substring %q", s, want)
		}
	}
}

func TestReceiptStringExpansion(t *testing.T) {
	r := pipeline.Receipt{Documents: 1, Expanded: 2, ExpansionBudget: 2, ExpansionExhausted: true}
	s := r.String()
	for _, want := range []string{"expanded=2", "expansion budget 2"} {
		if !strings.Contains(s, want) {
			t.Errorf("String() = %q, missing substring %q", s, want)
		}
	}
}

func copyFixtureCreated(t *testing.T, dir, name, created string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(fixtureDir, "small-spdx.json"))
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	doctored := strings.Replace(string(data), "2020-11-24T01:12:27Z", created, 1)
	if doctored == string(data) {
		t.Fatalf("fixture did not contain the expected created timestamp to replace")
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(doctored), 0o600); err != nil {
		t.Fatalf("writing fixture copy %s: %v", name, err)
	}
}

func TestRunCountsValidTimeFallbacks(t *testing.T) {
	dir := t.TempDir()
	copyFixtureCreated(t, dir, "epoch-spdx.json", "1970-01-01T00:00:00Z")

	fake := &fakeSink{responses: []response{
		{receipt: varve.Receipt{Nodes: 6, Edges: 3, Transactions: 1, Basis: 11}},
	}}

	rec, err := runOneShot(t, dir, fake)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// The doctored created (1970) is before the guard floor, so all three HasSBOM
	// assertions fall back to ingest time.
	if rec.Fallbacks != 3 {
		t.Errorf("Fallbacks = %d, want 3", rec.Fallbacks)
	}
	var pkgVersion int
	for _, n := range fake.streams[0].Nodes {
		for _, l := range n.Labels {
			if l == "PkgVersion" {
				pkgVersion++
			}
		}
	}
	if pkgVersion != 3 {
		t.Errorf("PkgVersion count = %d, want 3 (time does not change the package count)", pkgVersion)
	}
}

func pollConfig(dir string, poll time.Duration) config.Config {
	d := validtime.Default()
	return config.Config{
		Receivers:  config.Receivers{Files: &config.FilesReceiver{Path: dir, Poll: poll}},
		Processors: config.Processors{ValidTime: config.ValidTimeProcessor{Floor: d.Floor, FutureSkew: d.Skew}},
		Sink:       config.Sink{Varve: config.VarveSink{Addr: "http://x", TokenEnv: "T"}},
	}
}

func countPkgVersion(s varve.Stream) int {
	var n int
	for _, node := range s.Nodes {
		for _, l := range node.Labels {
			if l == "PkgVersion" {
				n++
			}
		}
	}
	return n
}

type pollSink struct {
	got chan varve.Stream
}

func (p *pollSink) Ingest(_ context.Context, s varve.Stream) (varve.Receipt, error) {
	p.got <- s
	return varve.Receipt{}, nil
}

func TestRunPollPicksUpNewFileAndCounts(t *testing.T) {
	dir := t.TempDir()
	sink := &pollSink{got: make(chan varve.Stream, 8)}
	cfg := pollConfig(dir, 25*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	type result struct {
		rec pipeline.Receipt
		err error
	}
	done := make(chan result, 1)
	go func() {
		rec, err := pipeline.Run(ctx, cfg, pipeline.Deps{Sink: sink, Now: func() time.Time { return pipeTestNow }})
		done <- result{rec, err}
	}()

	waitStream := func() varve.Stream {
		t.Helper()
		select {
		case s := <-sink.got:
			return s
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for a stream")
			return varve.Stream{}
		}
	}

	copyFixture(t, dir, "a.json")
	if got := countPkgVersion(waitStream()); got != 3 {
		t.Errorf("first stream PkgVersion = %d, want 3", got)
	}
	copyFixture(t, dir, "b.json")
	if got := countPkgVersion(waitStream()); got != 3 {
		t.Errorf("second stream PkgVersion = %d, want 3", got)
	}

	cancel()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case res := <-done:
			if res.err != nil {
				t.Fatalf("Run returned error on cancel, want nil: %v", res.err)
			}
			return
		case <-sink.got:
		case <-deadline:
			t.Fatal("timed out waiting for Run to return after cancel")
		}
	}
}

type flakySink struct {
	mu    sync.Mutex
	calls int
	sig   chan int
}

func (s *flakySink) Ingest(_ context.Context, _ varve.Stream) (varve.Receipt, error) {
	s.mu.Lock()
	s.calls++
	n := s.calls
	s.mu.Unlock()
	s.sig <- n
	if n == 1 {
		return varve.Receipt{}, &varve.IngestError{Status: 500, Message: "boom"}
	}
	return varve.Receipt{}, nil
}

type countingObserver struct {
	mu             sync.Mutex
	ingested       int
	skipped        int
	failed         int
	decorated      int
	decorateFailed int
}

func (o *countingObserver) DocumentIngested()         { o.mu.Lock(); o.ingested++; o.mu.Unlock() }
func (o *countingObserver) DocumentSkipped()          { o.mu.Lock(); o.skipped++; o.mu.Unlock() }
func (o *countingObserver) DocumentFailed()           { o.mu.Lock(); o.failed++; o.mu.Unlock() }
func (o *countingObserver) RecordsEmitted(_, _ int64) {}
func (o *countingObserver) FallbacksCounted(_ int)    {}
func (o *countingObserver) ExpansionDocuments(_ int)  {}
func (o *countingObserver) DocumentDecorated()        { o.mu.Lock(); o.decorated++; o.mu.Unlock() }
func (o *countingObserver) DocumentDecorateFailed()   { o.mu.Lock(); o.decorateFailed++; o.mu.Unlock() }
func (o *countingObserver) ClaimsEmitted(_ int)       {}
func (o *countingObserver) EnrichFailed(_ string)     {}

func TestRunPollContinuesAfterSinkFailure(t *testing.T) {
	dir := t.TempDir()
	sink := &flakySink{sig: make(chan int, 16)}
	obs := &countingObserver{}
	cfg := pollConfig(dir, 25*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	type result struct {
		rec pipeline.Receipt
		err error
	}
	done := make(chan result, 1)
	go func() {
		rec, err := pipeline.Run(ctx, cfg, pipeline.Deps{Sink: sink, Observer: obs, Now: func() time.Time { return pipeTestNow }})
		done <- result{rec, err}
	}()

	waitCall := func(want int) {
		t.Helper()
		deadline := time.After(5 * time.Second)
		for {
			select {
			case n := <-sink.sig:
				if n >= want {
					return
				}
			case <-deadline:
				t.Fatalf("timed out waiting for sink call >= %d", want)
			}
		}
	}

	// The GUAC file collector emits each file at most once (ModTime > lastChecked),
	// so a second document — not a re-ingest of the first — provides the succeeding
	// call that proves polling continued past the failure.
	copyFixture(t, dir, "a.json")
	waitCall(1) // first Ingest fails (500)
	copyFixture(t, dir, "b.json")
	waitCall(2) // a later Ingest succeeds — polling continued

	cancel()
	select {
	case res := <-done:
		if res.err != nil {
			t.Fatalf("Run returned error on cancel, want nil (poll mode swallows a sink failure): %v", res.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for Run to return")
	}

	obs.mu.Lock()
	failed := obs.failed
	obs.mu.Unlock()
	if failed != 1 {
		t.Errorf("observer DocumentFailed = %d, want 1", failed)
	}
}
