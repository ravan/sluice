package pipeline_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/ravan/sluice/pkg/config"
	"github.com/ravan/sluice/pkg/pipeline"
	"github.com/ravan/sluice/pkg/validtime"
	"github.com/ravan/sluice/pkg/varve"
)

// runWorkers is runOneShotWith at a chosen prepare width.
func runWorkers(t *testing.T, dir string, sink pipeline.Sink, workers int, decs ...pipeline.Decorator) (pipeline.Receipt, error) {
	t.Helper()
	d := validtime.Default()
	cfg := config.Config{
		Receivers:  config.Receivers{Files: &config.FilesReceiver{Path: dir}},
		Processors: config.Processors{ValidTime: config.ValidTimeProcessor{Floor: d.Floor, FutureSkew: d.Skew}},
		Sink:       config.Sink{Varve: config.VarveSink{Addr: "http://x", TokenEnv: "T"}},
	}
	return pipeline.Run(context.Background(), cfg, pipeline.Deps{
		Sink: sink, Decorators: decs, PrepareWorkers: workers,
		Now: func() time.Time { return pipeTestNow },
	})
}

// A wide prepare must not change what a run produces: same receipt, same
// stream on the wire, same order into the decorator.
func TestPrepareWorkersDoNotChangeTheRun(t *testing.T) {
	dir := t.TempDir()
	for i := range 12 {
		copyFixture(t, dir, fmt.Sprintf("doc-%02d.json", i))
	}

	serialSink := &fakeSink{}
	serialDec := &docDecorator{}
	serialRec, err := runWorkers(t, dir, serialSink, 1, serialDec)
	if err != nil {
		t.Fatalf("serial Run: %v", err)
	}

	wideSink := &fakeSink{}
	wideDec := &docDecorator{}
	wideRec, err := runWorkers(t, dir, wideSink, pipeline.AutoWorkers, wideDec)
	if err != nil {
		t.Fatalf("wide Run: %v", err)
	}

	if serialRec.String() != wideRec.String() {
		t.Errorf("receipt differs\n serial: %s\n wide:   %s", serialRec.String(), wideRec.String())
	}
	if serialRec.Documents != 12 || serialRec.Decorated != 12 {
		t.Fatalf("fixture did not produce 12 decorated documents: %s", serialRec.String())
	}
	if len(serialSink.streams) != 1 || len(wideSink.streams) != 1 {
		t.Fatalf("one-shot must sink once: serial=%d wide=%d", len(serialSink.streams), len(wideSink.streams))
	}
	if !sameStream(serialSink.streams[0], wideSink.streams[0]) {
		t.Error("the stream on the wire differs between a serial and a wide prepare")
	}

	// A wide prepare calls the decorator in no fixed order, so what is held
	// here is the set of documents, not the sequence. The order that is a
	// contract — the sink's and the receipt's — is checked above.
	serialSeen, wideSeen := sources(serialDec.inputs()), sources(wideDec.inputs())
	if len(serialSeen) != len(wideSeen) {
		t.Fatalf("decorator saw %d documents serial, %d wide", len(serialSeen), len(wideSeen))
	}
	for src := range serialSeen {
		if !wideSeen[src] {
			t.Errorf("a wide prepare never decorated %q", src)
		}
	}
}

// sources is the set of document sources a decorator was handed.
func sources(in []pipeline.DecorateInput) map[string]bool {
	out := make(map[string]bool, len(in))
	for _, i := range in {
		out[i.Source] = true
	}
	return out
}

// A decorator further down the chain still sees what the one before it added
// when prepare is wide.
func TestPrepareWorkersKeepTheDecoratorChain(t *testing.T) {
	dir := t.TempDir()
	for i := range 6 {
		copyFixture(t, dir, fmt.Sprintf("doc-%02d.json", i))
	}
	second := &chainDecorator{}
	if _, err := runWorkers(t, dir, &fakeSink{}, pipeline.AutoWorkers, &docDecorator{}, second); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := second.seenDocNode(); got != 6 {
		t.Errorf("second decorator saw the Document node %d times, want 6", got)
	}
}

// sameStream compares two streams by their records' ids, in order.
func sameStream(a, b varve.Stream) bool {
	if len(a.Nodes) != len(b.Nodes) || len(a.Edges) != len(b.Edges) {
		return false
	}
	for i := range a.Nodes {
		if a.Nodes[i].ID != b.Nodes[i].ID {
			return false
		}
	}
	for i := range a.Edges {
		if a.Edges[i].ID != b.Edges[i].ID {
			return false
		}
	}
	return true
}
