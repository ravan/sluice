package pipeline_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ravan/sluice/pkg/config"
	"github.com/ravan/sluice/pkg/guacseam"
	"github.com/ravan/sluice/pkg/pipeline"
	"github.com/ravan/sluice/pkg/validtime"
	"github.com/ravan/sluice/pkg/varve"
)

// docDecorator adds a Document node per input and links it to the first
// HasSBOM node it finds in in.Records. It records every input it saw.
type docDecorator struct {
	seen []pipeline.DecorateInput
	fail func(in pipeline.DecorateInput) error
}

func firstLabelled(s varve.Stream, label varve.NodeLabel) (varve.NodeID, bool) {
	for _, n := range s.Nodes {
		for _, l := range n.Labels {
			if l == label {
				return n.ID, true
			}
		}
	}
	return "", false
}

func (d *docDecorator) Decorate(_ context.Context, in pipeline.DecorateInput) (varve.Stream, error) {
	d.seen = append(d.seen, in)
	if d.fail != nil {
		if err := d.fail(in); err != nil {
			return varve.Stream{}, err
		}
	}
	docID := varve.NodeID("doc:" + in.Digest)
	out := varve.Stream{Nodes: []varve.NodeRecord{{
		ID:        docID,
		Labels:    []varve.NodeLabel{"Document"},
		Props:     []varve.Prop{{Key: "source", Value: varve.Str(in.Source)}},
		ValidFrom: in.ValidFrom,
	}}}
	if sbom, ok := firstLabelled(in.Records, "HasSBOM"); ok {
		out.Edges = []varve.EdgeRecord{{ID: varve.EdgeID(string(docID) + "|Describes|" + string(sbom)), Label: "Describes", Src: docID, Dst: sbom}}
	}
	return out, nil
}

// chainDecorator asserts it can see the Document node a previous decorator added.
type chainDecorator struct {
	sawDocNode int
}

func (c *chainDecorator) Decorate(_ context.Context, in pipeline.DecorateInput) (varve.Stream, error) {
	if _, ok := firstLabelled(in.Records, "Document"); ok {
		c.sawDocNode++
	}
	return varve.Stream{}, nil
}

func runOneShotWith(t *testing.T, dir string, sink pipeline.Sink, obs pipeline.Observer, decs ...pipeline.Decorator) (pipeline.Receipt, error) {
	t.Helper()
	d := validtime.Default()
	cfg := config.Config{
		Receivers:  config.Receivers{Files: &config.FilesReceiver{Path: dir}},
		Processors: config.Processors{ValidTime: config.ValidTimeProcessor{Floor: d.Floor, FutureSkew: d.Skew}},
		Sink:       config.Sink{Varve: config.VarveSink{Addr: "http://x", TokenEnv: "T"}},
	}
	return pipeline.Run(context.Background(), cfg, pipeline.Deps{Sink: sink, Observer: obs, Decorators: decs, Now: func() time.Time { return pipeTestNow }})
}

func TestRunWithoutDecoratorKeepsGoldenCounts(t *testing.T) {
	dir := t.TempDir()
	copyFixture(t, dir, "a.json")
	copyFixture(t, dir, "b.json")
	fake := &fakeSink{responses: []response{{receipt: varve.Receipt{Nodes: 12, Edges: 9, Transactions: 1, Basis: 11}}}}

	rec, err := runOneShotWith(t, dir, fake, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rec.Documents != 2 || rec.Transactions != 1 || fake.calls != 1 {
		t.Errorf("documents=%d transactions=%d sink calls=%d, want 2 / 1 / 1", rec.Documents, rec.Transactions, fake.calls)
	}
	if len(fake.streams[0].Nodes) != 12 || len(fake.streams[0].Edges) != 9 {
		t.Errorf("stream = %d nodes / %d edges, want 12 / 9 (per-document assemble then Merge equals the old batch)", len(fake.streams[0].Nodes), len(fake.streams[0].Edges))
	}
	if rec.Decorated != 0 || len(rec.DecorateFailed) != 0 {
		t.Errorf("Decorated=%d DecorateFailed=%v, want 0 / empty with no decorator", rec.Decorated, rec.DecorateFailed)
	}
}

func TestRunDecoratorRecordsLandInTheSameStream(t *testing.T) {
	dir := t.TempDir()
	copyFixture(t, dir, "a.json")
	copyFixture(t, dir, "b.json")
	fake := &fakeSink{responses: []response{{receipt: varve.Receipt{Nodes: 13, Edges: 11, Transactions: 1, Basis: 11}}}}
	dec := &docDecorator{}
	obs := &countingObserver{}

	rec, err := runOneShotWith(t, dir, fake, obs, dec)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if fake.calls != 1 || rec.Transactions != 1 {
		t.Fatalf("sink calls=%d transactions=%d, want 1 / 1 (one-shot stays one transaction)", fake.calls, rec.Transactions)
	}
	s := fake.streams[0]
	// a.json and b.json are byte-identical, so they share one digest and the
	// decorator's two Document nodes dedup to one; their HasSBOM ids fold the
	// source path, so the two Describes edges stay distinct.
	if len(s.Nodes) != 13 || len(s.Edges) != 11 {
		t.Errorf("stream = %d nodes / %d edges, want 13 / 11 (12/9 Sluice + 1 Document node + 2 Describes edges)", len(s.Nodes), len(s.Edges))
	}
	var docNodes, describes int
	docIDs := map[varve.NodeID]bool{}
	for _, n := range s.Nodes {
		if n.Labels[0] == "Document" {
			docNodes++
			docIDs[n.ID] = true
		}
	}
	for _, e := range s.Edges {
		if e.Label == "Describes" {
			describes++
			if !docIDs[e.Src] {
				t.Errorf("Describes edge src %q is not a Document node in the same stream", e.Src)
			}
			if _, ok := firstLabelled(varve.Stream{Nodes: s.Nodes}, "HasSBOM"); !ok {
				t.Errorf("no HasSBOM node in the stream for edge dst %q", e.Dst)
			}
		}
	}
	if docNodes != 1 || describes != 2 {
		t.Errorf("Document nodes=%d Describes edges=%d, want 1 / 2", docNodes, describes)
	}
	if rec.Decorated != rec.Documents || rec.Decorated != 2 {
		t.Errorf("Decorated=%d Documents=%d, want both 2", rec.Decorated, rec.Documents)
	}
	if len(rec.DecorateFailed) != 0 {
		t.Errorf("DecorateFailed = %v, want empty", rec.DecorateFailed)
	}
	if obs.decorated != 2 || obs.decorateFailed != 0 {
		t.Errorf("observer decorated=%d failed=%d, want 2 / 0", obs.decorated, obs.decorateFailed)
	}
	if len(dec.seen) != 2 {
		t.Fatalf("decorator saw %d documents, want 2", len(dec.seen))
	}
	for _, in := range dec.seen {
		if in.Origin != guacseam.OriginReceiver {
			t.Errorf("Origin = %v, want OriginReceiver", in.Origin)
		}
		if len(in.Records.Nodes) != 9 || len(in.Records.Edges) != 6 {
			t.Errorf("per-document Records = %d/%d, want 9/6", len(in.Records.Nodes), len(in.Records.Edges))
		}
		if in.Fallback || !in.ValidFrom.Equal(time.Date(2020, 11, 24, 1, 12, 27, 0, time.UTC)) {
			t.Errorf("ValidFrom=%v Fallback=%v, want the SBOM's created time and false", in.ValidFrom, in.Fallback)
		}
		if !in.Now.Equal(pipeTestNow) {
			t.Errorf("Now = %v, want %v", in.Now, pipeTestNow)
		}
		if in.Doc == nil || len(in.Preds) == 0 {
			t.Errorf("Doc/Preds missing: %v / %d", in.Doc, len(in.Preds))
		}
	}
}

func TestRunDecoratorDigestIsSHA256OfRaw(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(fixtureDir, "small-spdx.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	sum := sha256.Sum256(raw)
	want := hex.EncodeToString(sum[:])

	fake := &fakeSink{responses: []response{{receipt: varve.Receipt{Transactions: 1}}}}
	dec := &docDecorator{}
	if _, err := runOneShotWith(t, fixtureDir, fake, nil, dec); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(dec.seen) != 1 {
		t.Fatalf("decorator saw %d documents, want 1", len(dec.seen))
	}
	if dec.seen[0].Digest != want {
		t.Errorf("Digest = %q, want %q", dec.seen[0].Digest, want)
	}
	if string(dec.seen[0].Raw) != string(raw) {
		t.Errorf("Raw differs from the fixture bytes")
	}
	if !strings.HasSuffix(dec.seen[0].Source, "small-spdx.json") {
		t.Errorf("Source = %q, want the fixture path", dec.seen[0].Source)
	}
}

func TestRunSecondDecoratorSeesFirstDecoratorsRecords(t *testing.T) {
	fake := &fakeSink{responses: []response{{receipt: varve.Receipt{Transactions: 1}}}}
	first := &docDecorator{}
	second := &chainDecorator{}
	rec, err := runOneShotWith(t, fixtureDir, fake, nil, first, second)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if second.sawDocNode != 1 {
		t.Errorf("second decorator saw the Document node %d times, want 1", second.sawDocNode)
	}
	if rec.Decorated != 1 {
		t.Errorf("Decorated = %d, want 1", rec.Decorated)
	}
}
