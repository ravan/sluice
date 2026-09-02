package pipeline_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ravan/sluice/pkg/pipeline"
	"github.com/ravan/sluice/pkg/varve"
)

func TestRunDecoratorErrorSkipsOnlyThatDocument(t *testing.T) {
	dir := t.TempDir()
	copyFixture(t, dir, "a.json")
	copyFixture(t, dir, "b.json")
	fake := &fakeSink{responses: []response{{receipt: varve.Receipt{Transactions: 1}}}}
	obs := &countingObserver{}
	boom := errors.New("policy says no")
	dec := &docDecorator{fail: func(in pipeline.DecorateInput) error {
		if strings.HasSuffix(in.Source, "b.json") {
			return boom
		}
		return nil
	}}

	rec, err := runOneShotWith(t, dir, fake, obs, dec)
	if err != nil {
		t.Fatalf("Run returned %v, want nil (a decorator error is not a run error)", err)
	}
	if rec.Documents != 2 || rec.Decorated != 1 {
		t.Errorf("Documents=%d Decorated=%d, want 2 / 1", rec.Documents, rec.Decorated)
	}
	if len(rec.DecorateFailed) != 1 {
		t.Fatalf("DecorateFailed = %v, want one entry", rec.DecorateFailed)
	}
	de := rec.DecorateFailed[0]
	if !strings.HasSuffix(de.Source, "b.json") || de.Digest == "" || !errors.Is(de.Err, boom) {
		t.Errorf("DecorateFailed[0] = %+v, want b.json, a digest, and the decorator's error", de)
	}
	if !errors.Is(de, boom) {
		t.Errorf("DecorateError does not unwrap to the cause")
	}
	if obs.decorateFailed != 1 || obs.decorated != 1 {
		t.Errorf("observer failed=%d decorated=%d, want 1 / 1", obs.decorateFailed, obs.decorated)
	}
	if fake.calls != 1 {
		t.Fatalf("sink calls = %d, want 1", fake.calls)
	}
	s := fake.streams[0]
	// Only a.json's records: 9 Sluice nodes + 1 Document node, 6 edges + 1 Describes.
	if len(s.Nodes) != 10 || len(s.Edges) != 7 {
		t.Errorf("stream = %d nodes / %d edges, want 10 / 7 (b.json absent)", len(s.Nodes), len(s.Edges))
	}
	for _, n := range s.Nodes {
		if n.Labels[0] == "Document" && n.ID != varve.NodeID("doc:"+dec.seen[0].Digest) {
			t.Errorf("unexpected Document node %q", n.ID)
		}
	}
	if !strings.Contains(rec.String(), "decorate_failed=1") {
		t.Errorf("Receipt.String() = %q, want it to report decorate_failed=1", rec.String())
	}
}

func TestRunPollModeDecoratorErrorIsCountedAndPollingContinues(t *testing.T) {
	dir := t.TempDir()
	sink := &pollSink{got: make(chan varve.Stream, 8)}
	obs := &countingObserver{}
	dec := &docDecorator{fail: func(in pipeline.DecorateInput) error {
		if strings.HasSuffix(in.Source, "a.json") {
			return errors.New("reject a")
		}
		return nil
	}}
	cfg := pollConfig(dir, 25*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	type result struct {
		rec pipeline.Receipt
		err error
	}
	done := make(chan result, 1)
	go func() {
		rec, err := pipeline.Run(ctx, cfg, pipeline.Deps{Sink: sink, Observer: obs, Decorators: []pipeline.Decorator{dec}, Now: func() time.Time { return pipeTestNow }})
		done <- result{rec, err}
	}()

	copyFixture(t, dir, "a.json") // rejected: never reaches the sink
	time.Sleep(150 * time.Millisecond)
	copyFixture(t, dir, "b.json") // accepted: reaches the sink with its Document node
	var s varve.Stream
	select {
	case s = <-sink.got:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for b.json's stream")
	}
	if _, ok := firstLabelled(s, "Document"); !ok {
		t.Errorf("poll-mode stream lacks the decorator's Document node")
	}
	cancel()
	var res result
	select {
	case res = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for Run to return")
	}
	if res.err != nil {
		t.Fatalf("Run returned %v, want nil", res.err)
	}
	if len(res.rec.DecorateFailed) != 1 || !strings.HasSuffix(res.rec.DecorateFailed[0].Source, "a.json") {
		t.Errorf("DecorateFailed = %v, want one entry for a.json", res.rec.DecorateFailed)
	}
	if res.rec.Decorated != 1 {
		t.Errorf("Decorated = %d, want 1", res.rec.Decorated)
	}
	obs.mu.Lock()
	defer obs.mu.Unlock()
	if obs.decorateFailed != 1 || obs.decorated != 1 {
		t.Errorf("observer failed=%d decorated=%d, want 1 / 1", obs.decorateFailed, obs.decorated)
	}
	select {
	case extra := <-sink.got:
		t.Errorf("sink received an extra stream (%d nodes); the rejected document must not reach it", len(extra.Nodes))
	default:
	}
}
