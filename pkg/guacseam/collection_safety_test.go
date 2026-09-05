package guacseam

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/guacsec/guac/pkg/handler/collector"
	"github.com/guacsec/guac/pkg/handler/processor"
)

type streamCollector struct {
	count int
	sent  *atomic.Int64
}

func (s streamCollector) Type() string { return "same-type" }
func (s streamCollector) RetrieveArtifacts(ctx context.Context, ch chan<- *processor.Document) error {
	for i := 0; i < s.count; i++ {
		select {
		case ch <- &processor.Document{SourceInformation: processor.SourceInformation{Source: fmt.Sprint(i)}}:
			s.sent.Add(1)
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func TestConcurrentCollectionsOwnTheirDocuments(t *testing.T) {
	blob := readSmallSPDX(t)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			source := fmt.Sprintf("run-%d", i)
			c := fakeCollector{typ: source, blob: blob}
			// A wrapper gives every run the same registration type.
			out, err := collectWith(context.Background(), []collector.Collector{sameTypeCollector{c}}, ScanFlags{}, nil, func(_ context.Context, p Parsed) error {
				if p.Source != source+"-doc" {
					return fmt.Errorf("foreign document %s", p.Source)
				}
				return nil
			})
			if err != nil || out.Documents != 1 {
				t.Errorf("run %d: %+v %v", i, out, err)
			}
		}(i)
	}
	close(start)
	wg.Wait()
}

type sameTypeCollector struct{ fakeCollector }

func (sameTypeCollector) Type() string { return "same-type" }

func TestOutstandingPositionsBoundedBehindSlowFirstParse(t *testing.T) {
	var sent atomic.Int64
	stalled := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := collectParsed(context.Background(), context.Background(), []collector.Collector{streamCollector{100, &sent}}, ScanFlags{}, nil, func(context.Context, Parsed) error { return nil }, 2,
			func(_ context.Context, j parseJob, _ ScanFlags) parseResult {
				if j.seq == 0 {
					close(stalled)
					<-release
				}
				return parseResult{seq: j.seq, doc: j.doc}
			})
		done <- err
	}()
	<-stalled
	time.Sleep(50 * time.Millisecond)
	if got := sent.Load(); got > 4 {
		t.Errorf("accepted %d documents while first stalled; limit 4", got)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if sent.Load() != 100 {
		t.Fatalf("only delivered %d", sent.Load())
	}
}

func TestAcceptedWorkDrainsAfterCancellation(t *testing.T) {
	c := fakeCollector{typ: "drain", blob: readSmallSPDX(t)}
	intake2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	work2, stop2 := DrainContext(intake2, time.Second)
	defer stop2()
	_, err := collectOwned(intake2, work2, []collector.Collector{c}, ScanFlags{}, nil, func(ctx context.Context, _ Parsed) error {
		cancel2()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(20 * time.Millisecond):
			return nil
		}
	}, 1)
	if err != nil {
		t.Fatalf("accepted work canceled: %v", err)
	}
}

func TestDrainDeadlineAbortsBlockedProcessing(t *testing.T) {
	intake, cancel := context.WithCancel(context.Background())
	defer cancel()
	work, stop := DrainContext(intake, 20*time.Millisecond)
	defer stop()
	_, err := collectOwned(intake, work, []collector.Collector{fakeCollector{typ: "drain", blob: readSmallSPDX(t)}}, ScanFlags{}, nil, func(ctx context.Context, _ Parsed) error {
		cancel()
		<-ctx.Done()
		return ctx.Err()
	}, 1)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("drain error = %v", err)
	}
}

type unconditionalCollector struct {
	done chan struct{}
	blob []byte
}

func (c unconditionalCollector) Type() string { return "unconditional" }
func (c unconditionalCollector) RetrieveArtifacts(ctx context.Context, docs chan<- *processor.Document) error {
	defer close(c.done)
	for range 100 {
		docs <- &processor.Document{Blob: c.blob, Type: processor.DocumentUnknown, Format: processor.FormatUnknown}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	return nil
}
func TestSinkFailureReleasesUnconditionalCollectorSend(t *testing.T) {
	done := make(chan struct{})
	want := errors.New("sink failed")
	_, err := collectOwned(context.Background(), context.Background(), []collector.Collector{unconditionalCollector{done, readSmallSPDX(t)}}, ScanFlags{}, nil, func(context.Context, Parsed) error { return want }, 1)
	if !errors.Is(err, want) {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("collector stuck sending after fatal sink failure")
	}
}

func TestCancellationDrainsQueuedAcceptedDocuments(t *testing.T) {
	intake, cancel := context.WithCancel(context.Background())
	defer cancel()
	work, stop := DrainContext(intake, time.Second)
	defer stop()
	var sent atomic.Int64
	delivered := 0
	out, err := collectParsed(intake, work, []collector.Collector{streamCollector{4, &sent}}, ScanFlags{}, nil, func(ctx context.Context, _ Parsed) error {
		delivered++
		if delivered == 1 {
			deadline := time.After(time.Second)
			for sent.Load() < 4 {
				select {
				case <-deadline:
					return errors.New("documents never queued")
				case <-time.After(time.Millisecond):
				}
			}
			cancel()
		}
		return ctx.Err()
	}, 2, func(_ context.Context, j parseJob, _ ScanFlags) parseResult {
		return parseResult{seq: j.seq, doc: j.doc}
	})
	if err != nil || out.Documents != 4 || delivered != 4 {
		t.Fatalf("accepted=%d delivered=%d err=%v", out.Documents, delivered, err)
	}
}
