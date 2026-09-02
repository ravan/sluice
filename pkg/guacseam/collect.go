package guacseam

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/handler/collector"
	"github.com/guacsec/guac/pkg/handler/collector/file"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/handler/processor/process"
	"github.com/guacsec/guac/pkg/ingestor/parser"
	"github.com/guacsec/guac/pkg/ingestor/parser/common"
)

// FailedDocument names a document that did not survive processing or parsing.
// Skipped-and-counted, never silent (§2.6, §6 inv. 9).
type FailedDocument struct {
	Source string
	Err    error
}

// Outcome counts one collection pass.
type Outcome struct {
	Documents int
	Failed    []FailedDocument
}

// PredicateFunc consumes one document's parsed predicates and the deduped purls the
// parser found for it (fed to expansion). An error it returns aborts the whole pass —
// a sink failure is not a document failure (§2.6).
type PredicateFunc func(ctx context.Context, source string, preds []assembler.IngestPredicates, purls []string) error

// ScanFlags gates the four ParseDocumentTree enrichment scanners.
type ScanFlags struct {
	Vulns    bool
	Licenses bool
	EOL      bool
	DepsDev  bool
}

// FilesReceiver watches a directory of documents. Poll ⇒ re-scan at Interval;
// else one pass.
type FilesReceiver struct {
	Path     string
	Poll     bool
	Interval time.Duration
}

// Sources is one collection pass's whole receiver set plus pass-level Scan and
// OnSkip (which apply to every collected document). A nil receiver pointer is
// absent; Collect requires at least one present.
type Sources struct {
	Files  *FilesReceiver
	OCI    *OCIReceiver
	S3     *S3Receiver
	GCS    *GCSReceiver
	Scan   ScanFlags
	OnSkip func(FailedDocument)
}

// processAndParse runs process.Process then parser.ParseDocumentTree with the given scan
// flags, returning the predicates and the flattened, deduped purl list. Shared by
// collectWith's emit and expansion's per-document handler.
func processAndParse(ctx context.Context, doc *processor.Document, scan ScanFlags) ([]assembler.IngestPredicates, []string, error) {
	tree, err := process.Process(ctx, doc)
	if err != nil {
		return nil, nil, err
	}
	preds, ids, err := parser.ParseDocumentTree(ctx, tree, scan.Vulns, scan.Licenses, scan.EOL, scan.DepsDev)
	if err != nil {
		return nil, nil, err
	}
	return preds, purlsFrom(ids), nil
}

// purlsFrom flattens the PurlStrings of every non-nil IdentifierStrings.
func purlsFrom(ids []*common.IdentifierStrings) []string {
	seen := map[string]bool{}
	var purls []string
	for _, id := range ids {
		if id == nil {
			continue
		}
		for _, p := range id.PurlStrings {
			if seen[p] {
				continue
			}
			seen[p] = true
			purls = append(purls, p)
		}
	}
	return purls
}

// Collect is the ONLY place GUAC behaviour is invoked (§3): it builds every
// present receiver's collector, registers the whole set, runs collector.Collect
// once, and deregisters on return.
func Collect(ctx context.Context, src Sources, fn PredicateFunc) (Outcome, error) {
	cols, err := buildCollectors(ctx, src)
	if err != nil {
		return Outcome{}, err
	}
	return collectWith(ctx, cols, src.Scan, src.OnSkip, fn)
}

// buildCollectors builds one collector.Collector per present receiver in src, in
// a fixed order (files, oci, s3, gcs). Returns an error if none are present.
func buildCollectors(ctx context.Context, src Sources) ([]collector.Collector, error) {
	var cols []collector.Collector
	if src.Files != nil {
		c, err := buildFiles(ctx, *src.Files)
		if err != nil {
			return nil, err
		}
		cols = append(cols, c)
	}
	if src.OCI != nil {
		c, err := buildOCI(ctx, *src.OCI)
		if err != nil {
			return nil, err
		}
		cols = append(cols, c)
	}
	if src.S3 != nil {
		c, err := buildS3(*src.S3)
		if err != nil {
			return nil, err
		}
		cols = append(cols, c)
	}
	if src.GCS != nil {
		c, err := buildGCS(ctx, *src.GCS)
		if err != nil {
			return nil, err
		}
		cols = append(cols, c)
	}
	if len(cols) == 0 {
		return nil, fmt.Errorf("no receivers configured")
	}
	return cols, nil
}

// buildFiles builds GUAC's file collector for the receiver's directory.
func buildFiles(ctx context.Context, r FilesReceiver) (collector.Collector, error) {
	return file.NewFileCollector(ctx, r.Path, r.Poll, r.Interval), nil
}

// parseWorkers bounds the concurrent process+parse fan-out. GUAC hands documents
// to the emitter one at a time, but process+parse is pure per-document CPU work
// and dominates a pass, so it is the one stage worth spreading across cores. One
// core is left for the collector's own read/decode loop.
func parseWorkers() int {
	if n := runtime.GOMAXPROCS(0) - 1; n > 1 {
		return n
	}
	return 1
}

// parseJob is one collected document plus its arrival position.
type parseJob struct {
	seq int
	doc *processor.Document
}

// parseResult is one document's process+parse outcome, tagged with the arrival
// position that puts it back in order.
type parseResult struct {
	seq    int
	source string
	preds  []assembler.IngestPredicates
	purls  []string
	err    error
}

// collectWith registers cols, runs collector.Collect feeding a bounded pool of
// process+parse workers, and deregisters the whole set on return. Workers run
// concurrently but their results are replayed to fn and onSkip strictly in
// document arrival order by a single consumer, so fn stays single-threaded and a
// pass's output does not depend on which worker finished first.
func collectWith(ctx context.Context, cols []collector.Collector, scan ScanFlags, onSkip func(FailedDocument), fn PredicateFunc) (Outcome, error) {
	var registered []collector.Collector
	defer func() {
		for _, c := range registered {
			collector.DeregisterDocumentCollector(c.Type())
		}
	}()
	for _, c := range cols {
		if err := collector.RegisterDocumentCollector(c, c.Type()); err != nil {
			return Outcome{}, fmt.Errorf("registering %s collector: %w", c.Type(), err)
		}
		registered = append(registered, c)
	}

	var out Outcome
	var fnErr error
	var stopped atomic.Bool

	workers := parseWorkers()
	jobs := make(chan parseJob, workers)
	results := make(chan parseResult, workers)

	var wg sync.WaitGroup
	wg.Add(workers)
	for range workers {
		go func() {
			defer wg.Done()
			for j := range jobs {
				preds, purls, err := processAndParse(ctx, j.doc, scan)
				results <- parseResult{seq: j.seq, source: j.doc.SourceInformation.Source, preds: preds, purls: purls, err: err}
			}
		}()
	}
	go func() { wg.Wait(); close(results) }()

	// The consumer reorders by seq and is the ONLY goroutine that touches
	// out.Failed, fnErr, onSkip and fn.
	consumed := make(chan struct{})
	go func() {
		defer close(consumed)
		pending := map[int]parseResult{}
		next := 0
		for r := range results {
			pending[r.seq] = r
			for {
				p, ok := pending[next]
				if !ok {
					break
				}
				delete(pending, next)
				next++
				if fnErr != nil {
					continue
				}
				if p.err != nil {
					fd := FailedDocument{Source: p.source, Err: fmt.Errorf("processing/parsing %s: %w", p.source, p.err)}
					out.Failed = append(out.Failed, fd)
					if onSkip != nil {
						onSkip(fd)
					}
					continue
				}
				if err := fn(ctx, p.source, p.preds, p.purls); err != nil {
					fnErr = err
					stopped.Store(true)
				}
			}
		}
	}()

	emit := func(d *processor.Document) error {
		if stopped.Load() {
			return nil
		}
		jobs <- parseJob{seq: out.Documents, doc: d}
		out.Documents++
		return nil
	}

	handleErr := func(err error) bool {
		return err == nil ||
			errors.Is(err, context.Canceled) ||
			errors.Is(err, context.DeadlineExceeded)
	}

	collectErr := collector.Collect(ctx, emit, handleErr)
	close(jobs)
	<-consumed

	if collectErr != nil {
		return out, fmt.Errorf("collecting: %w", collectErr)
	}
	if fnErr != nil {
		return out, fnErr
	}
	return out, nil
}
