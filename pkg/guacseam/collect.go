package guacseam

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"time"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/handler/collector"
	"github.com/guacsec/guac/pkg/handler/collector/file"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/handler/processor/process"
	"github.com/guacsec/guac/pkg/ingestor/parser"
	"github.com/guacsec/guac/pkg/ingestor/parser/common"
	"github.com/guacsec/guac/pkg/logging"
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

// Origin says where a collected document came from.
type Origin int

const (
	OriginReceiver  Origin = iota // came from a configured receiver
	OriginExpansion               // synthesized by deps.dev expansion
)

// String renders the origin for logs.
func (o Origin) String() string {
	switch o {
	case OriginReceiver:
		return "receiver"
	case OriginExpansion:
		return "expansion"
	default:
		return fmt.Sprintf("Origin(%d)", int(o))
	}
}

// Parsed is one collected and parsed document: the raw GUAC document (bytes in
// Doc.Blob, plus type, format and provenance), the predicates the parser made
// from it, and the deduped purls it mentions (fed to expansion).
type Parsed struct {
	Source     string // Doc.SourceInformation.Source
	Origin     Origin
	Doc        *processor.Document
	Preds      []assembler.IngestPredicates
	Purls      []string
	ScanFailed []ScanFailure
}

// DocumentFunc consumes one parsed document. An error it returns aborts the
// whole pass — a sink failure is not a document failure (§2.6).
type DocumentFunc func(ctx context.Context, p Parsed) error

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
	// ProcessingContext optionally shares a drain deadline with a caller's final flush.
	ProcessingContext context.Context
}

// processAndParse parses base evidence. Scanners run separately so their errors
// can be included in the receipt without losing the base document.
func processAndParse(ctx context.Context, doc *processor.Document) ([]assembler.IngestPredicates, []string, error) {
	tree, err := process.Process(ctx, doc)
	if err != nil {
		return nil, nil, err
	}
	preds, ids, err := parser.ParseDocumentTree(ctx, tree, false, false, false, false)
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
// present receiver's collector and drives the run-owned set directly.
func Collect(ctx context.Context, src Sources, fn DocumentFunc) (Outcome, error) {
	cols, err := buildCollectors(ctx, src)
	if err != nil {
		return Outcome{}, err
	}
	workCtx := src.ProcessingContext
	if workCtx == nil {
		var cancel context.CancelFunc
		workCtx, cancel = DrainContext(ctx, 0)
		defer cancel()
	}
	return collectOwned(ctx, workCtx, cols, src.Scan, src.OnSkip, fn, parseWorkers())
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
	seq        int
	source     string
	doc        *processor.Document
	preds      []assembler.IngestPredicates
	purls      []string
	err        error
	scanFailed []ScanFailure
}

// collectWith owns its collectors and never touches GUAC's global registry.
func collectWith(ctx context.Context, cols []collector.Collector, scan ScanFlags, onSkip func(FailedDocument), fn DocumentFunc) (Outcome, error) {
	workCtx, cancel := DrainContext(ctx, 0)
	defer cancel()
	return collectOwned(ctx, workCtx, cols, scan, onSkip, fn, parseWorkers())
}

// DrainContext keeps accepted processing alive after intake cancellation, then
// cancels it after timeout. Callers must release it after their final flush.
// Processing callbacks must honor context cancellation.
func DrainContext(intake context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithCancel(context.WithoutCancel(intake))
	go func() {
		select {
		case <-ctx.Done():
			return
		case <-intake.Done():
		}
		timer := time.NewTimer(timeout)
		defer timer.Stop()
		select {
		case <-ctx.Done():
		case <-timer.C:
			cancel()
		}
	}()
	return ctx, cancel
}

func collectOwned(ctx, workCtx context.Context, cols []collector.Collector, scan ScanFlags, onSkip func(FailedDocument), fn DocumentFunc, workers int) (Outcome, error) {
	return collectParsed(ctx, workCtx, cols, scan, onSkip, fn, workers, parseCollected)
}

func parseCollected(ctx context.Context, j parseJob, scan ScanFlags) parseResult {
	collector.AddChildLogger(logging.FromContext(ctx), j.doc)
	preds, purls, err := processAndParse(ctx, j.doc)
	r := parseResult{seq: j.seq, source: j.doc.SourceInformation.Source, doc: j.doc, preds: preds, purls: purls, err: err}
	if err == nil {
		r.scanFailed = scanPredicates(ctx, preds, purls, scan)
	}
	return r
}

type parseFunc func(context.Context, parseJob, ScanFlags) parseResult

func collectParsed(ctx, workCtx context.Context, cols []collector.Collector, scan ScanFlags, onSkip func(FailedDocument), fn DocumentFunc, workers int, parse parseFunc) (Outcome, error) {
	intake, stop := context.WithCancel(ctx)
	defer stop()
	workCtx, stopWork := context.WithCancel(workCtx)
	defer stopWork()
	docs, errs := retrieveOwned(intake, cols, stop)
	// Credits span acceptance through ordered delivery, including the reorder map.
	credits := make(chan struct{}, workers*2)
	jobs := make(chan parseJob, workers)
	results := parseJobs(workCtx, jobs, scan, workers, parse)
	accepted := make(chan int, 1)
	go func() { defer close(jobs); accepted <- feedJobs(intake, workCtx, docs, jobs, credits) }()
	out, err := deliverResults(workCtx, results, credits, onSkip, fn)
	if err != nil {
		stop()
		stopWork()
	}
	out.Documents = <-accepted
	if err != nil {
		return out, err
	}
	return out, collectorErrors(intake, workCtx, errs, len(cols))
}

func retrieveOwned(ctx context.Context, cols []collector.Collector, stop context.CancelFunc) (<-chan *processor.Document, <-chan error) {
	docs := make(chan *processor.Document)
	errs := make(chan error, len(cols))
	var wg sync.WaitGroup
	for _, c := range cols {
		wg.Add(1)
		go func(c collector.Collector) {
			defer wg.Done()
			err := c.RetrieveArtifacts(ctx, docs)
			errs <- err
			if err != nil {
				stop()
			}
		}(c)
	}
	go func() { wg.Wait(); close(docs); close(errs) }()
	return docs, errs
}

func parseJobs(ctx context.Context, jobs <-chan parseJob, scan ScanFlags, workers int, parse parseFunc) <-chan parseResult {
	results := make(chan parseResult, workers)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				r := parse(ctx, j, scan)
				select {
				case results <- r:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	go func() { wg.Wait(); close(results) }()
	return results
}

func feedJobs(intake, work context.Context, docs <-chan *processor.Document, jobs chan<- parseJob, credits chan struct{}) int {
	count := 0
	defer func() { go drainCollectors(context.WithoutCancel(work), docs) }()
	for {
		select {
		case credits <- struct{}{}:
		case <-intake.Done():
			return count
		case <-work.Done():
			return count
		}
		select {
		case d, ok := <-docs:
			if !ok {
				<-credits
				return count
			}
			count++
			select {
			case jobs <- parseJob{seq: count - 1, doc: d}:
			case <-work.Done():
				<-credits
				return count
			}
		case <-intake.Done():
			<-credits
			return count
		case <-work.Done():
			<-credits
			return count
		}
	}
}

func deliverResults(ctx context.Context, results <-chan parseResult, credits chan struct{}, onSkip func(FailedDocument), fn DocumentFunc) (Outcome, error) {
	var out Outcome
	pending := map[int]parseResult{}
	next := 0
	for {
		select {
		case <-ctx.Done():
			return out, fmt.Errorf("processing drain expired: %w", ctx.Err())
		case r, ok := <-results:
			if !ok {
				return out, nil
			}
			pending[r.seq] = r
			for {
				p, ok := pending[next]
				if !ok {
					break
				}
				delete(pending, next)
				next++
				err := deliverResult(ctx, p, &out, onSkip, fn)
				<-credits
				if err != nil {
					return out, err
				}
			}
		}
	}
}

func deliverResult(ctx context.Context, p parseResult, out *Outcome, onSkip func(FailedDocument), fn DocumentFunc) error {
	if ctx.Err() != nil {
		return fmt.Errorf("processing drain expired: %w", ctx.Err())
	}
	if p.err == nil {
		return fn(ctx, Parsed{Source: p.source, Origin: OriginReceiver, Doc: p.doc, Preds: p.preds, Purls: p.purls, ScanFailed: p.scanFailed})
	}
	fd := FailedDocument{Source: p.source, Err: fmt.Errorf("processing/parsing %s: %w", p.source, p.err)}
	out.Failed = append(out.Failed, fd)
	if onSkip != nil {
		onSkip(fd)
	}
	return nil
}

func collectorErrors(intake, work context.Context, errs <-chan error, count int) error {
	for range count {
		select {
		case <-work.Done():
			return fmt.Errorf("collector drain expired: %w", work.Err())
		case err := <-errs:
			if err == nil {
				continue
			}
			if intake.Err() != nil && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
				continue
			}
			return fmt.Errorf("collecting: %w", err)
		}
	}
	return nil
}

// Imported collectors may send without selecting on their context. Release a
// blocked send after cancellation so they can observe cancellation and exit.
func drainCollectors(ctx context.Context, docs <-chan *processor.Document) {
	timer := time.NewTimer(30 * time.Second)
	defer timer.Stop()
	for {
		select {
		case _, ok := <-docs:
			if !ok {
				return
			}
		case <-ctx.Done():
			return
		case <-timer.C:
			return
		}
	}
}
