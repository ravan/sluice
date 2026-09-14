package pipeline

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/ravan/sluice/pkg/assemble"
	"github.com/ravan/sluice/pkg/config"
	"github.com/ravan/sluice/pkg/enrich"
	"github.com/ravan/sluice/pkg/guacseam"
	"github.com/ravan/sluice/pkg/validtime"
	"github.com/ravan/sluice/pkg/varve"
)

// Sink is the consumer-side seam the pipeline writes through — the run's one
// real I/O boundary, so tests drive it with a fake instead of a server.
type Sink interface {
	Ingest(ctx context.Context, s varve.Stream) (varve.Receipt, error)
}

// Receipt is one run's outcome (§2.1). Skipped carries every skipped document,
// so a run never drops one silently (§6 inv. 9).
type Receipt struct {
	Documents          int
	Nodes              int64
	Edges              int64
	Transactions       int64
	Basis              int64
	Skipped            []guacseam.FailedDocument
	Fallbacks          int
	Expanded           int
	ExpansionBudget    int
	ExpansionExhausted bool
	Decorated          int             // documents that passed every decorator (0 when none are configured)
	DecorateFailed     []DecorateError // documents a decorator rejected; skipped, never silent
	Claims             int             // enrichment claims folded in across every document
	EnrichFailed       []EnrichError   // enrichment calls that failed; counted, never fatal
}

// ErrNoEnricher is the failure recorded when the policy names a source this
// build carries no enricher for. Nothing ran, so it is reported rather than
// skipped in silence.
var ErrNoEnricher = errors.New("pipeline: no enricher built for this source")

// EnrichError names the source and document an enrichment call failed for. The
// document is still ingested (plan D7).
type EnrichError struct {
	Source enrich.Source
	Digest string
	Err    error
}

func (e EnrichError) Error() string {
	return fmt.Sprintf("enrich %s (sha256:%s): %v", e.Source, e.Digest, e.Err)
}

func (e EnrichError) Unwrap() error { return e.Err }

// String renders the receipt the one-shot CLI prints.
func (r Receipt) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "documents=%d nodes=%d edges=%d transactions=%d basis=%d skipped=%d fallbacks=%d expanded=%d decorated=%d decorate_failed=%d claims=%d enrich_failed=%d",
		r.Documents, r.Nodes, r.Edges, r.Transactions, r.Basis, len(r.Skipped), r.Fallbacks, r.Expanded, r.Decorated, len(r.DecorateFailed), r.Claims, len(r.EnrichFailed))
	for _, f := range r.Skipped {
		fmt.Fprintf(&b, "\n  skipped %s: %v", f.Source, f.Err)
	}
	for _, f := range r.DecorateFailed {
		fmt.Fprintf(&b, "\n  decorate failed %s: %v", f.Source, f.Err)
	}
	for _, f := range r.EnrichFailed {
		fmt.Fprintf(&b, "\n  enrich failed %s %s: %v", f.Source, f.Digest, f.Err)
	}
	if r.ExpansionExhausted {
		fmt.Fprintf(&b, "\n  expansion budget %d reached; some transitive dependencies were not collected", r.ExpansionBudget)
	}
	return b.String()
}

// Observer is the daemon's metrics seam (consumer-side, small). nil ⇒ no-op.
type Observer interface {
	DocumentIngested()
	DocumentSkipped()
	DocumentFailed()
	RecordsEmitted(nodes, edges int64)
	FallbacksCounted(n int)
	ExpansionDocuments(n int)
	DocumentDecorated()
	DocumentDecorateFailed()
	ClaimsEmitted(n int)
	EnrichFailed(source enrich.Source)
}

type noopObserver struct{}

func (noopObserver) DocumentIngested()            {}
func (noopObserver) DocumentSkipped()             {}
func (noopObserver) DocumentFailed()              {}
func (noopObserver) RecordsEmitted(_, _ int64)    {}
func (noopObserver) FallbacksCounted(_ int)       {}
func (noopObserver) ExpansionDocuments(_ int)     {}
func (noopObserver) DocumentDecorated()           {}
func (noopObserver) DocumentDecorateFailed()      {}
func (noopObserver) ClaimsEmitted(_ int)          {}
func (noopObserver) EnrichFailed(_ enrich.Source) {}

// Deps are the injected I/O/clock/observability dependencies (the core stays pure).
type Deps struct {
	expand       expandFunc        // internal expansion seam for receipt tests
	DrainTimeout time.Duration     // accepted-work grace period after cancellation; zero defaults to 30 seconds
	Sink         Sink              // required
	Observer     Observer          // nil ⇒ noopObserver
	Now          func() time.Time  // nil ⇒ func() time.Time { return time.Now().UTC() }
	Logger       *slog.Logger      // nil ⇒ slog over io.Discard
	Decorators   []Decorator       // run in order; each sees the stream the previous ones extended
	Enrichers    []enrich.Enricher // available sources; the config's policy picks and orders them
	// PrepareWorkers bounds how many documents assemble→enrich→decorate at
	// once. Zero (the default) and 1 both mean one document at a time.
	// AutoWorkers means GOMAXPROCS-1, leaving one core for the collector's
	// own parse fan-out. Whatever the width, the receipt and the sink see
	// documents in arrival order, so a run's output does not depend on it.
	//
	// It is opt-in because above 1 the pipeline calls every Decorator and
	// every Enricher from more than one goroutine, and in no fixed order:
	// a decorator that counts, caches or allocates per document must guard
	// that state and must not read anything into the order it is called in.
	// The caller that wrote them is the one who knows.
	PrepareWorkers int
}

// AutoWorkers asks Deps.PrepareWorkers for one worker per core, less one for
// the collector's parse fan-out.
const AutoWorkers = -1

// prepareWorkers resolves Deps.PrepareWorkers to a width of at least 1.
// Anything but AutoWorkers and a positive count is one worker: the default
// stays the serial pipeline every caller already has.
func prepareWorkers(n int) int {
	if n > 0 {
		return n
	}
	if n != AutoWorkers {
		return 1
	}
	if w := runtime.GOMAXPROCS(0) - 1; w > 1 {
		return w
	}
	return 1
}

// docEffects is the book-keeping one document produced while it was prepared.
// A worker fills it; the sequencer folds it into the receipt in arrival order,
// so a concurrent run's receipt is identical to a serial one's.
type docEffects struct {
	fallbacks      int
	enrichFailed   []EnrichError
	claims         int
	decorated      bool
	decorateFailed *DecorateError
	scanFailed     []EnrichError
}

// sourcesFromConfig maps configured receivers into a guacseam.Sources (Scan and
// OnSkip are set by Run at call time). A collector's Poll bool is (poll > 0) and
// its Interval is the poll duration.
func sourcesFromConfig(r config.Receivers) guacseam.Sources {
	var src guacseam.Sources
	if r.Files != nil {
		src.Files = &guacseam.FilesReceiver{Path: r.Files.Path, Poll: r.Files.Poll > 0, Interval: r.Files.Poll}
	}
	if r.OCI != nil {
		src.OCI = &guacseam.OCIReceiver{Refs: r.OCI.Refs, Registry: r.OCI.Registry, Insecure: r.OCI.Insecure, Poll: r.OCI.Poll > 0, Interval: r.OCI.Poll}
	}
	if r.S3 != nil {
		src.S3 = &guacseam.S3Receiver{URL: r.S3.URL, Bucket: r.S3.Bucket, Path: r.S3.Path, Region: r.S3.Region, Queues: r.S3.Queues, Poll: r.S3.Poll > 0}
	}
	if r.GCS != nil {
		src.GCS = &guacseam.GCSReceiver{Bucket: r.GCS.Bucket, Poll: r.GCS.Poll > 0, Interval: r.GCS.Poll}
	}
	return src
}

// anyPolling reports whether any configured receiver has a non-zero poll period.
func anyPolling(r config.Receivers) bool {
	return (r.Files != nil && r.Files.Poll > 0) ||
		(r.OCI != nil && r.OCI.Poll > 0) ||
		(r.S3 != nil && r.S3.Poll > 0) ||
		(r.GCS != nil && r.GCS.Poll > 0)
}

// enricherFor returns the enricher registered for src, or nil when the policy
// names a source this deployment did not build one for.
func enricherFor(es []enrich.Enricher, src enrich.Source) enrich.Enricher {
	for _, e := range es {
		if e.Source() == src {
			return e
		}
	}
	return nil
}

// foldClaims merges every claim's records into s, returning the merged stream
// and how many claims it folded in.
func foldClaims(s varve.Stream, claims []enrich.StampedClaim) (varve.Stream, int) {
	if len(claims) == 0 {
		return s, 0
	}
	streams := make([]varve.Stream, 0, len(claims)+1)
	streams = append(streams, s)
	for _, c := range claims {
		streams = append(streams, c.Records())
	}
	return varve.Merge(streams...), len(claims)
}

type expandFunc func(context.Context, []string, int, guacseam.DocumentFunc) (guacseam.Expansion, error)

// Run builds the collect→assemble→decorate→sink pipeline from cfg and runs it.
// It builds a collector per configured receiver (polling when any receiver's
// Poll>0, else one pass) and uses cfg.Processors.ValidTime; the caller supplies
// the Sink and any Decorators via deps. Every document (receiver or expansion,
// in both modes) is assembled alone, then each Decorator extends its stream. A
// decorator error skips that document, counts it in Receipt.DecorateFailed and
// the run continues. Poll mode sinks each document's stream at once. A one-pass
// run merges every document's stream (varve.Merge: content-derived ids make
// this equal to one batched assembly) and sinks ONCE, so it stays one
// transaction. Returns the cumulative Receipt (the daemon logs it at shutdown;
// the one-shot prints it). Any sink failure terminates the run with its committed progress in the receipt.
func Run(ctx context.Context, cfg config.Config, deps Deps) (Receipt, error) {
	expandDepsDev := deps.expand
	if expandDepsDev == nil {
		expandDepsDev = guacseam.ExpandDepsDev
	}
	if cfg.Receivers.Files == nil && cfg.Receivers.OCI == nil && cfg.Receivers.S3 == nil && cfg.Receivers.GCS == nil {
		return Receipt{}, fmt.Errorf("pipeline: at least one receiver is required")
	}
	workCtx, stopProcessing := guacseam.DrainContext(ctx, deps.DrainTimeout)
	defer stopProcessing()
	observer := deps.Observer
	if observer == nil {
		observer = noopObserver{}
	}
	now := deps.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	logger := deps.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	guard := validtime.Guard{Floor: cfg.Processors.ValidTime.Floor, Skew: cfg.Processors.ValidTime.FutureSkew}
	policy := cfg.Processors.Enrich.Policy
	scan := policy.ScanFlags()
	expandCfg := cfg.Processors.Expand
	oneShot := !anyPolling(cfg.Receivers)

	var rec Receipt
	if expandCfg.DepsDev {
		rec.ExpansionBudget = expandCfg.MaxDocs
	}

	// enrichDocument turns the document's own scanner evidence into claims, then
	// runs every allowed enricher in policy order, each seeing the claims the
	// previous ones added. A failure is recorded and counted; the document is
	// still ingested (plan D7).
	enrichDocument := func(ctx context.Context, digest string, raw []byte, s varve.Stream, t time.Time, eff *docEffects) varve.Stream {
		merged, n := foldClaims(s, policy.Stamp(enrich.Derive(s)))
		for _, src := range policy.Sources {
			// A source the policy itself refuses is silent: that is the cap
			// doing its job. A source this build has no enricher for is not —
			// the org asked for it and nothing ran, so it is reported.
			if !policy.Allows(src) {
				continue
			}
			// A scanner source already ran inside the parser and a replay
			// source is a host job's work; neither missing an Enricher here
			// is a fault.
			if src.Runner() != enrich.RunByEnricher {
				continue
			}
			e := enricherFor(deps.Enrichers, src)
			if e == nil {
				eff.enrichFailed = append(eff.enrichFailed, EnrichError{Source: src, Digest: digest, Err: ErrNoEnricher})
				continue
			}
			claims, err := e.Enrich(ctx, enrich.Input{Digest: digest, Records: merged, Document: raw, Now: t})
			if err != nil {
				eff.enrichFailed = append(eff.enrichFailed, EnrichError{Source: src, Digest: digest, Err: err})
				continue
			}
			var added int
			merged, added = foldClaims(merged, policy.Stamp(claims))
			n += added
		}
		eff.claims += n
		return merged
	}

	// prepare assembles one document, enriches it and runs the decorator chain
	// over its stream. ok=false means a decorator rejected it: recorded,
	// counted, skipped.
	prepare := func(ctx context.Context, p guacseam.Parsed) (varve.Stream, bool, docEffects) {
		var eff docEffects
		t := now()
		res := assemble.Assemble(ctx, p.Preds, guard, t)
		eff.fallbacks = res.Fallbacks
		var raw []byte
		if p.Doc != nil {
			raw = p.Doc.Blob
		}
		sum := sha256.Sum256(raw)
		digest := hex.EncodeToString(sum[:])
		for _, failure := range p.ScanFailed {
			eff.scanFailed = append(eff.scanFailed, EnrichError{Source: enrich.Source(failure.Source), Digest: digest, Err: failure.Err})
		}
		records := enrichDocument(ctx, digest, raw, res.Stream, t, &eff)
		if len(deps.Decorators) == 0 {
			return records, true, eff
		}
		in := DecorateInput{
			Raw:       raw,
			Digest:    digest,
			Source:    p.Source,
			Origin:    p.Origin,
			Doc:       p.Doc,
			Preds:     p.Preds,
			Records:   records,
			ValidFrom: res.ValidFrom,
			Fallback:  res.Fallback,
			Now:       t,
		}
		for _, d := range deps.Decorators {
			extra, err := d.Decorate(ctx, in)
			if err != nil {
				de := DecorateError{Source: p.Source, Digest: digest, Err: err}
				eff.decorateFailed = &de
				return varve.Stream{}, false, eff
			}
			in.Records = varve.Merge(in.Records, extra)
		}
		eff.decorated = true
		return in.Records, true, eff
	}

	// applyEffects folds one document's book-keeping into the receipt and the
	// observer. The sequencer is the only caller and it calls in arrival
	// order, so the receipt's slices keep the order a serial run gave them.
	applyEffects := func(eff docEffects) {
		rec.Fallbacks += eff.fallbacks
		observer.FallbacksCounted(eff.fallbacks)
		for _, e := range eff.scanFailed {
			rec.EnrichFailed = append(rec.EnrichFailed, e)
			observer.EnrichFailed(e.Source)
			logger.Warn("scanner failed", "source", e.Source, "digest", e.Digest, "error", e.Err)
		}
		for _, e := range eff.enrichFailed {
			rec.EnrichFailed = append(rec.EnrichFailed, e)
			observer.EnrichFailed(e.Source)
			if errors.Is(e.Err, ErrNoEnricher) {
				logger.Warn("no enricher for a source the policy names", "source", e.Source, "digest", e.Digest)
				continue
			}
			logger.Warn("enrichment failed", "source", e.Source, "digest", e.Digest, "error", e.Err)
		}
		rec.Claims += eff.claims
		observer.ClaimsEmitted(eff.claims)
		if de := eff.decorateFailed; de != nil {
			rec.DecorateFailed = append(rec.DecorateFailed, *de)
			observer.DocumentDecorateFailed()
			logger.Warn("document rejected by decorator", "source", de.Source, "digest", de.Digest, "error", de.Err)
		}
		if eff.decorated {
			rec.Decorated++
			observer.DocumentDecorated()
		}
	}

	ingestStream := func(ctx context.Context, source string, s varve.Stream) error {
		r, err := deps.Sink.Ingest(ctx, s)
		if err != nil {
			var ie *varve.IngestError
			if errors.As(err, &ie) {
				fold(&rec, ie.Committed)
			}
			logger.Error("sink ingest failed", "source", source, "error", err)
			return err
		}
		fold(&rec, r)
		observer.RecordsEmitted(int64(len(s.Nodes)), int64(len(s.Edges)))
		logger.Info("stream ingested", "source", source, "nodes", len(s.Nodes), "edges", len(s.Edges))
		return nil
	}

	expand := func(ctx context.Context, source string, purls []string, handle guacseam.DocumentFunc) error {
		if !expandCfg.DepsDev {
			return nil
		}
		remaining := expandCfg.MaxDocs - rec.Expanded
		if remaining <= 0 {
			return nil
		}
		exp, eerr := expandDepsDev(ctx, purls, remaining, handle)
		rec.Skipped = append(rec.Skipped, exp.Failed...)
		for _, failure := range exp.Failed {
			observer.DocumentSkipped()
			logger.Warn("expansion document skipped", "source", failure.Source, "error", failure.Err)
		}
		rec.Expanded += exp.Collected
		rec.ExpansionExhausted = rec.ExpansionExhausted || exp.Exhausted
		observer.ExpansionDocuments(exp.Collected)
		if eerr != nil {
			logger.Error("expansion failed", "source", source, "error", eerr)
			return eerr
		}
		return nil
	}

	// A one-shot pass merges every document's (and expansion document's)
	// stream into ONE sink call: cross-document duplicates dedup away before
	// the wire and the run pays one transaction instead of one per document.
	// Deterministic ids make the merge replay-identical to per-document ingest
	// (§2.6). Poll mode has no end-of-pass flush point, so it sinks per document.
	var batch []varve.Stream
	var batched int

	// handle is the ordered half of a document's life: the receipt, the batch
	// and the sink. It runs on one goroutine, one document at a time, in
	// arrival order, whatever width prepare ran at.
	handle := func(ctx context.Context, p guacseam.Parsed, s varve.Stream, ok bool, eff docEffects) error {
		applyEffects(eff)
		if !ok {
			return nil // rejected by a decorator: counted, skipped, no expansion
		}
		if oneShot {
			batch = append(batch, s)
			batched++
			return expand(ctx, p.Source, p.Purls, func(ctx context.Context, ep guacseam.Parsed) error {
				es, eok, eeff := prepare(ctx, ep)
				applyEffects(eeff)
				if eok {
					batch = append(batch, es)
				}
				return nil
			})
		}
		if err := ingestStream(ctx, p.Source, s); err != nil {
			observer.DocumentFailed()
			return err
		}
		observer.DocumentIngested()
		return expand(ctx, p.Source, p.Purls, func(ctx context.Context, ep guacseam.Parsed) error {
			es, eok, eeff := prepare(ctx, ep)
			applyEffects(eeff)
			if !eok {
				return nil
			}
			if err := ingestStream(ctx, ep.Source, es); err != nil {
				observer.DocumentFailed()
				return err
			}
			return nil
		})
	}

	// prepare is per-document CPU and per-document network (the enrichers),
	// and it is the stage a pass spends its wall clock in. Spreading it over
	// workers while handle stays ordered keeps every output identical and
	// lets the cores work.
	workers := prepareWorkers(deps.PrepareWorkers)
	var fn guacseam.DocumentFunc
	var drainPool func() error
	if workers == 1 {
		fn = func(ctx context.Context, p guacseam.Parsed) error {
			s, ok, eff := prepare(ctx, p)
			return handle(ctx, p, s, ok, eff)
		}
	} else {
		pool := startPreparePool(workCtx, workers, prepare, handle)
		fn, drainPool = pool.submit, pool.drain
	}

	src := sourcesFromConfig(cfg.Receivers)
	src.Scan = scan
	src.ProcessingContext = workCtx
	src.OnSkip = func(fd guacseam.FailedDocument) {
		observer.DocumentSkipped()
		logger.Warn("document skipped", "source", fd.Source, "error", fd.Err)
	}
	out, err := guacseam.Collect(ctx, src, fn)
	// Every worker and the sequencer must be finished before the receipt is
	// read: they are the ones writing it.
	if drainPool != nil {
		if perr := drainPool(); err == nil {
			err = perr
		}
	}
	rec.Documents = out.Documents
	rec.Skipped = append(rec.Skipped, out.Failed...)
	if err != nil {
		return rec, fmt.Errorf("running receivers: %w", err)
	}
	if len(batch) > 0 {
		if err := ingestStream(workCtx, "batch", varve.Merge(batch...)); err != nil {
			for i := 0; i < batched; i++ {
				observer.DocumentFailed()
			}
			return rec, err
		}
		for i := 0; i < batched; i++ {
			observer.DocumentIngested()
		}
	}
	return rec, nil
}

func fold(rec *Receipt, r varve.Receipt) {
	rec.Nodes += r.Nodes
	rec.Edges += r.Edges
	rec.Transactions += r.Transactions
	rec.Basis = r.Basis
}

// preparedDoc is one document on its way through the pool: the parse result
// going in, and the prepare output plus its book-keeping coming back. seq is
// the arrival position that puts it back in order.
type preparedDoc struct {
	seq int
	p   guacseam.Parsed
	s   varve.Stream
	ok  bool
	eff docEffects
}

// preparePool runs prepare on several documents at once and hands each result
// to handle on one goroutine, in arrival order. handle is therefore as serial
// as it ever was; only the per-document work spreads out.
type preparePool struct {
	ctx  context.Context
	jobs chan preparedDoc
	done chan struct{}
	seq  int

	mu  sync.Mutex
	err error
}

// startPreparePool starts workers and the sequencer. Call drain once the
// producer is finished, before reading anything handle wrote.
func startPreparePool(
	ctx context.Context,
	workers int,
	prepare func(context.Context, guacseam.Parsed) (varve.Stream, bool, docEffects),
	handle func(context.Context, guacseam.Parsed, varve.Stream, bool, docEffects) error,
) *preparePool {
	pool := &preparePool{ctx: ctx, jobs: make(chan preparedDoc), done: make(chan struct{})}
	results := make(chan preparedDoc, workers)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range pool.jobs {
				j.s, j.ok, j.eff = prepare(ctx, j.p)
				select {
				case results <- j:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	go func() { wg.Wait(); close(results) }()
	go pool.sequence(results, handle)
	return pool
}

// sequence delivers results to handle in arrival order, holding the ones that
// finished early until their turn comes.
func (pool *preparePool) sequence(
	results <-chan preparedDoc,
	handle func(context.Context, guacseam.Parsed, varve.Stream, bool, docEffects) error,
) {
	defer close(pool.done)
	pending := map[int]preparedDoc{}
	next := 0
	for r := range results {
		pending[r.seq] = r
		for pool.failed() == nil {
			q, ok := pending[next]
			if !ok {
				break
			}
			delete(pending, next)
			next++
			if err := handle(pool.ctx, q.p, q.s, q.ok, q.eff); err != nil {
				pool.fail(err)
			}
		}
	}
}

// submit queues one document. It blocks while every worker is busy, which is
// what holds the whole pass to a bounded number of documents in flight.
func (pool *preparePool) submit(ctx context.Context, p guacseam.Parsed) error {
	// A sink failure downstream aborts intake at the next document, as it
	// does when the stages are one goroutine.
	if err := pool.failed(); err != nil {
		return err
	}
	select {
	case pool.jobs <- preparedDoc{seq: pool.seq, p: p}:
		pool.seq++
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-pool.ctx.Done():
		return pool.ctx.Err()
	}
}

// drain closes intake and waits for every worker and the sequencer to finish.
// Until it returns, the receipt is still being written.
func (pool *preparePool) drain() error {
	close(pool.jobs)
	<-pool.done
	return pool.failed()
}

func (pool *preparePool) fail(err error) {
	pool.mu.Lock()
	defer pool.mu.Unlock()
	if pool.err == nil {
		pool.err = err
	}
}

func (pool *preparePool) failed() error {
	pool.mu.Lock()
	defer pool.mu.Unlock()
	return pool.err
}
