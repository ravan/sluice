package pipeline

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
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
	enrichDocument := func(ctx context.Context, digest string, s varve.Stream, t time.Time) varve.Stream {
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
				rec.EnrichFailed = append(rec.EnrichFailed, EnrichError{Source: src, Digest: digest, Err: ErrNoEnricher})
				observer.EnrichFailed(src)
				logger.Warn("no enricher for a source the policy names", "source", src, "digest", digest)
				continue
			}
			claims, err := e.Enrich(ctx, enrich.Input{Digest: digest, Records: merged, Now: t})
			if err != nil {
				rec.EnrichFailed = append(rec.EnrichFailed, EnrichError{Source: src, Digest: digest, Err: err})
				observer.EnrichFailed(src)
				logger.Warn("enrichment failed", "source", src, "digest", digest, "error", err)
				continue
			}
			var added int
			merged, added = foldClaims(merged, policy.Stamp(claims))
			n += added
		}
		rec.Claims += n
		observer.ClaimsEmitted(n)
		return merged
	}

	// prepare assembles one document, enriches it and runs the decorator chain
	// over its stream. ok=false means a decorator rejected it: recorded,
	// counted, skipped.
	prepare := func(ctx context.Context, p guacseam.Parsed) (varve.Stream, bool) {
		t := now()
		res := assemble.Assemble(ctx, p.Preds, guard, t)
		rec.Fallbacks += res.Fallbacks
		observer.FallbacksCounted(res.Fallbacks)
		var raw []byte
		if p.Doc != nil {
			raw = p.Doc.Blob
		}
		sum := sha256.Sum256(raw)
		digest := hex.EncodeToString(sum[:])
		for _, failure := range p.ScanFailed {
			source := enrich.Source(failure.Source)
			rec.EnrichFailed = append(rec.EnrichFailed, EnrichError{Source: source, Digest: digest, Err: failure.Err})
			observer.EnrichFailed(source)
			logger.Warn("scanner failed", "source", source, "digest", digest, "error", failure.Err)
		}
		records := enrichDocument(ctx, digest, res.Stream, t)
		if len(deps.Decorators) == 0 {
			return records, true
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
				rec.DecorateFailed = append(rec.DecorateFailed, de)
				observer.DocumentDecorateFailed()
				logger.Warn("document rejected by decorator", "source", p.Source, "digest", in.Digest, "error", err)
				return varve.Stream{}, false
			}
			in.Records = varve.Merge(in.Records, extra)
		}
		rec.Decorated++
		observer.DocumentDecorated()
		return in.Records, true
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
	var fn guacseam.DocumentFunc
	if oneShot {
		fn = func(ctx context.Context, p guacseam.Parsed) error {
			s, ok := prepare(ctx, p)
			if !ok {
				return nil // rejected by a decorator: counted, skipped, no expansion
			}
			batch = append(batch, s)
			batched++
			return expand(ctx, p.Source, p.Purls, func(ctx context.Context, ep guacseam.Parsed) error {
				if es, ok := prepare(ctx, ep); ok {
					batch = append(batch, es)
				}
				return nil
			})
		}
	} else {
		fn = func(ctx context.Context, p guacseam.Parsed) error {
			s, ok := prepare(ctx, p)
			if !ok {
				return nil // rejected by a decorator: counted, skipped, no expansion
			}
			if err := ingestStream(ctx, p.Source, s); err != nil {
				observer.DocumentFailed()
				return err
			}
			observer.DocumentIngested()
			return expand(ctx, p.Source, p.Purls, func(ctx context.Context, ep guacseam.Parsed) error {
				es, ok := prepare(ctx, ep)
				if !ok {
					return nil
				}
				if err := ingestStream(ctx, ep.Source, es); err != nil {
					observer.DocumentFailed()
					return err
				}
				return nil
			})
		}
	}

	src := sourcesFromConfig(cfg.Receivers)
	src.Scan = scan
	src.ProcessingContext = workCtx
	src.OnSkip = func(fd guacseam.FailedDocument) {
		observer.DocumentSkipped()
		logger.Warn("document skipped", "source", fd.Source, "error", fd.Err)
	}
	out, err := guacseam.Collect(ctx, src, fn)
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
