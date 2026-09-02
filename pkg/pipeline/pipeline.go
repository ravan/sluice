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
}

// String renders the receipt the one-shot CLI prints.
func (r Receipt) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "documents=%d nodes=%d edges=%d transactions=%d basis=%d skipped=%d fallbacks=%d expanded=%d decorated=%d decorate_failed=%d",
		r.Documents, r.Nodes, r.Edges, r.Transactions, r.Basis, len(r.Skipped), r.Fallbacks, r.Expanded, r.Decorated, len(r.DecorateFailed))
	for _, f := range r.Skipped {
		fmt.Fprintf(&b, "\n  skipped %s: %v", f.Source, f.Err)
	}
	for _, f := range r.DecorateFailed {
		fmt.Fprintf(&b, "\n  decorate failed %s: %v", f.Source, f.Err)
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
}

type noopObserver struct{}

func (noopObserver) DocumentIngested()         {}
func (noopObserver) DocumentSkipped()          {}
func (noopObserver) DocumentFailed()           {}
func (noopObserver) RecordsEmitted(_, _ int64) {}
func (noopObserver) FallbacksCounted(_ int)    {}
func (noopObserver) ExpansionDocuments(_ int)  {}
func (noopObserver) DocumentDecorated()        {}
func (noopObserver) DocumentDecorateFailed()   {}

// Deps are the injected I/O/clock/observability dependencies (the core stays pure).
type Deps struct {
	Sink       Sink             // required
	Observer   Observer         // nil ⇒ noopObserver
	Now        func() time.Time // nil ⇒ func() time.Time { return time.Now().UTC() }
	Logger     *slog.Logger     // nil ⇒ slog over io.Discard
	Decorators []Decorator      // run in order; each sees the stream the previous ones extended
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
// the one-shot prints it). A one-pass sink failure is returned; a poll-mode
// sink failure is logged+counted and polling continues.
func Run(ctx context.Context, cfg config.Config, deps Deps) (Receipt, error) {
	if cfg.Receivers.Files == nil && cfg.Receivers.OCI == nil && cfg.Receivers.S3 == nil && cfg.Receivers.GCS == nil {
		return Receipt{}, fmt.Errorf("pipeline: at least one receiver is required")
	}
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
	scan := guacseam.ScanFlags{Vulns: cfg.Processors.Enrich.Vulns, Licenses: cfg.Processors.Enrich.Licenses, EOL: cfg.Processors.Enrich.EOL, DepsDev: cfg.Processors.Enrich.DepsDev}
	expandCfg := cfg.Processors.Expand
	oneShot := !anyPolling(cfg.Receivers)

	var rec Receipt
	if expandCfg.DepsDev {
		rec.ExpansionBudget = expandCfg.MaxDocs
	}

	// prepare assembles one document and runs the decorator chain over its
	// stream. ok=false means a decorator rejected it: recorded, counted, skipped.
	prepare := func(ctx context.Context, p guacseam.Parsed) (varve.Stream, bool) {
		t := now()
		res := assemble.Assemble(ctx, p.Preds, guard, t)
		rec.Fallbacks += res.Fallbacks
		observer.FallbacksCounted(res.Fallbacks)
		if len(deps.Decorators) == 0 {
			return res.Stream, true
		}
		var raw []byte
		if p.Doc != nil {
			raw = p.Doc.Blob
		}
		sum := sha256.Sum256(raw)
		in := DecorateInput{
			Raw:       raw,
			Digest:    hex.EncodeToString(sum[:]),
			Source:    p.Source,
			Origin:    p.Origin,
			Doc:       p.Doc,
			Preds:     p.Preds,
			Records:   res.Stream,
			ValidFrom: res.ValidFrom,
			Fallback:  res.Fallback,
			Now:       t,
		}
		for _, d := range deps.Decorators {
			extra, err := d.Decorate(ctx, in)
			if err != nil {
				de := DecorateError{Source: p.Source, Digest: in.Digest, Err: err}
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

	expand := func(ctx context.Context, source string, purls []string, handle guacseam.DocumentFunc) {
		if !expandCfg.DepsDev {
			return
		}
		remaining := expandCfg.MaxDocs - rec.Expanded
		if remaining <= 0 {
			return
		}
		exp, eerr := guacseam.ExpandDepsDev(ctx, purls, remaining, handle)
		rec.Expanded += exp.Collected
		rec.ExpansionExhausted = rec.ExpansionExhausted || exp.Exhausted
		observer.ExpansionDocuments(exp.Collected)
		if eerr != nil {
			logger.Error("expansion failed", "source", source, "error", eerr)
		}
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
			expand(ctx, p.Source, p.Purls, func(ctx context.Context, ep guacseam.Parsed) error {
				if es, ok := prepare(ctx, ep); ok {
					batch = append(batch, es)
				}
				return nil // best-effort: an expansion doc never aborts expansion or the run
			})
			return nil
		}
	} else {
		fn = func(ctx context.Context, p guacseam.Parsed) error {
			s, ok := prepare(ctx, p)
			if !ok {
				return nil // rejected by a decorator: counted, skipped, no expansion
			}
			if err := ingestStream(ctx, p.Source, s); err != nil {
				observer.DocumentFailed()
				return nil // poll mode: a sink failure is logged+counted and polling continues
			}
			observer.DocumentIngested()
			expand(ctx, p.Source, p.Purls, func(ctx context.Context, ep guacseam.Parsed) error {
				es, ok := prepare(ctx, ep)
				if !ok {
					return nil
				}
				if err := ingestStream(ctx, ep.Source, es); err != nil {
					observer.DocumentFailed()
				}
				return nil // best-effort: an expansion doc never aborts expansion or the run
			})
			return nil
		}
	}

	src := sourcesFromConfig(cfg.Receivers)
	src.Scan = scan
	src.OnSkip = func(fd guacseam.FailedDocument) {
		observer.DocumentSkipped()
		logger.Warn("document skipped", "source", fd.Source, "error", fd.Err)
	}
	out, err := guacseam.Collect(ctx, src, fn)
	rec.Documents = out.Documents
	rec.Skipped = out.Failed
	if err != nil {
		return rec, fmt.Errorf("running receivers: %w", err)
	}
	if len(batch) > 0 {
		if err := ingestStream(ctx, "batch", varve.Merge(batch...)); err != nil {
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
