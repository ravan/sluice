package guacseam

import (
	"context"
	"errors"
	"fmt"

	"github.com/guacsec/guac/pkg/collectsub/datasource"
	"github.com/guacsec/guac/pkg/collectsub/datasource/inmemsource"
	"github.com/guacsec/guac/pkg/handler/collector"
	"github.com/guacsec/guac/pkg/handler/collector/deps_dev"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/logging"
)

// Expansion reports one expansion pass: how many documents were collected (Collected),
// the budget it ran under (Limit), and whether the budget clamped collection (Exhausted).
type Expansion struct {
	Collected int
	Limit     int
	Exhausted bool
	Failed    []FailedDocument
}

// docRetriever is the deps.dev collector's method, isolated as a consumer-side seam so the
// budget/drain core (drainExpansion) is unit-testable with a fake. *depsCollector satisfies it.
type docRetriever interface {
	RetrieveArtifacts(ctx context.Context, docChannel chan<- *processor.Document) error
}

// ExpandDepsDev builds the imported deps.dev collector for purls and drives it directly
// (never via collector.Collect), processing/parsing/handing each emitted document to fn,
// bounded by limit. It is an I/O boundary (real deps.dev calls) — proven by the demo, not
// a unit test.
func ExpandDepsDev(ctx context.Context, purls []string, limit int, fn DocumentFunc) (Expansion, error) {
	if len(purls) == 0 || limit <= 0 {
		return Expansion{Limit: limit}, nil
	}
	srcs := make([]datasource.Source, len(purls))
	for i, p := range purls {
		srcs[i] = datasource.Source{Value: p}
	}
	ds, err := inmemsource.NewInmemDataSources(&datasource.DataSources{PurlDataSources: srcs})
	if err != nil {
		return Expansion{Limit: limit}, fmt.Errorf("building deps.dev datasource: %w", err)
	}
	col, err := deps_dev.NewDepsCollector(ctx, ds, false, true, 0, nil)
	if err != nil {
		return Expansion{Limit: limit}, fmt.Errorf("building deps.dev collector: %w", err)
	}
	return drainExpansion(ctx, col, limit, expansionHandler(fn))
}

// expansionHandler adapts fn to the per-document handler drainExpansion drives:
// process+parse the expansion document (no enrichment scans) and hand it to fn
// tagged OriginExpansion. A malformed document is skipped, never fatal.
func expansionHandler(fn DocumentFunc) func(context.Context, *processor.Document) error {
	return func(ctx context.Context, doc *processor.Document) error {
		collector.AddChildLogger(logging.FromContext(ctx), doc)
		preds, subpurls, perr := processAndParse(ctx, doc)
		if perr != nil {
			return &expansionParseError{FailedDocument{Source: doc.SourceInformation.Source, Err: perr}}
		}
		return fn(ctx, Parsed{Source: doc.SourceInformation.Source, Origin: OriginExpansion, Doc: doc, Preds: preds, Purls: subpurls})
	}
}

type expansionParseError struct{ FailedDocument }

func (e *expansionParseError) Error() string { return e.Err.Error() }

// drainExpansion is the testable core: run r.RetrieveArtifacts in a goroutine emitting to a
// channel; process up to limit documents through handle; drain-and-discard the overflow
// (setting Exhausted) so the goroutine always finishes; surface the first handle error or
// the retriever's error.
func drainExpansion(ctx context.Context, r docRetriever, limit int, handle func(context.Context, *processor.Document) error) (Expansion, error) {
	intake, stop := context.WithCancel(ctx)
	defer stop()
	docs := make(chan *processor.Document)
	errc := make(chan error, 1)
	go func() { errc <- r.RetrieveArtifacts(intake, docs); close(docs) }()

	exp := Expansion{Limit: limit}
collect:
	for {
		var doc *processor.Document
		select {
		case d, ok := <-docs:
			if !ok {
				break collect
			}
			doc = d
		case <-ctx.Done():
			stop()
			go drainCollectors(context.WithoutCancel(ctx), docs)
			return exp, fmt.Errorf("deps.dev expansion canceled: %w", ctx.Err())
		}

		if exp.Collected >= limit {
			exp.Exhausted = true
			continue // budget hit: drain-and-discard the rest
		}
		if err := handle(ctx, doc); err != nil {
			var parseErr *expansionParseError
			if errors.As(err, &parseErr) {
				exp.Failed = append(exp.Failed, parseErr.FailedDocument)
				exp.Collected++
				continue
			}
			stop()
			go drainCollectors(context.WithoutCancel(ctx), docs)
			return exp, err
		}
		exp.Collected++
	}
	if err := <-errc; err != nil {
		return exp, fmt.Errorf("deps.dev expansion: %w", err)
	}
	return exp, nil
}
