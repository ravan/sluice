package guacseam

import (
	"context"
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
func ExpandDepsDev(ctx context.Context, purls []string, limit int, fn PredicateFunc) (Expansion, error) {
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
	handle := func(ctx context.Context, doc *processor.Document) error {
		collector.AddChildLogger(logging.FromContext(ctx), doc)
		preds, subpurls, perr := processAndParse(ctx, doc, ScanFlags{})
		if perr != nil {
			return nil // best-effort: a malformed expansion doc is skipped, not fatal
		}
		return fn(ctx, doc.SourceInformation.Source, preds, subpurls)
	}
	return drainExpansion(ctx, col, limit, handle)
}

// drainExpansion is the testable core: run r.RetrieveArtifacts in a goroutine emitting to a
// channel; process up to limit documents through handle; drain-and-discard the overflow
// (setting Exhausted) so the goroutine always finishes; surface the first handle error or
// the retriever's error.
func drainExpansion(ctx context.Context, r docRetriever, limit int, handle func(context.Context, *processor.Document) error) (Expansion, error) {
	docs := make(chan *processor.Document)
	errc := make(chan error, 1)
	go func() { errc <- r.RetrieveArtifacts(ctx, docs); close(docs) }()

	exp := Expansion{Limit: limit}
	var handleErr error
	for doc := range docs {
		if handleErr != nil {
			continue // drain remaining docs so the goroutine can finish
		}
		if exp.Collected >= limit {
			exp.Exhausted = true
			continue // budget hit: drain-and-discard the rest
		}
		if err := handle(ctx, doc); err != nil {
			handleErr = err
			continue
		}
		exp.Collected++
	}
	if handleErr != nil {
		return exp, handleErr
	}
	if err := <-errc; err != nil {
		return exp, fmt.Errorf("deps.dev expansion: %w", err)
	}
	return exp, nil
}
