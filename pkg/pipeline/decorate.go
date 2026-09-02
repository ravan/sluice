package pipeline

import (
	"context"
	"fmt"
	"time"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/handler/processor"

	"github.com/ravan/sluice/pkg/guacseam"
	"github.com/ravan/sluice/pkg/varve"
)

// Decorator adds records to one document's stream. It runs after assemble and
// before the sink, so it is the only point that sees both the document and the
// Sluice records made from it while still inside the document's transaction.
// It must not modify in.Records. It may copy ids from in.Records into its own
// edges. It must be safe for concurrent use. Decorators run in Deps order;
// each sees the stream the previous ones extended.
type Decorator interface {
	Decorate(ctx context.Context, in DecorateInput) (varve.Stream, error)
}

// DecorateInput is everything a Decorator may read about one document.
type DecorateInput struct {
	Raw       []byte                       // Doc.Blob, the original bytes
	Digest    string                       // lower-case hex sha256 of Raw
	Source    string                       // receiver URI or expansion tag
	Origin    guacseam.Origin              // receiver or deps.dev expansion
	Doc       *processor.Document          // raw GUAC document
	Preds     []assembler.IngestPredicates // what the parser made of it
	Records   varve.Stream                 // what assemble made for this document
	ValidFrom time.Time                    // the document's resolved valid time
	Fallback  bool                         // true when ValidFrom fell back to ingest time
	Now       time.Time                    // the run's ingest time
}

// DecorateError names the document a decorator rejected. The document is
// skipped and counted; the run continues.
type DecorateError struct {
	Source string
	Digest string
	Err    error
}

func (e DecorateError) Error() string {
	return fmt.Sprintf("decorate %s (sha256:%s): %v", e.Source, e.Digest, e.Err)
}

func (e DecorateError) Unwrap() error { return e.Err }
