package guacseam

import (
	"context"
	"fmt"
	"time"

	"cloud.google.com/go/storage"
	"github.com/guacsec/guac/pkg/handler/collector"
	"github.com/guacsec/guac/pkg/handler/collector/gcs"
)

// GCSReceiver collects SBOMs from a GCS bucket. The storage client resolves GCP
// Application Default Credentials at construction (a real I/O boundary).
type GCSReceiver struct {
	Bucket   string
	Poll     bool
	Interval time.Duration
}

// buildGCS builds GUAC's GCS collector for the receiver.
func buildGCS(ctx context.Context, r GCSReceiver) (collector.Collector, error) {
	cl, err := storage.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("building gcs storage client: %w", err)
	}
	opts := []gcs.Opt{gcs.WithBucket(r.Bucket), gcs.WithClient(cl)}
	if r.Poll {
		opts = append(opts, gcs.WithPolling(r.Interval))
	}
	return gcs.NewGCSCollector(opts...)
}
