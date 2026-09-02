package guacseam

import (
	"github.com/guacsec/guac/pkg/handler/collector"
	"github.com/guacsec/guac/pkg/handler/collector/s3"
)

// S3Receiver collects SBOMs from an S3 bucket (list mode) or an SQS message
// provider (poll mode). Queues is required when Poll is set.
type S3Receiver struct {
	URL    string // custom endpoint (e.g. MinIO); "" ⇒ AWS SDK defaults
	Bucket string
	Path   string // folder prefix; list mode only
	Region string // "" ⇒ collector default
	Queues string // comma-separated; required when Poll (SQS message provider)
	Poll   bool
}

// buildS3 builds GUAC's S3 collector for the receiver.
func buildS3(r S3Receiver) (collector.Collector, error) {
	cfg := s3.S3CollectorConfig{
		S3Url:    r.URL,
		S3Bucket: r.Bucket,
		S3Path:   r.Path,
		S3Region: r.Region,
		Queues:   r.Queues,
		Poll:     r.Poll,
	}
	return s3.NewS3Collector(cfg), nil
}
