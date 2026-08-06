package guacseam

import (
	"testing"

	"github.com/guacsec/guac/pkg/handler/collector/s3"
)

func TestBuildS3Type(t *testing.T) {
	c, err := buildS3(S3Receiver{Bucket: "b", Region: "us-east-1"})
	if err != nil {
		t.Fatalf("buildS3 returned error: %v", err)
	}
	if c == nil {
		t.Fatal("buildS3 returned nil collector")
	}
	if c.Type() != s3.S3CollectorType {
		t.Errorf("Type() = %q, want %q", c.Type(), s3.S3CollectorType)
	}
}
