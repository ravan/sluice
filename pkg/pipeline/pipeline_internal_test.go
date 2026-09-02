package pipeline

import (
	"testing"
	"time"

	"github.com/ravan/sluice/pkg/config"
)

func TestSourcesFromConfig(t *testing.T) {
	src := sourcesFromConfig(config.Receivers{
		Files: &config.FilesReceiver{Path: "d", Poll: 30 * time.Second},
		OCI:   &config.OCIReceiver{Refs: []string{"r:1"}, Registry: true, Insecure: true},
		S3:    &config.S3Receiver{Bucket: "b"},
		GCS:   &config.GCSReceiver{Bucket: "g", Poll: time.Minute},
	})

	if src.Files == nil {
		t.Fatalf("Files = nil, want non-nil")
	}
	if !src.Files.Poll || src.Files.Interval != 30*time.Second {
		t.Errorf("Files = %+v, want Poll true / Interval 30s", src.Files)
	}
	if src.OCI == nil {
		t.Fatalf("OCI = nil, want non-nil")
	}
	if len(src.OCI.Refs) != 1 || src.OCI.Refs[0] != "r:1" || !src.OCI.Registry || !src.OCI.Insecure || src.OCI.Poll {
		t.Errorf("OCI = %+v, want Refs [r:1] Registry true Insecure true Poll false", src.OCI)
	}
	if src.S3 == nil {
		t.Fatalf("S3 = nil, want non-nil")
	}
	if src.S3.Bucket != "b" || src.S3.Poll {
		t.Errorf("S3 = %+v, want Bucket b Poll false", src.S3)
	}
	if src.GCS == nil {
		t.Fatalf("GCS = nil, want non-nil")
	}
	if src.GCS.Bucket != "g" || !src.GCS.Poll || src.GCS.Interval != time.Minute {
		t.Errorf("GCS = %+v, want Bucket g Poll true Interval 1m", src.GCS)
	}
}

func TestAnyPolling(t *testing.T) {
	tests := []struct {
		name string
		recv config.Receivers
		want bool
	}{
		{
			name: "files poll",
			recv: config.Receivers{Files: &config.FilesReceiver{Path: "d", Poll: 30 * time.Second}},
			want: true,
		},
		{
			name: "gcs poll",
			recv: config.Receivers{GCS: &config.GCSReceiver{Bucket: "g", Poll: time.Minute}},
			want: true,
		},
		{
			name: "all zero",
			recv: config.Receivers{
				Files: &config.FilesReceiver{Path: "d"},
				OCI:   &config.OCIReceiver{Refs: []string{"r:1"}},
				S3:    &config.S3Receiver{Bucket: "b"},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := anyPolling(tt.recv); got != tt.want {
				t.Errorf("anyPolling(%+v) = %v, want %v", tt.recv, got, tt.want)
			}
		})
	}
}
