package main

import (
	"strings"
	"testing"
	"time"
)

func TestOCIReceivers(t *testing.T) {
	recv := ociReceivers([]string{"reg/a:1"}, true, true)
	if recv.OCI == nil {
		t.Fatalf("OCI = nil, want non-nil")
	}
	if len(recv.OCI.Refs) != 1 || recv.OCI.Refs[0] != "reg/a:1" {
		t.Errorf("OCI.Refs = %v, want [reg/a:1]", recv.OCI.Refs)
	}
	if !recv.OCI.Registry || !recv.OCI.Insecure {
		t.Errorf("OCI Registry/Insecure = %v/%v, want true/true", recv.OCI.Registry, recv.OCI.Insecure)
	}
	if recv.OCI.Poll != 0 {
		t.Errorf("OCI.Poll = %v, want 0", recv.OCI.Poll)
	}
	if recv.Files != nil || recv.S3 != nil || recv.GCS != nil {
		t.Errorf("other receivers = %+v/%+v/%+v, want all nil", recv.Files, recv.S3, recv.GCS)
	}
}

func TestS3Receivers(t *testing.T) {
	recv := s3Receivers("b", "http://minio:9000", "us-east-1", "sboms/")
	if recv.S3 == nil {
		t.Fatalf("S3 = nil, want non-nil")
	}
	if recv.S3.Bucket != "b" || recv.S3.URL != "http://minio:9000" ||
		recv.S3.Region != "us-east-1" || recv.S3.Path != "sboms/" {
		t.Errorf("S3 = %+v, want bucket/url/region/path set", recv.S3)
	}
	if recv.S3.Poll != 0 {
		t.Errorf("S3.Poll = %v, want 0", recv.S3.Poll)
	}
	if recv.Files != nil || recv.OCI != nil || recv.GCS != nil {
		t.Errorf("other receivers = %+v/%+v/%+v, want all nil", recv.Files, recv.OCI, recv.GCS)
	}
}

func TestGCSReceivers(t *testing.T) {
	recv := gcsReceivers("g")
	if recv.GCS == nil {
		t.Fatalf("GCS = nil, want non-nil")
	}
	if recv.GCS.Bucket != "g" {
		t.Errorf("GCS.Bucket = %q, want g", recv.GCS.Bucket)
	}
	if recv.GCS.Poll != 0 {
		t.Errorf("GCS.Poll = %v, want 0", recv.GCS.Poll)
	}
	if recv.Files != nil || recv.OCI != nil || recv.S3 != nil {
		t.Errorf("other receivers = %+v/%+v/%+v, want all nil", recv.Files, recv.OCI, recv.S3)
	}
}

func TestBuildIngestConfig(t *testing.T) {
	cfg, err := buildIngestConfig(filesReceivers("d"), ingestFlags{
		varveAddr:     "http://v",
		validFloor:    "2000-01-01T00:00:00Z",
		validSkew:     5 * time.Minute,
		enrichVulns:   true,
		expandDepsDev: true,
		expandMaxDocs: 25,
	})
	if err != nil {
		t.Fatalf("buildIngestConfig returned error: %v", err)
	}
	if cfg.Receivers.Files == nil || cfg.Receivers.Files.Path != "d" {
		t.Errorf("Receivers.Files = %+v, want Path d", cfg.Receivers.Files)
	}
	if !cfg.Processors.Enrich.Vulns {
		t.Errorf("Enrich.Vulns = false, want true")
	}
	if !cfg.Processors.Expand.DepsDev || cfg.Processors.Expand.MaxDocs != 25 {
		t.Errorf("Expand = %+v, want DepsDev true MaxDocs 25", cfg.Processors.Expand)
	}
	if !cfg.Processors.ValidTime.Floor.Equal(time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("ValidTime.Floor = %v, want 2000-01-01T00:00:00Z", cfg.Processors.ValidTime.Floor)
	}
	if cfg.Processors.ValidTime.FutureSkew != 5*time.Minute {
		t.Errorf("ValidTime.FutureSkew = %v, want 5m", cfg.Processors.ValidTime.FutureSkew)
	}
	if cfg.Sink.Varve.Addr != "http://v" || cfg.Sink.Varve.TokenEnv != "VARVE_TOKEN" {
		t.Errorf("Sink.Varve = %+v, want {http://v VARVE_TOKEN}", cfg.Sink.Varve)
	}

	if _, err := buildIngestConfig(filesReceivers("d"), ingestFlags{validFloor: "nope"}); err == nil {
		t.Fatal("expected an error for a bad floor, got nil")
	} else if !strings.Contains(err.Error(), "valid-floor") {
		t.Errorf("error = %q, want it to contain %q", err.Error(), "valid-floor")
	}
}
