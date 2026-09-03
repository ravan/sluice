package config

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ravan/sluice/pkg/enrich"
	"github.com/ravan/sluice/pkg/enrich/euvd"
	"github.com/ravan/sluice/pkg/enrich/vulnerablecode"
	"github.com/ravan/sluice/pkg/validtime"
)

func TestLoadValid(t *testing.T) {
	const src = `receivers:
  files: {path: ./sboms, poll: 30s}
processors:
  valid_time: {floor: "2001-02-03T04:05:06Z", future_skew: 2m}
sink:
  varve: {addr: "http://localhost:8080", token_env: VARVE_TOKEN}
`
	cfg, err := Load(strings.NewReader(src))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Receivers.Files == nil {
		t.Fatalf("Receivers.Files = nil, want non-nil")
	}
	if cfg.Receivers.Files.Path != "./sboms" {
		t.Errorf("Path = %q, want ./sboms", cfg.Receivers.Files.Path)
	}
	if cfg.Receivers.Files.Poll != 30*time.Second {
		t.Errorf("Poll = %v, want 30s", cfg.Receivers.Files.Poll)
	}
	if !cfg.Processors.ValidTime.Floor.Equal(time.Date(2001, 2, 3, 4, 5, 6, 0, time.UTC)) {
		t.Errorf("Floor = %v, want 2001-02-03T04:05:06Z", cfg.Processors.ValidTime.Floor)
	}
	if cfg.Processors.ValidTime.FutureSkew != 2*time.Minute {
		t.Errorf("FutureSkew = %v, want 2m", cfg.Processors.ValidTime.FutureSkew)
	}
	if cfg.Sink.Varve.Addr != "http://localhost:8080" {
		t.Errorf("Addr = %q, want http://localhost:8080", cfg.Sink.Varve.Addr)
	}
	if cfg.Sink.Varve.TokenEnv != "VARVE_TOKEN" {
		t.Errorf("TokenEnv = %q, want VARVE_TOKEN", cfg.Sink.Varve.TokenEnv)
	}
}

func TestLoadDefaultsValidTimeAndPoll(t *testing.T) {
	const src = `receivers:
  files: {path: ./x}
sink:
  varve: {addr: "http://localhost:8080", token_env: VARVE_TOKEN}
`
	cfg, err := Load(strings.NewReader(src))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Receivers.Files.Poll != 0 {
		t.Errorf("Poll = %v, want 0", cfg.Receivers.Files.Poll)
	}
	if !cfg.Processors.ValidTime.Floor.Equal(validtime.Default().Floor) {
		t.Errorf("Floor = %v, want %v", cfg.Processors.ValidTime.Floor, validtime.Default().Floor)
	}
	if cfg.Processors.ValidTime.FutureSkew != validtime.Default().Skew {
		t.Errorf("FutureSkew = %v, want %v", cfg.Processors.ValidTime.FutureSkew, validtime.Default().Skew)
	}
}

func TestLoadRejects(t *testing.T) {
	const validSink = "sink:\n  varve: {addr: \"http://localhost:8080\", token_env: VARVE_TOKEN}\n"
	const validReceivers = "receivers:\n  files: {path: ./x}\n"

	tests := []struct {
		name string
		src  string
		want string // exact error substring, when set
	}{
		{
			name: "unknown key",
			src:  validReceivers + "processors:\n  bogus: {x: 1}\n" + validSink,
		},
		{
			name: "no receivers stanza at all",
			src:  "receivers: {}\n" + validSink,
			want: "at least one receiver is required",
		},
		{
			name: "empty path",
			src:  "receivers:\n  files: {path: \"\"}\n" + validSink,
		},
		{
			name: "missing sink",
			src:  validReceivers,
		},
		{
			name: "empty addr",
			src:  validReceivers + "sink:\n  varve: {addr: \"\", token_env: VARVE_TOKEN}\n",
		},
		{
			name: "empty token_env",
			src:  validReceivers + "sink:\n  varve: {addr: \"http://localhost:8080\", token_env: \"\"}\n",
		},
		{
			name: "bad poll",
			src:  "receivers:\n  files: {path: ./x, poll: banana}\n" + validSink,
		},
		{
			name: "zero poll",
			src:  "receivers:\n  files: {path: ./x, poll: 0s}\n" + validSink,
		},
		{
			name: "bad floor",
			src:  validReceivers + "processors:\n  valid_time: {floor: not-a-time}\n" + validSink,
		},
		{
			name: "negative future_skew",
			src:  validReceivers + "processors:\n  valid_time: {future_skew: -1m}\n" + validSink,
		},
		{
			name: "enrich unknown subkey",
			src:  validReceivers + "processors:\n  enrich: {vulnz: true}\n" + validSink,
		},
		{
			name: "expand max_docs zero",
			src:  validReceivers + "processors:\n  expand: {deps_dev: true, max_docs: 0}\n" + validSink,
		},
		{
			name: "expand max_docs negative",
			src:  validReceivers + "processors:\n  expand: {deps_dev: true, max_docs: -5}\n" + validSink,
		},
		{
			name: "oci registry without refs",
			src:  "receivers:\n  oci: {registry: true}\n" + validSink,
			want: "receivers.oci.refs is required",
		},
		{
			name: "s3 without bucket",
			src:  "receivers:\n  s3: {region: x}\n" + validSink,
			want: "receivers.s3.bucket is required",
		},
		{
			name: "s3 poll without queues",
			src:  "receivers:\n  s3: {bucket: b, poll: 10s}\n" + validSink,
			want: "receivers.s3.queues is required when poll is set",
		},
		{
			name: "gcs without bucket",
			src:  "receivers:\n  gcs: {poll: 1m}\n" + validSink,
			want: "receivers.gcs.bucket is required",
		},
		{
			name: "oci bad poll",
			src:  "receivers:\n  oci: {refs: [x], poll: nope}\n" + validSink,
			want: "receivers.oci.poll:",
		},
		{
			name: "oci negative poll",
			src:  "receivers:\n  oci: {refs: [x], poll: -1s}\n" + validSink,
			want: "receivers.oci.poll must be > 0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load(strings.NewReader(tt.src))
			if err == nil {
				t.Fatalf("Load() error = nil, want non-nil")
			}
			if !strings.HasPrefix(err.Error(), "config:") {
				t.Errorf("error = %q, want prefix %q", err.Error(), "config:")
			}
			if tt.want != "" && !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %q, want it to contain %q", err.Error(), tt.want)
			}
		})
	}
}

func TestLoadReceiverKinds(t *testing.T) {
	const validSink = "sink:\n  varve: {addr: \"http://localhost:8080\", token_env: VARVE_TOKEN}\n"

	t.Run("all kinds", func(t *testing.T) {
		src := "receivers:\n" +
			"  oci: {refs: [\"ghcr.io/x/y:tag\"], registry: true, insecure: true, poll: 30s}\n" +
			"  s3: {bucket: b, url: \"http://minio:9000\", region: us-east-1, path: \"sboms/\", queues: q, poll: 15s}\n" +
			"  gcs: {bucket: g, poll: 1m}\n" +
			validSink
		cfg, err := Load(strings.NewReader(src))
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}
		if cfg.Receivers.OCI == nil {
			t.Fatalf("Receivers.OCI = nil, want non-nil")
		}
		if len(cfg.Receivers.OCI.Refs) != 1 || cfg.Receivers.OCI.Refs[0] != "ghcr.io/x/y:tag" {
			t.Errorf("OCI.Refs = %v, want [ghcr.io/x/y:tag]", cfg.Receivers.OCI.Refs)
		}
		if !cfg.Receivers.OCI.Registry {
			t.Errorf("OCI.Registry = false, want true")
		}
		if !cfg.Receivers.OCI.Insecure {
			t.Errorf("OCI.Insecure = false, want true")
		}
		if cfg.Receivers.OCI.Poll != 30*time.Second {
			t.Errorf("OCI.Poll = %v, want 30s", cfg.Receivers.OCI.Poll)
		}
		if cfg.Receivers.S3 == nil {
			t.Fatalf("Receivers.S3 = nil, want non-nil")
		}
		if cfg.Receivers.S3.Bucket != "b" || cfg.Receivers.S3.URL != "http://minio:9000" ||
			cfg.Receivers.S3.Region != "us-east-1" || cfg.Receivers.S3.Path != "sboms/" ||
			cfg.Receivers.S3.Queues != "q" {
			t.Errorf("S3 = %+v, want bucket/url/region/path/queues set", cfg.Receivers.S3)
		}
		if cfg.Receivers.S3.Poll != 15*time.Second {
			t.Errorf("S3.Poll = %v, want 15s", cfg.Receivers.S3.Poll)
		}
		if cfg.Receivers.GCS == nil {
			t.Fatalf("Receivers.GCS = nil, want non-nil")
		}
		if cfg.Receivers.GCS.Bucket != "g" {
			t.Errorf("GCS.Bucket = %q, want g", cfg.Receivers.GCS.Bucket)
		}
		if cfg.Receivers.GCS.Poll != time.Minute {
			t.Errorf("GCS.Poll = %v, want 1m", cfg.Receivers.GCS.Poll)
		}
	})

	t.Run("oci only, no files", func(t *testing.T) {
		src := "receivers:\n  oci: {refs: [\"ghcr.io/x/y:tag\"]}\n" + validSink
		cfg, err := Load(strings.NewReader(src))
		if err != nil {
			t.Fatalf("Load() error = %v (files should no longer be mandatory)", err)
		}
		if cfg.Receivers.Files != nil {
			t.Errorf("Receivers.Files = %+v, want nil", cfg.Receivers.Files)
		}
		if cfg.Receivers.OCI == nil {
			t.Errorf("Receivers.OCI = nil, want non-nil")
		}
	})
}

func TestLoadRejectsUnknownKeyMentionsField(t *testing.T) {
	const src = "receivers:\n  files: {path: ./x}\n" +
		"processors:\n  bogus: {x: 1}\n" +
		"sink:\n  varve: {addr: \"http://localhost:8080\", token_env: VARVE_TOKEN}\n"
	_, err := Load(strings.NewReader(src))
	if err == nil {
		t.Fatalf("Load() error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "bogus") {
		t.Errorf("error = %q, want it to mention %q", err.Error(), "bogus")
	}
}

func TestLoadEnrichAndExpand(t *testing.T) {
	const src = `receivers:
  files: {path: ./x}
processors:
  enrich: {sources: [euvd, osv], eu_only: true}
  expand: {deps_dev: true, max_docs: 25}
sink:
  varve: {addr: "http://localhost:8080", token_env: VARVE_TOKEN}
`
	cfg, err := Load(strings.NewReader(src))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	wantSources := []enrich.Source{enrich.SourceEUVD, enrich.SourceOSV}
	if !slices.Equal(cfg.Processors.Enrich.Policy.Sources, wantSources) {
		t.Errorf("Enrich.Policy.Sources = %v, want %v", cfg.Processors.Enrich.Policy.Sources, wantSources)
	}
	if !cfg.Processors.Enrich.Policy.EUOnly {
		t.Errorf("Enrich.Policy.EUOnly = false, want true")
	}
	if cfg.Processors.Enrich.EUVDURL != euvd.DefaultURL {
		t.Errorf("Enrich.EUVDURL = %q, want %q", cfg.Processors.Enrich.EUVDURL, euvd.DefaultURL)
	}
	if !cfg.Processors.Expand.DepsDev {
		t.Errorf("Expand.DepsDev = false, want true")
	}
	if cfg.Processors.Expand.MaxDocs != 25 {
		t.Errorf("Expand.MaxDocs = %d, want 25", cfg.Processors.Expand.MaxDocs)
	}
}

func TestLoadEnrichEUVDURL(t *testing.T) {
	const src = `receivers:
  files: {path: ./x}
processors:
  enrich: {sources: [euvd], euvd: {url: "http://stub/api"}}
sink:
  varve: {addr: "http://localhost:8080", token_env: VARVE_TOKEN}
`
	cfg, err := Load(strings.NewReader(src))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Processors.Enrich.EUVDURL != "http://stub/api" {
		t.Errorf("Enrich.EUVDURL = %q, want %q", cfg.Processors.Enrich.EUVDURL, "http://stub/api")
	}
}

func TestLoadEnrichRejectsUnknownSource(t *testing.T) {
	const src = `receivers:
  files: {path: ./x}
processors:
  enrich: {sources: [nvd]}
sink:
  varve: {addr: "http://localhost:8080", token_env: VARVE_TOKEN}
`
	_, err := Load(strings.NewReader(src))
	if err == nil {
		t.Fatal("Load() error = nil, want an error")
	}
	if !strings.Contains(err.Error(), "processors.enrich.sources") {
		t.Errorf("error = %q, want it to contain %q", err.Error(), "processors.enrich.sources")
	}
}

func TestLoadEnrichRejectsTheRetiredScanBooleans(t *testing.T) {
	const src = `receivers:
  files: {path: ./x}
processors:
  enrich: {vulns: true}
sink:
  varve: {addr: "http://localhost:8080", token_env: VARVE_TOKEN}
`
	_, err := Load(strings.NewReader(src))
	if err == nil {
		t.Fatal("Load() error = nil, want the unknown-key error")
	}
	if !strings.Contains(err.Error(), "vulns") {
		t.Errorf("error = %q, want it to contain %q", err.Error(), "vulns")
	}
}

func TestLoadExpandDefaultsMaxDocs(t *testing.T) {
	const src = `receivers:
  files: {path: ./x}
processors:
  expand: {deps_dev: true}
sink:
  varve: {addr: "http://localhost:8080", token_env: VARVE_TOKEN}
`
	cfg, err := Load(strings.NewReader(src))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !cfg.Processors.Expand.DepsDev {
		t.Errorf("Expand.DepsDev = false, want true")
	}
	if cfg.Processors.Expand.MaxDocs != 500 {
		t.Errorf("Expand.MaxDocs = %d, want 500", cfg.Processors.Expand.MaxDocs)
	}
}

func TestLoadDefaultsEnrichExpandAbsent(t *testing.T) {
	const src = `receivers:
  files: {path: ./x}
sink:
  varve: {addr: "http://localhost:8080", token_env: VARVE_TOKEN}
`
	cfg, err := Load(strings.NewReader(src))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(cfg.Processors.Enrich.Policy.Sources) != 0 || cfg.Processors.Enrich.Policy.EUOnly {
		t.Errorf("Enrich.Policy = %+v, want the zero policy", cfg.Processors.Enrich.Policy)
	}
	if cfg.Processors.Enrich.EUVDURL != euvd.DefaultURL {
		t.Errorf("Enrich.EUVDURL = %q, want %q", cfg.Processors.Enrich.EUVDURL, euvd.DefaultURL)
	}
	if cfg.Processors.Expand.DepsDev {
		t.Errorf("Expand.DepsDev = true, want false")
	}
}

func TestLoadExampleConfig(t *testing.T) {
	cfg, err := LoadFile("../../deploy/pipeline.yaml")
	if err != nil {
		t.Fatalf("LoadFile() error = %v", err)
	}
	if cfg.Sink.Varve.Addr == "" {
		t.Errorf("Sink.Varve.Addr = empty, want non-empty")
	}
}

func TestLoadSinkGraph(t *testing.T) {
	const src = `receivers:
  files: {path: ./x}
sink:
  varve: {addr: "http://localhost:8080", token_env: VARVE_TOKEN, graph: org_a}
`
	cfg, err := Load(strings.NewReader(src))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Sink.Varve.Graph != "org_a" {
		t.Errorf("Graph = %q, want org_a", cfg.Sink.Varve.Graph)
	}

	const noGraph = `receivers:
  files: {path: ./x}
sink:
  varve: {addr: "http://localhost:8080", token_env: VARVE_TOKEN}
`
	cfg, err = Load(strings.NewReader(noGraph))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Sink.Varve.Graph != "" {
		t.Errorf("Graph = %q, want empty (Varve default graph)", cfg.Sink.Varve.Graph)
	}

	const reserved = `receivers:
  files: {path: ./x}
sink:
  varve: {addr: "http://localhost:8080", token_env: VARVE_TOKEN, graph: __meta}
`
	if _, err := Load(strings.NewReader(reserved)); err == nil || !strings.Contains(err.Error(), "sink.varve.graph") {
		t.Errorf("Load(reserved graph) error = %v, want a sink.varve.graph error", err)
	}

	const unknown = `receivers:
  files: {path: ./x}
sink:
  varve: {addr: "http://localhost:8080", token_env: VARVE_TOKEN, graf: org_a}
`
	if _, err := Load(strings.NewReader(unknown)); err == nil {
		t.Errorf("Load(unknown sink key) = nil error, want a KnownFields failure")
	}
}

func TestLoadEnrichVulnerableCode(t *testing.T) {
	cases := []struct {
		name     string
		block    string
		wantURL  string
		wantJur  enrich.Jurisdiction
		wantErr  bool
		contains string
	}{
		{
			name:    "absent block",
			block:   `{sources: [vulnerablecode]}`,
			wantURL: vulnerablecode.DefaultURL,
			wantJur: enrich.US,
		},
		{
			name:    "url and jurisdiction",
			block:   `{sources: [vulnerablecode], vulnerablecode: {url: "http://stub", jurisdiction: eu}}`,
			wantURL: "http://stub",
			wantJur: enrich.EU,
		},
		{
			name:     "unknown jurisdiction",
			block:    `{sources: [vulnerablecode], vulnerablecode: {jurisdiction: moon}}`,
			wantErr:  true,
			contains: "processors.enrich.vulnerablecode.jurisdiction",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := "receivers:\n  files: {path: ./x}\nprocessors:\n  enrich: " + tc.block +
				"\nsink:\n  varve: {addr: \"http://localhost:8080\", token_env: VARVE_TOKEN}\n"
			cfg, err := Load(strings.NewReader(src))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("Load() error = nil, want non-nil")
				}
				if !strings.Contains(err.Error(), tc.contains) {
					t.Errorf("error = %q, want it to name %q", err.Error(), tc.contains)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			got := cfg.Processors.Enrich.VulnerableCode
			if got.URL != tc.wantURL {
				t.Errorf("VulnerableCode.URL = %q, want %q", got.URL, tc.wantURL)
			}
			if got.Jurisdiction != tc.wantJur {
				t.Errorf("VulnerableCode.Jurisdiction = %q, want %q", got.Jurisdiction, tc.wantJur)
			}
			if j := cfg.Processors.Enrich.Policy.JurisdictionOf(enrich.SourceVulnerableCode); j != tc.wantJur {
				t.Errorf("Policy.JurisdictionOf(vulnerablecode) = %q, want %q", j, tc.wantJur)
			}
		})
	}
}
