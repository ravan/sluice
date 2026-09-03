package config

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/ravan/sluice/pkg/enrich"
	"github.com/ravan/sluice/pkg/enrich/euvd"
	"github.com/ravan/sluice/pkg/enrich/vulnerablecode"
	"github.com/ravan/sluice/pkg/validtime"
	"gopkg.in/yaml.v3"
)

// Config is the validated pipeline definition both front-ends build (§6 inv. 8).
type Config struct {
	Receivers  Receivers
	Processors Processors
	Sink       Sink
}

// Receivers: the configured source set. Each kind is nil when its stanza is
// absent; Load requires at least one present.
type Receivers struct {
	Files *FilesReceiver
	OCI   *OCIReceiver
	S3    *S3Receiver
	GCS   *GCSReceiver
}

// FilesReceiver watches a directory. Poll == 0 ⇒ one pass (one-shot); Poll > 0 ⇒
// poll at that interval until the run's context is cancelled.
type FilesReceiver struct {
	Path string
	Poll time.Duration
}

// OCIReceiver collects SBOMs attached to OCI artifacts. Poll == 0 ⇒ one-shot.
type OCIReceiver struct {
	Refs     []string
	Registry bool
	Insecure bool
	Poll     time.Duration // 0 ⇒ one-shot
}

// S3Receiver collects SBOMs from an S3 bucket. Poll == 0 ⇒ one-shot (bucket-list mode).
type S3Receiver struct {
	URL    string
	Bucket string
	Path   string
	Region string
	Queues string
	Poll   time.Duration // 0 ⇒ one-shot (bucket-list mode)
}

// GCSReceiver collects SBOMs from a GCS bucket. Poll == 0 ⇒ one-shot.
type GCSReceiver struct {
	Bucket string
	Poll   time.Duration // 0 ⇒ one-shot
}

// Processors: the valid-time guard plus the enrich/expand controls.
type Processors struct {
	ValidTime ValidTimeProcessor
	Enrich    EnrichProcessor
	Expand    ExpandProcessor
}

// EnrichProcessor is the org's enrichment policy plus the endpoints the
// enrichers this build carries need. Absent ⇒ the zero policy (nothing
// enriches) and the default endpoints.
type EnrichProcessor struct {
	Policy         enrich.Policy
	EUVDURL        string
	VulnerableCode VulnerableCodeProcessor
}

// VulnerableCodeProcessor is the VulnerableCode endpoint and the jurisdiction
// of the host it names. An absent block means DefaultURL and US.
type VulnerableCodeProcessor struct {
	URL          string
	Jurisdiction enrich.Jurisdiction
}

// ExpandProcessor: in-process deps.dev expansion. DepsDev false ⇒ no expansion.
// MaxDocs is the per-run budget, meaningful only when DepsDev is true.
type ExpandProcessor struct {
	DepsDev bool
	MaxDocs int
}

// ValidTimeProcessor mirrors validtime.Guard's inputs; absent ⇒ validtime.Default().
type ValidTimeProcessor struct {
	Floor      time.Time
	FutureSkew time.Duration
}

// Sink: the one varve writer. This is the declaration the cmd layer reads to build
// the *varve.Client; pipeline.Run never reads it.
type Sink struct {
	Varve VarveSink
}

// VarveSink names the writer address, the ENV VAR (not the token) holding the
// bearer token — so a secret never lands in the YAML or in argv — and the
// named graph to ingest into ("" ⇒ the Varve default graph).
type VarveSink struct {
	Addr     string
	TokenEnv string
	Graph    string // wire: sink.varve.graph
}

type wireConfig struct {
	Receivers  wireReceivers  `yaml:"receivers"`
	Processors wireProcessors `yaml:"processors"`
	Sink       wireSink       `yaml:"sink"`
}

type wireReceivers struct {
	Files *wireFilesReceiver `yaml:"files"`
	OCI   *wireOCIReceiver   `yaml:"oci"`
	S3    *wireS3Receiver    `yaml:"s3"`
	GCS   *wireGCSReceiver   `yaml:"gcs"`
}

type wireFilesReceiver struct {
	Path string `yaml:"path"`
	Poll string `yaml:"poll"`
}

type wireOCIReceiver struct {
	Refs     []string `yaml:"refs"`
	Registry bool     `yaml:"registry"`
	Insecure bool     `yaml:"insecure"`
	Poll     string   `yaml:"poll"`
}

type wireS3Receiver struct {
	URL    string `yaml:"url"`
	Bucket string `yaml:"bucket"`
	Path   string `yaml:"path"`
	Region string `yaml:"region"`
	Queues string `yaml:"queues"`
	Poll   string `yaml:"poll"`
}

type wireGCSReceiver struct {
	Bucket string `yaml:"bucket"`
	Poll   string `yaml:"poll"`
}

type wireProcessors struct {
	ValidTime *wireValidTime `yaml:"valid_time"`
	Enrich    *wireEnrich    `yaml:"enrich"`
	Expand    *wireExpand    `yaml:"expand"`
}

type wireValidTime struct {
	Floor      string `yaml:"floor"`
	FutureSkew string `yaml:"future_skew"`
}

type wireEnrich struct {
	Sources        []string            `yaml:"sources"`
	EUOnly         bool                `yaml:"eu_only"`
	EUVD           *wireEUVD           `yaml:"euvd"`
	VulnerableCode *wireVulnerableCode `yaml:"vulnerablecode"`
}

type wireEUVD struct {
	URL string `yaml:"url"`
}

type wireVulnerableCode struct {
	URL          string `yaml:"url"`
	Jurisdiction string `yaml:"jurisdiction"`
}

type wireExpand struct {
	DepsDev bool `yaml:"deps_dev"`
	MaxDocs *int `yaml:"max_docs"`
}

type wireSink struct {
	Varve *wireVarveSink `yaml:"varve"`
}

type wireVarveSink struct {
	Addr     string `yaml:"addr"`
	TokenEnv string `yaml:"token_env"`
	Graph    string `yaml:"graph"`
}

// Load parses and validates a pipeline.yaml.
func Load(r io.Reader) (Config, error) {
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)

	var wire wireConfig
	if err := dec.Decode(&wire); err != nil {
		return Config{}, fmt.Errorf("config: decode: %w", err)
	}

	var cfg Config

	if wire.Receivers.Files != nil {
		if wire.Receivers.Files.Path == "" {
			return Config{}, fmt.Errorf("config: receivers.files.path is required")
		}
		files := FilesReceiver{Path: wire.Receivers.Files.Path}
		if wire.Receivers.Files.Poll != "" {
			poll, err := time.ParseDuration(wire.Receivers.Files.Poll)
			if err != nil {
				return Config{}, fmt.Errorf("config: receivers.files.poll: %w", err)
			}
			if poll <= 0 {
				return Config{}, fmt.Errorf("config: receivers.files.poll must be > 0")
			}
			files.Poll = poll
		}
		cfg.Receivers.Files = &files
	}

	if wire.Receivers.OCI != nil {
		if len(wire.Receivers.OCI.Refs) == 0 {
			return Config{}, fmt.Errorf("config: receivers.oci.refs is required")
		}
		o := OCIReceiver{Refs: wire.Receivers.OCI.Refs, Registry: wire.Receivers.OCI.Registry, Insecure: wire.Receivers.OCI.Insecure}
		if wire.Receivers.OCI.Poll != "" {
			poll, err := time.ParseDuration(wire.Receivers.OCI.Poll)
			if err != nil {
				return Config{}, fmt.Errorf("config: receivers.oci.poll: %w", err)
			}
			if poll <= 0 {
				return Config{}, fmt.Errorf("config: receivers.oci.poll must be > 0")
			}
			o.Poll = poll
		}
		cfg.Receivers.OCI = &o
	}

	if wire.Receivers.S3 != nil {
		if wire.Receivers.S3.Bucket == "" {
			return Config{}, fmt.Errorf("config: receivers.s3.bucket is required")
		}
		s := S3Receiver{
			URL:    wire.Receivers.S3.URL,
			Bucket: wire.Receivers.S3.Bucket,
			Path:   wire.Receivers.S3.Path,
			Region: wire.Receivers.S3.Region,
			Queues: wire.Receivers.S3.Queues,
		}
		if wire.Receivers.S3.Poll != "" {
			poll, err := time.ParseDuration(wire.Receivers.S3.Poll)
			if err != nil {
				return Config{}, fmt.Errorf("config: receivers.s3.poll: %w", err)
			}
			if poll <= 0 {
				return Config{}, fmt.Errorf("config: receivers.s3.poll must be > 0")
			}
			s.Poll = poll
		}
		if s.Poll > 0 && s.Queues == "" {
			return Config{}, fmt.Errorf("config: receivers.s3.queues is required when poll is set")
		}
		cfg.Receivers.S3 = &s
	}

	if wire.Receivers.GCS != nil {
		if wire.Receivers.GCS.Bucket == "" {
			return Config{}, fmt.Errorf("config: receivers.gcs.bucket is required")
		}
		g := GCSReceiver{Bucket: wire.Receivers.GCS.Bucket}
		if wire.Receivers.GCS.Poll != "" {
			poll, err := time.ParseDuration(wire.Receivers.GCS.Poll)
			if err != nil {
				return Config{}, fmt.Errorf("config: receivers.gcs.poll: %w", err)
			}
			if poll <= 0 {
				return Config{}, fmt.Errorf("config: receivers.gcs.poll must be > 0")
			}
			g.Poll = poll
		}
		cfg.Receivers.GCS = &g
	}

	if cfg.Receivers.Files == nil && cfg.Receivers.OCI == nil && cfg.Receivers.S3 == nil && cfg.Receivers.GCS == nil {
		return Config{}, fmt.Errorf("config: at least one receiver is required")
	}

	def := validtime.Default()
	vt := ValidTimeProcessor{Floor: def.Floor, FutureSkew: def.Skew}
	if wire.Processors.ValidTime != nil {
		if wire.Processors.ValidTime.Floor != "" {
			floor, err := time.Parse(time.RFC3339, wire.Processors.ValidTime.Floor)
			if err != nil {
				return Config{}, fmt.Errorf("config: processors.valid_time.floor: %w", err)
			}
			vt.Floor = floor.UTC()
		}
		if wire.Processors.ValidTime.FutureSkew != "" {
			skew, err := time.ParseDuration(wire.Processors.ValidTime.FutureSkew)
			if err != nil {
				return Config{}, fmt.Errorf("config: processors.valid_time.future_skew: %w", err)
			}
			if skew < 0 {
				return Config{}, fmt.Errorf("config: processors.valid_time.future_skew must be >= 0")
			}
			vt.FutureSkew = skew
		}
	}
	cfg.Processors.ValidTime = vt

	cfg.Processors.Enrich = EnrichProcessor{
		EUVDURL:        euvd.DefaultURL,
		VulnerableCode: VulnerableCodeProcessor{URL: vulnerablecode.DefaultURL, Jurisdiction: enrich.US},
	}
	if e := wire.Processors.Enrich; e != nil {
		if e.VulnerableCode != nil {
			if e.VulnerableCode.URL != "" {
				cfg.Processors.Enrich.VulnerableCode.URL = e.VulnerableCode.URL
			}
			if e.VulnerableCode.Jurisdiction != "" {
				j, jerr := enrich.ParseJurisdiction(e.VulnerableCode.Jurisdiction)
				if jerr != nil {
					return Config{}, fmt.Errorf("config: processors.enrich.vulnerablecode.jurisdiction: %w", jerr)
				}
				cfg.Processors.Enrich.VulnerableCode.Jurisdiction = j
			}
		}
		hosted := map[enrich.Source]enrich.Jurisdiction{
			enrich.SourceVulnerableCode: cfg.Processors.Enrich.VulnerableCode.Jurisdiction,
		}
		policy, perr := enrich.ParsePolicy(e.Sources, e.EUOnly, hosted)
		if perr != nil {
			return Config{}, fmt.Errorf("config: processors.enrich.sources: %w", perr)
		}
		cfg.Processors.Enrich.Policy = policy
		if e.EUVD != nil && e.EUVD.URL != "" {
			cfg.Processors.Enrich.EUVDURL = e.EUVD.URL
		}
	}

	if wire.Processors.Expand != nil {
		expand := ExpandProcessor{DepsDev: wire.Processors.Expand.DepsDev}
		switch {
		case wire.Processors.Expand.MaxDocs == nil:
			expand.MaxDocs = 500
		case *wire.Processors.Expand.MaxDocs <= 0:
			return Config{}, fmt.Errorf("config: processors.expand.max_docs must be > 0")
		default:
			expand.MaxDocs = *wire.Processors.Expand.MaxDocs
		}
		cfg.Processors.Expand = expand
	}

	if wire.Sink.Varve == nil {
		return Config{}, fmt.Errorf("config: sink.varve is required")
	}
	if wire.Sink.Varve.Addr == "" {
		return Config{}, fmt.Errorf("config: sink.varve.addr is required")
	}
	if wire.Sink.Varve.TokenEnv == "" {
		return Config{}, fmt.Errorf("config: sink.varve.token_env is required")
	}
	if strings.HasPrefix(wire.Sink.Varve.Graph, "__") {
		return Config{}, fmt.Errorf("config: sink.varve.graph %q: names starting with \"__\" are reserved", wire.Sink.Varve.Graph)
	}
	cfg.Sink.Varve = VarveSink{Addr: wire.Sink.Varve.Addr, TokenEnv: wire.Sink.Varve.TokenEnv, Graph: wire.Sink.Varve.Graph}

	return cfg, nil
}

// LoadFile opens path then calls Load.
func LoadFile(path string) (cfg Config, err error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("config: open %s: %w", path, err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("config: close %s: %w", path, cerr)
		}
	}()

	return Load(f)
}
