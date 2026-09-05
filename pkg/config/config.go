// Package config is the validated pipeline definition both front-ends build:
// the YAML file Load reads, and the flag set the cmd layer assembles.
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

// defaultMaxDocs is the per-run expansion budget when a present expand stanza
// names none. reservedGraphPrefix marks the graph names varve keeps for itself.
const (
	defaultMaxDocs      = 500
	reservedGraphPrefix = "__"
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

// Hosted is the per-install jurisdiction map ParsePolicy takes. It is the one
// place that says which source this block configures.
func (v VulnerableCodeProcessor) Hosted() map[enrich.Source]enrich.Jurisdiction {
	return map[enrich.Source]enrich.Jurisdiction{enrich.SourceVulnerableCode: v.Jurisdiction}
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
	TrustedWriters []string // wire: sink.varve.trusted_writers (HTTP origins)
	Addr           string
	TokenEnv       string
	Graph          string // wire: sink.varve.graph
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
	TrustedWriters []string `yaml:"trusted_writers"`
	Addr           string   `yaml:"addr"`
	TokenEnv       string   `yaml:"token_env"`
	Graph          string   `yaml:"graph"`
}

// Load parses and validates a pipeline.yaml. Each stanza is validated by its
// own function, so a new stanza adds a function rather than a branch here.
func Load(r io.Reader) (Config, error) {
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)

	var wire wireConfig
	if err := dec.Decode(&wire); err != nil {
		return Config{}, fmt.Errorf("config: decode: %w", err)
	}

	var cfg Config
	var err error
	if cfg.Receivers, err = receiversFrom(wire.Receivers); err != nil {
		return Config{}, err
	}
	if cfg.Processors.ValidTime, err = validTimeFrom(wire.Processors.ValidTime); err != nil {
		return Config{}, err
	}
	if cfg.Processors.Enrich, err = enrichFrom(wire.Processors.Enrich); err != nil {
		return Config{}, err
	}
	if cfg.Processors.Expand, err = expandFrom(wire.Processors.Expand); err != nil {
		return Config{}, err
	}
	if cfg.Sink, err = sinkFrom(wire.Sink); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// parsePoll reads one receiver's poll interval. An absent value is one pass,
// not an error; a non-positive one is a mistake worth naming. field is the
// dotted config path, so the error says which stanza was wrong.
func parsePoll(field, raw string) (time.Duration, error) {
	if raw == "" {
		return 0, nil
	}
	poll, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("config: %s: %w", field, err)
	}
	if poll <= 0 {
		return 0, fmt.Errorf("config: %s must be > 0", field)
	}
	return poll, nil
}

// receiversFrom validates every receiver stanza present. At least one must be.
func receiversFrom(w wireReceivers) (Receivers, error) {
	var out Receivers
	var err error
	if w.Files != nil {
		if out.Files, err = filesFrom(*w.Files); err != nil {
			return Receivers{}, err
		}
	}
	if w.OCI != nil {
		if out.OCI, err = ociFrom(*w.OCI); err != nil {
			return Receivers{}, err
		}
	}
	if w.S3 != nil {
		if out.S3, err = s3From(*w.S3); err != nil {
			return Receivers{}, err
		}
	}
	if w.GCS != nil {
		if out.GCS, err = gcsFrom(*w.GCS); err != nil {
			return Receivers{}, err
		}
	}
	if out.Files == nil && out.OCI == nil && out.S3 == nil && out.GCS == nil {
		return Receivers{}, fmt.Errorf("config: at least one receiver is required")
	}
	return out, nil
}

func filesFrom(w wireFilesReceiver) (*FilesReceiver, error) {
	if w.Path == "" {
		return nil, fmt.Errorf("config: receivers.files.path is required")
	}
	poll, err := parsePoll("receivers.files.poll", w.Poll)
	if err != nil {
		return nil, err
	}
	return &FilesReceiver{Path: w.Path, Poll: poll}, nil
}

func ociFrom(w wireOCIReceiver) (*OCIReceiver, error) {
	if len(w.Refs) == 0 {
		return nil, fmt.Errorf("config: receivers.oci.refs is required")
	}
	poll, err := parsePoll("receivers.oci.poll", w.Poll)
	if err != nil {
		return nil, err
	}
	return &OCIReceiver{Refs: w.Refs, Registry: w.Registry, Insecure: w.Insecure, Poll: poll}, nil
}

func s3From(w wireS3Receiver) (*S3Receiver, error) {
	if w.Bucket == "" {
		return nil, fmt.Errorf("config: receivers.s3.bucket is required")
	}
	poll, err := parsePoll("receivers.s3.poll", w.Poll)
	if err != nil {
		return nil, err
	}
	if poll > 0 && w.Queues == "" {
		return nil, fmt.Errorf("config: receivers.s3.queues is required when poll is set")
	}
	return &S3Receiver{
		URL:    w.URL,
		Bucket: w.Bucket,
		Path:   w.Path,
		Region: w.Region,
		Queues: w.Queues,
		Poll:   poll,
	}, nil
}

func gcsFrom(w wireGCSReceiver) (*GCSReceiver, error) {
	if w.Bucket == "" {
		return nil, fmt.Errorf("config: receivers.gcs.bucket is required")
	}
	poll, err := parsePoll("receivers.gcs.poll", w.Poll)
	if err != nil {
		return nil, err
	}
	return &GCSReceiver{Bucket: w.Bucket, Poll: poll}, nil
}

// validTimeFrom starts from validtime.Default() and overrides what the stanza
// names. An absent stanza is the default guard.
func validTimeFrom(w *wireValidTime) (ValidTimeProcessor, error) {
	def := validtime.Default()
	vt := ValidTimeProcessor{Floor: def.Floor, FutureSkew: def.Skew}
	if w == nil {
		return vt, nil
	}
	if w.Floor != "" {
		floor, err := time.Parse(time.RFC3339, w.Floor)
		if err != nil {
			return ValidTimeProcessor{}, fmt.Errorf("config: processors.valid_time.floor: %w", err)
		}
		vt.Floor = floor.UTC()
	}
	if w.FutureSkew != "" {
		skew, err := time.ParseDuration(w.FutureSkew)
		if err != nil {
			return ValidTimeProcessor{}, fmt.Errorf("config: processors.valid_time.future_skew: %w", err)
		}
		if skew < 0 {
			return ValidTimeProcessor{}, fmt.Errorf("config: processors.valid_time.future_skew must be >= 0")
		}
		vt.FutureSkew = skew
	}
	return vt, nil
}

// enrichFrom starts from the default endpoints and overrides what the stanza
// names. An absent stanza is the zero policy: nothing enriches.
func enrichFrom(w *wireEnrich) (EnrichProcessor, error) {
	out := EnrichProcessor{
		EUVDURL:        euvd.DefaultURL,
		VulnerableCode: VulnerableCodeProcessor{URL: vulnerablecode.DefaultURL, Jurisdiction: enrich.US},
	}
	if w == nil {
		return out, nil
	}
	if vc := w.VulnerableCode; vc != nil {
		if vc.URL != "" {
			out.VulnerableCode.URL = vc.URL
		}
		if vc.Jurisdiction != "" {
			j, err := enrich.ParseJurisdiction(vc.Jurisdiction)
			if err != nil {
				return EnrichProcessor{}, fmt.Errorf("config: processors.enrich.vulnerablecode.jurisdiction: %w", err)
			}
			out.VulnerableCode.Jurisdiction = j
		}
	}
	policy, err := enrich.ParsePolicy(w.Sources, w.EUOnly, out.VulnerableCode.Hosted())
	if err != nil {
		return EnrichProcessor{}, fmt.Errorf("config: processors.enrich.sources: %w", err)
	}
	out.Policy = policy
	if w.EUVD != nil && w.EUVD.URL != "" {
		out.EUVDURL = w.EUVD.URL
	}
	return out, nil
}

// expandFrom reads the expansion budget. An absent stanza is no expansion; an
// absent max_docs inside a present stanza is defaultMaxDocs.
func expandFrom(w *wireExpand) (ExpandProcessor, error) {
	if w == nil {
		return ExpandProcessor{}, nil
	}
	out := ExpandProcessor{DepsDev: w.DepsDev, MaxDocs: defaultMaxDocs}
	switch {
	case w.MaxDocs == nil:
	case *w.MaxDocs <= 0:
		return ExpandProcessor{}, fmt.Errorf("config: processors.expand.max_docs must be > 0")
	default:
		out.MaxDocs = *w.MaxDocs
	}
	return out, nil
}

// sinkFrom validates the one required stanza: there is nowhere else to write.
func sinkFrom(w wireSink) (Sink, error) {
	if w.Varve == nil {
		return Sink{}, fmt.Errorf("config: sink.varve is required")
	}
	if w.Varve.Addr == "" {
		return Sink{}, fmt.Errorf("config: sink.varve.addr is required")
	}
	if w.Varve.TokenEnv == "" {
		return Sink{}, fmt.Errorf("config: sink.varve.token_env is required")
	}
	if strings.HasPrefix(w.Varve.Graph, reservedGraphPrefix) {
		return Sink{}, fmt.Errorf("config: sink.varve.graph %q: names starting with %q are reserved",
			w.Varve.Graph, reservedGraphPrefix)
	}
	return Sink{Varve: VarveSink{TrustedWriters: w.Varve.TrustedWriters, Addr: w.Varve.Addr, TokenEnv: w.Varve.TokenEnv, Graph: w.Varve.Graph}}, nil
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
