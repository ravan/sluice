// Package cosignvuln parses the cosign vulnerability attestation, predicate
// https://cosign.sigstore.dev/attestation/vuln/v1, whose scanner.result is a
// whole Trivy JSON report rather than the flat {id, severity} list of the
// in-toto vulns/v0.1 predicate GUAC already parses. GUAC's guesser files the
// cosign statement as a generic ITE6 document, which has no parser, so
// without this package every such attestation is skipped.
//
// The statement becomes GUAC ingest predicates:
//
//   - CertifyVuln from each finding to the package Trivy names in
//     PkgIdentifier.PURL, and to each subject that names a purl. A subject
//     with no finding gets the noVuln sentinel, the same as a clean scan.
//   - VulnMetadata from every CVSS score a finding carries, one per source.
//   - VulnEqual from a finding's VendorIDs (Trivy's aliases for the same
//     vulnerability).
//   - IsOccurrence from a subject that carries both a purl and a digest.
//
// A subject with neither a purl nor a digest, which is what OBS writes today,
// is ignored: the findings still attach to the affected packages.
package cosignvuln

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/guacsec/guac/pkg/assembler"
	"github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/guacsec/guac/pkg/assembler/helpers"
	"github.com/guacsec/guac/pkg/handler/processor"
	"github.com/guacsec/guac/pkg/handler/processor/process"
	"github.com/guacsec/guac/pkg/ingestor/parser"
	"github.com/guacsec/guac/pkg/ingestor/parser/common"
)

// PredicateType is the in-toto predicateType this package parses.
const PredicateType = "https://cosign.sigstore.dev/attestation/vuln/v1"

// DocumentType is the GUAC document type the processor and parser register
// under. Classify stamps it on a document GUAC would otherwise misfile.
const DocumentType processor.DocumentType = "COSIGN_VULN"

// statementPrefix is shared by every in-toto statement version.
const statementPrefix = "https://in-toto.io/Statement"

func init() {
	// Both return an error only when overwriting a registration; this type is
	// ours alone, and a second registration of the same package is impossible.
	_ = process.RegisterDocumentProcessor(Processor{}, DocumentType)
	_ = parser.RegisterDocumentParser(NewParser, DocumentType)
}

// Classify stamps DocumentType on an untyped document that is a cosign
// vulnerability statement, so GUAC's type guesser never sees it. It reports
// whether it did. A document that already has a type is left alone; the
// zero type counts as untyped, the same as GUAC's explicit unknown.
func Classify(doc *processor.Document) bool {
	if doc == nil || !untyped(doc.Type) || !IsStatement(doc.Blob) {
		return false
	}
	doc.Type = DocumentType
	return true
}

func untyped(t processor.DocumentType) bool {
	return t == "" || t == processor.DocumentUnknown
}

// IsStatement reports whether blob is an in-toto statement with the cosign
// vulnerability predicate type. It reads only the two header fields.
func IsStatement(blob []byte) bool {
	var head struct {
		Type          string `json:"_type"`
		PredicateType string `json:"predicateType"`
	}
	if json.Unmarshal(blob, &head) != nil {
		return false
	}
	return strings.HasPrefix(head.Type, statementPrefix) && head.PredicateType == PredicateType
}

// Processor is the GUAC document processor for DocumentType: it validates
// the statement and unpacks nothing.
type Processor struct{}

// ValidateSchema checks the document type and that the blob decodes.
func (Processor) ValidateSchema(d *processor.Document) error {
	if d.Type != DocumentType {
		return fmt.Errorf("cosignvuln: expected %s document, got %s", DocumentType, d.Type)
	}
	_, err := decode(d.Blob)
	return err
}

// Unpack returns nothing: the statement is the whole document.
func (Processor) Unpack(*processor.Document) ([]*processor.Document, error) {
	return nil, nil
}

// Parser is the GUAC document parser for DocumentType.
type Parser struct {
	preds *assembler.IngestPredicates
	ids   *common.IdentifierStrings
}

// NewParser returns a fresh Parser; the registry calls it per document.
func NewParser() common.DocumentParser { return &Parser{} }

// Parse turns the statement into ingest predicates.
func (p *Parser) Parse(_ context.Context, doc *processor.Document) error {
	st, err := decode(doc.Blob)
	if err != nil {
		return err
	}
	b := newBuild(st)
	if err := b.subjects(st.Subject); err != nil {
		return err
	}
	if err := b.findings(st.Predicate.Scanner.Result.Results); err != nil {
		return err
	}
	b.finish()
	p.preds, p.ids = b.preds, b.ids
	return nil
}

// GetIdentities returns nothing: the statement carries no identities.
func (*Parser) GetIdentities(context.Context) []common.TrustInformation { return nil }

// GetPredicates returns what Parse assembled.
func (p *Parser) GetPredicates(context.Context) *assembler.IngestPredicates { return p.preds }

// GetIdentifiers returns every purl Parse saw: subjects first, then findings.
func (p *Parser) GetIdentifiers(context.Context) (*common.IdentifierStrings, error) {
	return p.ids, nil
}

// statement is the part of the cosign vulnerability statement this package
// reads. Field names follow the wire: cosign's are camelCase, Trivy's are
// CapitalCase.
type statement struct {
	Type          string    `json:"_type"`
	PredicateType string    `json:"predicateType"`
	Subject       []subject `json:"subject"`
	Predicate     struct {
		Scanner struct {
			URI     string `json:"uri"`
			Version string `json:"version"`
			DB      struct {
				URI     string `json:"uri"`
				Version string `json:"version"`
			} `json:"db"`
			Result report `json:"result"`
		} `json:"scanner"`
		Metadata struct {
			ScanStartedOn  string `json:"scanStartedOn"`
			ScanFinishedOn string `json:"scanFinishedOn"`
		} `json:"metadata"`
	} `json:"predicate"`
}

// subject is one in-toto ResourceDescriptor. cosign writes the image
// reference in name; the in-toto v1 form allows a purl in uri as well.
type subject struct {
	Name   string            `json:"name"`
	URI    string            `json:"uri"`
	Digest map[string]string `json:"digest"`
}

// report is the Trivy JSON report inside scanner.result.
type report struct {
	CreatedAt string   `json:"CreatedAt"`
	Results   []result `json:"Results"`
}

// result is one scanned target: the OS package set or one binary.
type result struct {
	Target          string    `json:"Target"`
	Vulnerabilities []finding `json:"Vulnerabilities"`
}

// finding is one Trivy DetectedVulnerability.
type finding struct {
	VulnerabilityID  string   `json:"VulnerabilityID"`
	VendorIDs        []string `json:"VendorIDs"`
	PkgName          string   `json:"PkgName"`
	InstalledVersion string   `json:"InstalledVersion"`
	PkgIdentifier    struct {
		PURL string `json:"PURL"`
	} `json:"PkgIdentifier"`
	CVSS map[string]cvss `json:"CVSS"`
}

// cvss is one source's scores for a finding.
type cvss struct {
	V2Vector  string  `json:"V2Vector"`
	V3Vector  string  `json:"V3Vector"`
	V40Vector string  `json:"V40Vector"`
	V2Score   float64 `json:"V2Score"`
	V3Score   float64 `json:"V3Score"`
	V40Score  float64 `json:"V40Score"`
}

func decode(blob []byte) (*statement, error) {
	var st statement
	if err := json.Unmarshal(blob, &st); err != nil {
		return nil, fmt.Errorf("cosignvuln: decode statement: %w", err)
	}
	if !strings.HasPrefix(st.Type, statementPrefix) {
		return nil, fmt.Errorf("cosignvuln: not an in-toto statement: _type %q", st.Type)
	}
	if st.PredicateType != PredicateType {
		return nil, fmt.Errorf("cosignvuln: unexpected predicateType %q", st.PredicateType)
	}
	return &st, nil
}

// build accumulates predicates for one statement.
type build struct {
	scan        *generated.ScanMetadataInput
	subjectPkgs []*generated.PkgInputSpec
	preds       *assembler.IngestPredicates
	ids         *common.IdentifierStrings
	seen        map[string]bool
}

func newBuild(st *statement) *build {
	sc := st.Predicate.Scanner
	return &build{
		scan: &generated.ScanMetadataInput{
			TimeScanned:    scanTime(st),
			DbUri:          sc.DB.URI,
			DbVersion:      sc.DB.Version,
			ScannerUri:     sc.URI,
			ScannerVersion: sc.Version,
		},
		preds: &assembler.IngestPredicates{},
		ids:   &common.IdentifierStrings{},
		seen:  map[string]bool{},
	}
}

// scanTime is the first of scanFinishedOn, scanStartedOn and the report's
// CreatedAt that parses. Zero when none does; the valid-time guard then
// falls back and counts it.
func scanTime(st *statement) time.Time {
	for _, s := range []string{st.Predicate.Metadata.ScanFinishedOn, st.Predicate.Metadata.ScanStartedOn, st.Predicate.Scanner.Result.CreatedAt} {
		if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

// once reports whether key is new, recording it.
func (b *build) once(key string) bool {
	if b.seen[key] {
		return false
	}
	b.seen[key] = true
	return true
}

// subjects reads each subject's purl and digest. A purl that does not parse
// is an error: a subject is the statement's claim about what was scanned.
func (b *build) subjects(subs []subject) error {
	for _, s := range subs {
		var pkg *generated.PkgInputSpec
		if purl := subjectPurl(s); purl != "" {
			p, err := helpers.PurlToPkg(purl)
			if err != nil {
				return fmt.Errorf("cosignvuln: subject purl %q: %w", purl, err)
			}
			pkg = p
			b.subjectPkgs = append(b.subjectPkgs, p)
			b.ids.PurlStrings = append(b.ids.PurlStrings, purl)
		}
		art := subjectArtifact(s)
		if pkg != nil && art != nil {
			b.preds.IsOccurrence = append(b.preds.IsOccurrence, assembler.IsOccurrenceIngest{
				Pkg:          pkg,
				Artifact:     art,
				IsOccurrence: &generated.IsOccurrenceInputSpec{Justification: "cosign vulnerability attestation subject"},
			})
		}
	}
	return nil
}

// subjectPurl is the subject's purl: uri first, then name, when either is one.
func subjectPurl(s subject) string {
	for _, c := range []string{s.URI, s.Name} {
		if strings.HasPrefix(c, "pkg:") {
			return c
		}
	}
	return ""
}

// subjectArtifact is the subject's first non-empty digest, or nil.
func subjectArtifact(s subject) *generated.ArtifactInputSpec {
	algos := make([]string, 0, len(s.Digest))
	for a := range s.Digest {
		algos = append(algos, a)
	}
	sort.Strings(algos)
	for _, a := range algos {
		if hex := strings.TrimSpace(s.Digest[a]); hex != "" {
			return &generated.ArtifactInputSpec{Algorithm: strings.ToLower(a), Digest: strings.ToLower(hex)}
		}
	}
	return nil
}

// findings walks every result's vulnerabilities.
func (b *build) findings(results []result) error {
	for _, r := range results {
		for _, f := range r.Vulnerabilities {
			if err := b.finding(f); err != nil {
				return fmt.Errorf("cosignvuln: target %q: %w", r.Target, err)
			}
		}
	}
	return nil
}

// finding certifies one vulnerability against its package and every subject
// package, then records its aliases and scores.
func (b *build) finding(f finding) error {
	vuln, err := helpers.CreateVulnInput(f.VulnerabilityID)
	if err != nil {
		return fmt.Errorf("vulnerability id: %w", err)
	}
	purl := f.PkgIdentifier.PURL
	if purl == "" {
		purl = "pkg:generic/" + f.PkgName + "@" + f.InstalledVersion
	}
	pkg, err := helpers.PurlToPkg(purl)
	if err != nil {
		return fmt.Errorf("package purl %q: %w", purl, err)
	}
	if b.once("purl\x00" + purl) {
		b.ids.PurlStrings = append(b.ids.PurlStrings, purl)
	}
	b.certify(pkg, purl, vuln)
	for _, sp := range b.subjectPkgs {
		b.certify(sp, subjectKey(sp), vuln)
	}
	b.aliases(vuln, f.VendorIDs)
	b.scores(vuln, f.CVSS)
	return nil
}

// subjectKey identifies a subject package for de-duplication; the purl it
// came from is not kept on the spec.
func subjectKey(p *generated.PkgInputSpec) string {
	return helpers.PkgInputSpecToPurl(p)
}

func (b *build) certify(pkg *generated.PkgInputSpec, pkgKey string, vuln *generated.VulnerabilityInputSpec) {
	if !b.once("cert\x00" + pkgKey + "\x00" + vuln.VulnerabilityID) {
		return
	}
	b.preds.CertifyVuln = append(b.preds.CertifyVuln, assembler.CertifyVulnIngest{
		Pkg:           pkg,
		Vulnerability: vuln,
		VulnData:      b.scan,
	})
}

// aliases records each vendor id as equal to the finding's id. A vendor id
// with no type prefix is not an identifier and is dropped.
func (b *build) aliases(vuln *generated.VulnerabilityInputSpec, vendorIDs []string) {
	for _, id := range vendorIDs {
		alias, err := helpers.CreateVulnInput(id)
		if err != nil || alias.VulnerabilityID == vuln.VulnerabilityID {
			continue
		}
		if !b.once("equal\x00" + vuln.VulnerabilityID + "\x00" + alias.VulnerabilityID) {
			continue
		}
		b.preds.VulnEqual = append(b.preds.VulnEqual, assembler.VulnEqualIngest{
			Vulnerability:      vuln,
			EqualVulnerability: alias,
			VulnEqual:          &generated.VulnEqualInputSpec{Justification: "Trivy VendorIDs"},
		})
	}
}

// scores records one VulnMetadata per CVSS score, in source order so the
// output is stable.
func (b *build) scores(vuln *generated.VulnerabilityInputSpec, bySource map[string]cvss) {
	sources := make([]string, 0, len(bySource))
	for s := range bySource {
		sources = append(sources, s)
	}
	sort.Strings(sources)
	for _, s := range sources {
		c := bySource[s]
		b.score(vuln, generated.VulnerabilityScoreTypeCvssv2, c.V2Score)
		b.score(vuln, cvss3Type(c.V3Vector), c.V3Score)
		b.score(vuln, generated.VulnerabilityScoreTypeCvssv4, c.V40Score)
	}
}

// cvss3Type tells CVSS 3.1 from 3.0 by the vector prefix.
func cvss3Type(vector string) generated.VulnerabilityScoreType {
	if strings.HasPrefix(vector, "CVSS:3.1/") {
		return generated.VulnerabilityScoreTypeCvssv31
	}
	return generated.VulnerabilityScoreTypeCvssv3
}

func (b *build) score(vuln *generated.VulnerabilityInputSpec, typ generated.VulnerabilityScoreType, value float64) {
	if value <= 0 {
		return
	}
	key := fmt.Sprintf("score\x00%s\x00%s\x00%g", vuln.VulnerabilityID, typ, value)
	if !b.once(key) {
		return
	}
	b.preds.VulnMetadata = append(b.preds.VulnMetadata, assembler.VulnMetadataIngest{
		Vulnerability: vuln,
		VulnMetadata: &generated.VulnerabilityMetadataInputSpec{
			ScoreType:  typ,
			ScoreValue: value,
			Timestamp:  b.scan.TimeScanned,
		},
	})
}

// finish gives a subject with no finding the noVuln sentinel: a clean scan
// is a claim too.
func (b *build) finish() {
	if len(b.preds.CertifyVuln) > 0 {
		return
	}
	for _, sp := range b.subjectPkgs {
		b.preds.CertifyVuln = append(b.preds.CertifyVuln, assembler.CertifyVulnIngest{
			Pkg:           sp,
			Vulnerability: &generated.VulnerabilityInputSpec{Type: "noVuln"},
			VulnData:      b.scan,
		})
	}
}
